import os
from unittest.mock import patch

import frappe
from frappe.mpass_sso import ACCESS_TOKEN_HEADER, EDGE_SECRET_HEADER, EMAIL_HEADER, provision_user
from frappe.tests import IntegrationTestCase
from frappe.tests.test_api import FrappeAPITestCase, make_request
from frappe.tests.test_mpass_sso import EDGE_SECRET, SSO_ENV, corporate_token, purge_test_users
from frappe.utils import get_test_client

from raven import mpass_raven_user
from raven.mpass_raven_user import (
	RAVEN_USER_ROLE,
	Outcome,
	backfill_raven_users,
	ensure_raven_user,
	ensure_raven_user_on_session_creation,
)


def mpass_member(email: str) -> str:
	if frappe.db.exists("User", email):
		return email
	return provision_user(email, "").name


def raven_record_enabled(user: str):
	return frappe.db.get_value("Raven User", {"user": user, "type": "User"}, "enabled")


def holds_raven_user_role(user: str) -> bool:
	return RAVEN_USER_ROLE in frappe.get_roles(user)


def save_user(user: str) -> None:
	doc = frappe.get_doc("User", user)
	doc.location = "saved again"
	doc.save(ignore_permissions=True)


class TestMpassRavenUser(IntegrationTestCase):
	def setUp(self):
		frappe.set_user("Administrator")

	def tearDown(self):
		frappe.set_user("Administrator")
		frappe.db.rollback()

	def test_a_new_member_gets_the_role_and_an_enabled_record(self):
		user = mpass_member("mpass_raven_new@example.com")

		self.assertEqual(ensure_raven_user(user), Outcome.GRANTED)

		self.assertTrue(holds_raven_user_role(user))
		self.assertEqual(raven_record_enabled(user), 1)

	def test_the_record_stays_enabled_after_a_later_user_save(self):
		user = mpass_member("mpass_raven_later_save@example.com")
		ensure_raven_user(user)

		save_user(user)

		self.assertEqual(raven_record_enabled(user), 1)

	def test_repairs_the_record_auto_add_left_disabled(self):
		user = mpass_member("mpass_raven_half_made@example.com")
		save_user(user)
		self.assertEqual(raven_record_enabled(user), 0)

		self.assertEqual(ensure_raven_user(user), Outcome.GRANTED)
		self.assertEqual(raven_record_enabled(user), 1)

	def test_grants_no_role_beyond_raven_user(self):
		user = mpass_member("mpass_raven_only_role@example.com")
		before = set(frappe.get_roles(user))

		ensure_raven_user(user)

		self.assertEqual(set(frappe.get_roles(user)) - before, {RAVEN_USER_ROLE})

	def test_a_second_login_changes_nothing(self):
		user = mpass_member("mpass_raven_repeat@example.com")
		ensure_raven_user(user)

		self.assertEqual(ensure_raven_user(user), Outcome.EXISTS)

	def test_standard_disabled_and_website_users_are_ineligible(self):
		disabled = mpass_member("mpass_raven_disabled@example.com")
		frappe.db.set_value("User", disabled, "enabled", 0)
		website = mpass_member("mpass_raven_website@example.com")
		frappe.db.set_value("User", website, "user_type", "Website User")

		for user in ("Administrator", "Guest", disabled, website):
			self.assertEqual(ensure_raven_user(user), Outcome.INELIGIBLE)

	def test_a_failed_grant_keeps_earlier_writes_and_does_not_raise(self):
		user = mpass_member("mpass_raven_failed@example.com")
		frappe.db.set_value("User", user, "bio", "written before the hook")

		with patch.object(mpass_raven_user, "grant_raven_access", side_effect=frappe.ValidationError):
			self.assertEqual(ensure_raven_user(user), Outcome.FAILED)

		self.assertEqual(frappe.db.get_value("User", user, "bio"), "written before the hook")
		self.assertFalse(holds_raven_user_role(user))

	def test_a_transaction_lost_mid_grant_does_not_raise(self):
		user = mpass_member("mpass_raven_lost_transaction@example.com")

		def lose_the_transaction(_user):
			frappe.db.rollback()
			raise frappe.QueryDeadlockError

		with patch.object(mpass_raven_user, "grant_raven_access", side_effect=lose_the_transaction):
			self.assertEqual(ensure_raven_user(user), Outcome.FAILED)

	def test_the_session_hook_runs_only_under_sso(self):
		user = mpass_member("mpass_raven_session_hook@example.com")
		frappe.set_user(user)

		with patch.object(mpass_raven_user, "sso_enabled", return_value=False):
			ensure_raven_user_on_session_creation()
		self.assertFalse(holds_raven_user_role(user))

		with patch.object(mpass_raven_user, "sso_enabled", return_value=True):
			ensure_raven_user_on_session_creation()
		self.assertTrue(holds_raven_user_role(user))

	def test_backfill_makes_every_system_user_a_raven_user(self):
		user = mpass_member("mpass_raven_backfill@example.com")

		with patch.object(frappe.db, "commit"):
			outcomes = backfill_raven_users()

		self.assertGreaterEqual(outcomes.get(Outcome.GRANTED, 0), 1)
		self.assertTrue(holds_raven_user_role(user))
		self.assertEqual(raven_record_enabled(user), 1)


class TestMpassRavenUserOnSsoLogin(FrappeAPITestCase):
	user = "mpass_raven_sso_login@example.com"

	def setUp(self):
		super().setUp()
		patcher = patch.dict(os.environ, {**SSO_ENV, "MPASS_EDGE_SECRET": EDGE_SECRET})
		patcher.start()
		self.addCleanup(patcher.stop)
		self.client = get_test_client()

	@classmethod
	def tearDownClass(cls):
		frappe.db.delete("Raven User", {"user": cls.user})
		purge_test_users(cls.user)
		super().tearDownClass()

	def get(self, path: str):
		headers = {
			EMAIL_HEADER: self.user,
			ACCESS_TOKEN_HEADER: corporate_token(),
			EDGE_SECRET_HEADER: EDGE_SECRET,
		}
		return make_request(target=self.client.get, args=(path,), kwargs={"headers": headers})

	def test_the_first_sso_request_opens_raven(self):
		response = self.get("/api/method/raven.api.raven_users.get_list")

		self.assertEqual(response.status_code, 200)
		self.assertIn(self.user, [row["name"] for row in response.json["message"]])
