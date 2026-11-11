import os
import sys
import unittest
from unittest.mock import patch

import frappe
from frappe.tests import IntegrationTestCase
from frappe.tests.test_api import FrappeAPITestCase, make_request
from frappe.utils import get_test_client, now_datetime

try:
	from frappe.mpass_sso import ACCESS_TOKEN_HEADER, EDGE_SECRET_HEADER, EMAIL_HEADER, provision_user
	from frappe.tests.test_mpass_sso import EDGE_SECRET, SSO_ENV, corporate_token, purge_test_users
except ImportError as missing_layer:
	raise unittest.SkipTest("needs the Pressingly/frappe mPass SSO layer") from missing_layer

from raven import mpass_raven_user
from raven.mpass_raven_user import (
	RAVEN_USER_ROLE,
	SSO_DISABLED,
	Outcome,
	backfill_raven_users,
	ensure_raven_user,
	ensure_raven_user_on_session_creation,
	sso_enabled,
	was_granted,
)


def mpass_member(email: str, signed_in: bool = True) -> str:
	user = email if frappe.db.exists("User", email) else provision_user(email, "").name
	if signed_in:
		frappe.db.set_value("User", user, "last_login", now_datetime())
	return user


def raven_record_enabled(user: str):
	return frappe.db.get_value("Raven User", {"user": user, "type": "User"}, "enabled")


def holds_raven_user_role(user: str) -> bool:
	return RAVEN_USER_ROLE in frappe.get_roles(user)


def save_user(user: str) -> None:
	doc = frappe.get_doc("User", user)
	doc.location = "saved again"
	doc.save(ignore_permissions=True)


def revoke(user: str) -> None:
	frappe.get_doc("User", user).remove_roles(RAVEN_USER_ROLE)


class TestMpassRavenUser(IntegrationTestCase):
	def setUp(self):
		frappe.set_user("Administrator")
		self.auto_add = frappe.db.get_single_value("Raven Settings", "auto_add_system_users")
		frappe.db.set_single_value("Raven Settings", "auto_add_system_users", 1)
		for patcher in (
			patch.object(frappe.db, "commit"),
			patch.object(mpass_raven_user, "sso_enabled", return_value=True),
		):
			patcher.start()
			self.addCleanup(patcher.stop)

	def tearDown(self):
		frappe.set_user("Administrator")
		frappe.db.rollback()
		frappe.db.set_single_value("Raven Settings", "auto_add_system_users", self.auto_add)

	def test_a_new_member_gets_the_role_and_an_enabled_record(self):
		user = mpass_member("mpass_raven_new@example.com")

		self.assertEqual(ensure_raven_user(user), Outcome.GRANTED)

		self.assertTrue(holds_raven_user_role(user))
		self.assertEqual(raven_record_enabled(user), 1)
		self.assertTrue(was_granted(user))

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

		self.assertEqual(set(frappe.get_roles(user)), before | {RAVEN_USER_ROLE})

	def test_a_second_login_changes_nothing(self):
		user = mpass_member("mpass_raven_repeat@example.com")
		ensure_raven_user(user)

		self.assertEqual(ensure_raven_user(user), Outcome.EXISTS)

	def test_a_revoked_user_is_not_granted_again(self):
		user = mpass_member("mpass_raven_revoked@example.com")
		ensure_raven_user(user)
		revoke(user)

		self.assertEqual(ensure_raven_user(user), Outcome.REVOKED)
		self.assertFalse(holds_raven_user_role(user))

	def test_the_next_session_keeps_a_revoked_user_out(self):
		user = mpass_member("mpass_raven_revoked_session@example.com")
		ensure_raven_user(user)
		revoke(user)
		frappe.set_user(user)

		ensure_raven_user_on_session_creation()

		self.assertFalse(holds_raven_user_role(user))

	def test_access_granted_by_hand_is_marked_and_its_revocation_sticks(self):
		user = mpass_member("mpass_raven_by_hand@example.com")
		frappe.get_doc("User", user).add_roles(RAVEN_USER_ROLE)

		self.assertEqual(ensure_raven_user(user), Outcome.EXISTS)
		self.assertTrue(was_granted(user))
		revoke(user)
		self.assertEqual(ensure_raven_user(user), Outcome.REVOKED)

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
		self.assertFalse(was_granted(user))

	def test_a_transaction_lost_mid_grant_does_not_raise(self):
		user = mpass_member("mpass_raven_lost_transaction@example.com")

		def lose_the_transaction(_user):
			frappe.db.rollback()
			raise frappe.QueryDeadlockError

		with patch.object(mpass_raven_user, "grant_raven_access", side_effect=lose_the_transaction):
			self.assertEqual(ensure_raven_user(user), Outcome.FAILED)

	def test_earlier_login_writes_are_committed_before_the_grant(self):
		user = mpass_member("mpass_raven_commit_first@example.com")

		ensure_raven_user(user)

		frappe.db.commit.assert_called()

	def test_the_session_hook_runs_only_under_sso(self):
		user = mpass_member("mpass_raven_session_hook@example.com")
		frappe.set_user(user)

		with patch.object(mpass_raven_user, "sso_enabled", return_value=False):
			ensure_raven_user_on_session_creation()
		self.assertFalse(holds_raven_user_role(user))

		ensure_raven_user_on_session_creation()
		self.assertTrue(holds_raven_user_role(user))

	def test_backfill_grants_signed_in_users_and_skips_the_rest(self):
		signed_in = mpass_member("mpass_raven_backfill@example.com")
		never_signed_in = mpass_member("mpass_raven_service_account@example.com", signed_in=False)
		revoked = mpass_member("mpass_raven_backfill_revoked@example.com")
		ensure_raven_user(revoked)
		revoke(revoked)

		outcomes = backfill_raven_users()

		self.assertGreaterEqual(outcomes.get(Outcome.GRANTED, 0), 1)
		self.assertGreaterEqual(outcomes.get(Outcome.REVOKED, 0), 1)
		self.assertTrue(holds_raven_user_role(signed_in))
		self.assertEqual(raven_record_enabled(signed_in), 1)
		self.assertFalse(holds_raven_user_role(never_signed_in))
		self.assertFalse(holds_raven_user_role(revoked))

	def test_backfill_does_nothing_without_sso(self):
		user = mpass_member("mpass_raven_backfill_no_sso@example.com")

		with patch.object(mpass_raven_user, "sso_enabled", return_value=False):
			self.assertEqual(backfill_raven_users(), {"skipped": SSO_DISABLED})
		self.assertFalse(holds_raven_user_role(user))


class TestSsoDetection(unittest.TestCase):
	def test_frappe_without_the_mpass_layer_is_not_sso(self):
		with patch.dict(sys.modules, {"frappe.mpass_sso": None}):
			self.assertFalse(sso_enabled())

	def test_the_mpass_layer_decides_when_present(self):
		with patch.dict(os.environ, {**SSO_ENV, "MPASS_EDGE_SECRET": EDGE_SECRET}):
			self.assertTrue(sso_enabled())
		with patch.dict(os.environ, {"AUTH_TYPE": ""}):
			self.assertFalse(sso_enabled())


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
		frappe.db.delete("DefaultValue", {"parent": cls.user})
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
