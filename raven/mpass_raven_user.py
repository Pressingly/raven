"""Raven access for users admitted through mPass SSO.

Under SSO every session is created by a login that already passed the mPass tenant check, so that
session's user is made a Raven User. Raven's own auto-add gives a new System User a Raven User
record but not the role, and the user's next save then disables that record; this grants the role
and re-enables the record. Nothing beyond the Raven User role is granted.
"""

from collections import Counter
from enum import StrEnum

import frappe
from frappe.mpass_sso import sso_enabled

from raven.api.raven_users import give_raven_access

RAVEN_USER_ROLE = "Raven User"
SAVEPOINT = "mpass_raven_user"


class Outcome(StrEnum):
	INELIGIBLE = "ineligible"
	EXISTS = "exists"
	GRANTED = "granted"
	FAILED = "failed"


def ensure_raven_user_on_session_creation(login_manager=None) -> None:
	if sso_enabled():
		ensure_raven_user(frappe.session.user)


def backfill_raven_users() -> dict[str, int]:
	"""Make every enabled system user a Raven User. Idempotent; run with `bench execute`."""
	users = frappe.get_all(
		"User",
		filters={"enabled": 1, "user_type": "System User", "name": ("not in", frappe.STANDARD_USERS)},
		pluck="name",
	)
	outcomes = Counter()
	for user in users:
		outcomes[ensure_raven_user(user)] += 1
		frappe.db.commit()  # nosemgrep
	return dict(outcomes)


def ensure_raven_user(user: str) -> Outcome:
	"""Never raises: a failure here must not fail the login that triggered it."""
	if not is_eligible(user):
		return Outcome.INELIGIBLE
	if has_raven_access(user):
		return Outcome.EXISTS

	frappe.db.savepoint(SAVEPOINT)
	try:
		grant_raven_access(user)
	except Exception:
		restore_after_failure()
		logger().exception(f"could not make {user} a Raven User")
		return Outcome.FAILED

	frappe.db.release_savepoint(SAVEPOINT)
	return Outcome.GRANTED


def is_eligible(user: str) -> bool:
	if user in frappe.STANDARD_USERS:
		return False
	details = frappe.db.get_value("User", user, ["user_type", "enabled"], as_dict=True)
	return bool(details) and details.user_type == "System User" and bool(details.enabled)


def has_raven_access(user: str) -> bool:
	holds_role = frappe.db.exists(
		"Has Role", {"parent": user, "parenttype": "User", "role": RAVEN_USER_ROLE}
	)
	record_enabled = frappe.db.get_value("Raven User", {"user": user, "type": "User"}, "enabled")
	return bool(holds_role) and bool(record_enabled)


def grant_raven_access(user: str) -> None:
	"""The User save runs Raven's own hook, which creates or re-enables the Raven User record."""
	user_doc = frappe.get_doc("User", user)
	user_doc.flags.ignore_permissions = True
	give_raven_access(user_doc)


def restore_after_failure() -> None:
	"""A deadlock or MariaDB 1020 rolls the whole transaction back and takes the savepoint with it.
	The session row is already committed, so a full rollback loses nothing of the login."""
	try:
		frappe.db.rollback(save_point=SAVEPOINT)
	except Exception:
		frappe.db.rollback()


def logger():
	return frappe.logger("mpass_raven_user")
