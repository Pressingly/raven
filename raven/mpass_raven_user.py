"""Raven access for users admitted through mPass SSO.

Under SSO every session is created by a login that already passed the mPass tenant check, so that
session's user is made a Raven User by default. Raven's own auto-add gives a new System User a
Raven User record but not the role, and the user's next save then disables that record; the grant
adds the role and re-enables the record. Nothing beyond the Raven User role is granted.

The grant is made once. A per-user default (GRANT_MARKER, kept in DefaultValue, so User saves
leave it alone) records that this user was given Raven access, or already had it when first seen.
A user who carries the marker but no longer holds the role had it taken away by an admin and is
left without it: neither later logins nor the backfill grant it again.
"""

from collections import Counter
from enum import StrEnum

import frappe

from raven.api.raven_users import give_raven_access

RAVEN_USER_ROLE = "Raven User"
GRANT_MARKER = "mpass_raven_granted"
SAVEPOINT = "mpass_raven_user"
SSO_DISABLED = "sso_disabled"


class Outcome(StrEnum):
	INELIGIBLE = "ineligible"
	EXISTS = "exists"
	REVOKED = "revoked"
	GRANTED = "granted"
	FAILED = "failed"


def sso_enabled() -> bool:
	"""Upstream frappe has no mPass layer: without it no session is an SSO session."""
	try:
		from frappe.mpass_sso import sso_enabled as mpass_sso_enabled
	except ImportError:
		return False
	return mpass_sso_enabled()


def ensure_raven_user_on_session_creation(login_manager=None) -> None:
	if sso_enabled():
		ensure_raven_user(frappe.session.user)


def backfill_raven_users() -> dict[str, int | str]:
	"""Give Raven access to the enabled system users who have signed in at least once and were
	never granted it, so API-only service accounts are left out. Idempotent; a no-op without SSO.
	Run with `bench execute raven.mpass_raven_user.backfill_raven_users`."""
	if not sso_enabled():
		return {"skipped": SSO_DISABLED}

	users = frappe.get_all(
		"User",
		filters={
			"enabled": 1,
			"user_type": "System User",
			"last_login": ("is", "set"),
			"name": ("not in", frappe.STANDARD_USERS),
		},
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
		mark_granted(user)
		return Outcome.EXISTS
	if was_granted(user) and not holds_raven_user_role(user):
		return Outcome.REVOKED

	commit_earlier_writes()
	frappe.db.savepoint(SAVEPOINT)
	try:
		grant_raven_access(user)
		mark_granted(user)
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


def holds_raven_user_role(user: str) -> bool:
	return bool(
		frappe.db.exists("Has Role", {"parent": user, "parenttype": "User", "role": RAVEN_USER_ROLE})
	)


def has_raven_access(user: str) -> bool:
	record_enabled = frappe.db.get_value("Raven User", {"user": user, "type": "User"}, "enabled")
	return holds_raven_user_role(user) and bool(record_enabled)


def was_granted(user: str) -> bool:
	return bool(
		frappe.db.get_value("DefaultValue", {"parent": user, "defkey": GRANT_MARKER}, "defvalue")
	)


def mark_granted(user: str) -> None:
	if not was_granted(user):
		frappe.defaults.set_user_default(GRANT_MARKER, 1, user)


def grant_raven_access(user: str) -> None:
	"""The User save runs Raven's own hook, which creates or re-enables the Raven User record."""
	user_doc = frappe.get_doc("User", user)
	user_doc.flags.ignore_permissions = True
	give_raven_access(user_doc)


def commit_earlier_writes() -> None:
	"""Login hooks that ran before this one (an HRMS Employee, cleared sessions) commit here, so
	the full rollback restore_after_failure may fall back to can only discard this grant."""
	frappe.db.commit()  # nosemgrep


def restore_after_failure() -> None:
	"""A deadlock or MariaDB 1020 rolls the whole transaction back and takes the savepoint with it.
	Everything before the grant was committed first, so the full rollback loses only the grant."""
	try:
		frappe.db.rollback(save_point=SAVEPOINT)
	except Exception:
		logger().warning("savepoint lost with the transaction; rolled back the Raven grant only")
		frappe.db.rollback()


def logger():
	return frappe.logger("mpass_raven_user")
