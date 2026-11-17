"""Role-based access control (deny by default, complete mediation).

Permission matrix
-----------------
=====================  =====  =====  =======
Permission             Admin  Staff  Auditor
=====================  =====  =====  =======
manage users / roles     Y      -       -
upload / list own files  -      Y       -
download / delete own    -      Y       -
view audit log           -      -       Y
change own password      Y      Y       Y
=====================  =====  =====  =======

Admin has *no* implicit access to Staff documents, and the Auditor has no
access to document contents. Every protected view is wrapped with
``role_required``; file views additionally scope every query by owner.
"""
from __future__ import annotations

from functools import wraps

from flask import abort, request
from flask_login import current_user, login_required

from ..models import Role
from .audit import Action, Result, log_event


class Permission:
    MANAGE_USERS = "manage_users"
    MANAGE_OWN_FILES = "manage_own_files"
    VIEW_AUDIT_LOG = "view_audit_log"
    CHANGE_OWN_PASSWORD = "change_own_password"


ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    Role.ADMIN.value: frozenset({Permission.MANAGE_USERS, Permission.CHANGE_OWN_PASSWORD}),
    Role.STAFF.value: frozenset({Permission.MANAGE_OWN_FILES, Permission.CHANGE_OWN_PASSWORD}),
    Role.AUDITOR.value: frozenset({Permission.VIEW_AUDIT_LOG, Permission.CHANGE_OWN_PASSWORD}),
}


def has_permission(user, permission: str) -> bool:
    if not getattr(user, "is_authenticated", False):
        return False
    return permission in ROLE_PERMISSIONS.get(user.role, frozenset())


def permission_required(permission: str):
    """Decorator: user must be logged in *and* hold ``permission``."""

    def decorator(view):
        @wraps(view)
        @login_required
        def wrapped(*args, **kwargs):
            if not has_permission(current_user, permission):
                log_event(Action.ACCESS_DENIED, Result.DENIED,
                          details=f"missing permission {permission} for {request.method} {request.path}")
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorator
