"""Admin panel: create users, assign roles, lock/unlock, reset passwords.

The Admin role manages *accounts* only; no view here exposes document names,
metadata or contents.
"""
from __future__ import annotations

from flask import Blueprint, abort, current_app, flash, redirect, render_template, url_for
from flask_login import current_user

from ..extensions import db
from ..forms import ActionForm, ChangeRoleForm, CreateUserForm, ResetPasswordForm
from ..models import Role, User
from ..security.audit import Action, Result, log_event
from ..security.passwords import hash_password
from ..security.rbac import Permission, permission_required
from ..security.validation import ValidationError, validate_password_strength, validate_username

bp = Blueprint("admin", __name__, url_prefix="/admin")


def _get_user_or_404(user_id: int) -> User:
    user = db.session.get(User, user_id)
    if user is None:
        abort(404)
    return user


def _is_self(user: User) -> bool:
    return user.id == current_user.id


def _active_admin_count() -> int:
    return db.session.execute(
        db.select(db.func.count(User.id)).filter_by(role=Role.ADMIN.value, is_locked=False)
    ).scalar_one()


@bp.route("/users", methods=["GET"])
@permission_required(Permission.MANAGE_USERS)
def users():
    all_users = db.session.execute(db.select(User).order_by(User.username)).scalars().all()
    role_forms = {}
    for u in all_users:
        f = ChangeRoleForm(prefix=f"u{u.id}")
        f.role.data = u.role
        role_forms[u.id] = f
    return render_template("admin/users.html", users=all_users, create_form=CreateUserForm(),
                           role_forms=role_forms, action_form=ActionForm(),
                           reset_form=ResetPasswordForm(), roles=list(Role))


@bp.route("/users/create", methods=["POST"])
@permission_required(Permission.MANAGE_USERS)
def create_user():
    form = CreateUserForm()
    if not form.validate_on_submit():
        flash("Please complete all fields.", "danger")
        return redirect(url_for("admin.users"))
    try:
        username = validate_username(form.username.data)
        if form.role.data not in Role.values():
            raise ValidationError("Invalid role.")
        validate_password_strength(form.temp_password.data, username,
                                   current_app.config["PASSWORD_MIN_LENGTH"],
                                   current_app.config["PASSWORD_MAX_LENGTH"])
    except ValidationError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("admin.users"))

    if db.session.execute(db.select(User.id).filter_by(username=username)).first():
        flash("That username is already taken.", "danger")
        return redirect(url_for("admin.users"))

    user = User(username=username, role=form.role.data,
                password_hash=hash_password(form.temp_password.data), must_change_password=True)
    db.session.add(user)
    db.session.commit()
    log_event(Action.USER_CREATED, Result.SUCCESS,
              details=f"created user '{user.username}' (id {user.id}) with role {user.role}")
    flash(f"User '{user.username}' created. They must change the temporary password at first login.",
          "success")
    return redirect(url_for("admin.users"))


@bp.route("/users/<int:user_id>/role", methods=["POST"])
@permission_required(Permission.MANAGE_USERS)
def change_role(user_id: int):
    user = _get_user_or_404(user_id)
    form = ChangeRoleForm(prefix=f"u{user.id}")
    if not form.validate_on_submit() or form.role.data not in Role.values():
        flash("Invalid role.", "danger")
        return redirect(url_for("admin.users"))
    if _is_self(user):
        log_event(Action.ROLE_CHANGED, Result.DENIED, details="admin attempted to change own role")
        flash("You cannot change your own role.", "danger")
        return redirect(url_for("admin.users"))
    old = user.role
    if old == form.role.data:
        return redirect(url_for("admin.users"))
    user.role = form.role.data
    user.rotate_session_nonce()  # force re-login with the new role
    db.session.commit()
    log_event(Action.ROLE_CHANGED, Result.SUCCESS,
              details=f"user '{user.username}' (id {user.id}): {old} -> {user.role}")
    flash(f"Role for '{user.username}' changed to {user.role_label}.", "success")
    return redirect(url_for("admin.users"))


@bp.route("/users/<int:user_id>/lock", methods=["POST"])
@permission_required(Permission.MANAGE_USERS)
def lock_user(user_id: int):
    user = _get_user_or_404(user_id)
    if _is_self(user):
        flash("You cannot lock your own account.", "danger")
        return redirect(url_for("admin.users"))
    user.is_locked = True
    user.rotate_session_nonce()  # terminate active sessions immediately
    db.session.commit()
    log_event(Action.ACCOUNT_LOCKED_BY_ADMIN, Result.SUCCESS,
              details=f"locked user '{user.username}' (id {user.id})")
    flash(f"Account '{user.username}' locked.", "success")
    return redirect(url_for("admin.users"))


@bp.route("/users/<int:user_id>/unlock", methods=["POST"])
@permission_required(Permission.MANAGE_USERS)
def unlock_user(user_id: int):
    user = _get_user_or_404(user_id)
    user.is_locked = False
    user.failed_login_count = 0
    db.session.commit()
    log_event(Action.ACCOUNT_UNLOCKED, Result.SUCCESS,
              details=f"unlocked user '{user.username}' (id {user.id})")
    flash(f"Account '{user.username}' unlocked.", "success")
    return redirect(url_for("admin.users"))


@bp.route("/users/<int:user_id>/reset-password", methods=["POST"])
@permission_required(Permission.MANAGE_USERS)
def reset_password(user_id: int):
    user = _get_user_or_404(user_id)
    form = ResetPasswordForm()
    if not form.validate_on_submit():
        flash("A temporary password is required.", "danger")
        return redirect(url_for("admin.users"))
    try:
        validate_password_strength(form.temp_password.data, user.username,
                                   current_app.config["PASSWORD_MIN_LENGTH"],
                                   current_app.config["PASSWORD_MAX_LENGTH"])
    except ValidationError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("admin.users"))
    user.password_hash = hash_password(form.temp_password.data)
    user.must_change_password = True
    user.rotate_session_nonce()
    db.session.commit()
    log_event(Action.PASSWORD_RESET, Result.SUCCESS,
              details=f"reset password for '{user.username}' (id {user.id})")
    flash(f"Temporary password set for '{user.username}'.", "success")
    return redirect(url_for("admin.users"))
