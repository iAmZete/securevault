"""Authentication: login, logout, password change, session expiry."""
from __future__ import annotations

from flask import (Blueprint, current_app, flash, redirect, render_template, request,
                   session, url_for)
from flask_login import current_user, login_required, login_user, logout_user

from ..extensions import db, limiter
from ..forms import ChangePasswordForm, LoginForm
from ..models import Role, User, utcnow
from ..security.audit import Action, Result, log_event
from ..security.passwords import hash_password, needs_rehash, verify_password
from ..security.validation import ValidationError, normalize_username, validate_password_strength

bp = Blueprint("auth", __name__)

GENERIC_LOGIN_ERROR = "Invalid username or password, or the account is locked."


def home_for(user) -> str:
    if user.role == Role.ADMIN.value:
        return url_for("admin.users")
    if user.role == Role.AUDITOR.value:
        return url_for("auditor.logs")
    return url_for("files.index")


def _login_rate_limit() -> str:
    return current_app.config["LOGIN_RATE_LIMIT"]


@bp.route("/login", methods=["GET", "POST"])
@limiter.limit(_login_rate_limit, methods=["POST"])
def login():
    if current_user.is_authenticated:
        return redirect(home_for(current_user))

    form = LoginForm()
    if form.validate_on_submit():
        username = normalize_username(form.username.data)
        # ORM query -> parameterised SQL; input is never concatenated.
        user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none()
        password_ok = verify_password(user.password_hash if user else None, form.password.data)

        if user is None:
            log_event(Action.LOGIN_FAILED, Result.FAILURE, username=username[:64],
                      details="unknown username")
            flash(GENERIC_LOGIN_ERROR, "danger")
            return render_template("auth/login.html", form=form), 401

        if user.is_locked:
            log_event(Action.LOGIN_FAILED, Result.DENIED, user=user, details="account locked")
            flash(GENERIC_LOGIN_ERROR, "danger")
            return render_template("auth/login.html", form=form), 401

        if not password_ok:
            user.failed_login_count += 1
            max_attempts = current_app.config["MAX_FAILED_LOGINS"]
            if user.failed_login_count >= max_attempts:
                user.is_locked = True
                user.rotate_session_nonce()
                db.session.commit()
                log_event(Action.LOGIN_FAILED, Result.FAILURE, user=user,
                          details=f"bad password (attempt {user.failed_login_count})")
                log_event(Action.ACCOUNT_LOCKED, Result.SUCCESS, user=user,
                          details=f"locked after {max_attempts} failed attempts")
            else:
                db.session.commit()
                log_event(Action.LOGIN_FAILED, Result.FAILURE, user=user,
                          details=f"bad password (attempt {user.failed_login_count})")
            flash(GENERIC_LOGIN_ERROR, "danger")
            return render_template("auth/login.html", form=form), 401

        # Success: reset counters, upgrade hash parameters if needed.
        user.failed_login_count = 0
        user.last_login_at = utcnow()
        if needs_rehash(user.password_hash):
            user.password_hash = hash_password(form.password.data)
        db.session.commit()

        session.clear()  # prevent session fixation
        login_user(user, remember=False)
        session.permanent = True
        session["last_active"] = utcnow().timestamp()
        log_event(Action.LOGIN_SUCCESS, Result.SUCCESS, user=user)

        if user.must_change_password:
            flash("Please set a new password before continuing.", "warning")
            return redirect(url_for("auth.change_password"))
        return redirect(home_for(user))

    status = 400 if request.method == "POST" else 200
    return render_template("auth/login.html", form=form), status


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    log_event(Action.LOGOUT, Result.SUCCESS)
    logout_user()
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("auth.login"))


@bp.route("/account/password", methods=["GET", "POST"])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        user: User = current_user._get_current_object()
        if not verify_password(user.password_hash, form.current_password.data):
            log_event(Action.PASSWORD_CHANGED, Result.FAILURE, details="current password incorrect")
            flash("Current password is incorrect.", "danger")
            return render_template("auth/change_password.html", form=form), 400
        if form.new_password.data == form.current_password.data:
            flash("New password must differ from the current password.", "danger")
            return render_template("auth/change_password.html", form=form), 400
        try:
            validate_password_strength(
                form.new_password.data, user.username,
                current_app.config["PASSWORD_MIN_LENGTH"], current_app.config["PASSWORD_MAX_LENGTH"],
            )
        except ValidationError as exc:
            flash(str(exc), "danger")
            return render_template("auth/change_password.html", form=form), 400

        user.password_hash = hash_password(form.new_password.data)
        user.must_change_password = False
        user.password_changed_at = utcnow()
        user.rotate_session_nonce()  # invalidates all other sessions
        db.session.commit()
        log_event(Action.PASSWORD_CHANGED, Result.SUCCESS, user=user)

        # Re-issue this session with the new nonce.
        session.clear()
        login_user(user, remember=False)
        session.permanent = True
        session["last_active"] = utcnow().timestamp()
        flash("Password changed successfully.", "success")
        return redirect(home_for(user))

    status = 400 if request.method == "POST" else 200
    return render_template("auth/change_password.html", form=form), status
