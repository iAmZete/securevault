"""SecureVault application factory."""
from __future__ import annotations

import hmac
import logging
import os
import secrets
from pathlib import Path

from flask import Flask, abort, flash, redirect, request, session, url_for
from flask_login import current_user, logout_user

from .config import CONFIGS
from .extensions import csrf, db, limiter, login_manager, talisman
from .models import User, utcnow
from .security.audit import Action, Result, configure_audit_file_logger, log_event
from .security.crypto import CryptoService, _restrict_dir, _write_secret, load_master_key

CSP = {
    "default-src": "'self'",
    "script-src": "'self'",
    "style-src": "'self'",
    "img-src": "'self' data:",
    "font-src": "'self'",
    "object-src": "'none'",
    "base-uri": "'none'",
    "form-action": "'self'",
    "frame-ancestors": "'none'",
}

# Endpoints reachable while a forced password change is pending.
_PASSWORD_CHANGE_ALLOWED = {"auth.change_password", "auth.logout", "static"}


def _load_secret_key(app: Flask) -> str:
    env_key = os.environ.get("SECUREVAULT_SECRET_KEY")
    if env_key:
        return env_key
    path = Path(app.config["SECRET_KEY_FILE"])
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        _restrict_dir(path.parent)
        _write_secret(path, secrets.token_hex(32).encode())
    return path.read_text().strip()


def create_app(config_name: str | None = None, overrides: dict | None = None) -> Flask:
    config_name = config_name or os.environ.get("SECUREVAULT_ENV", "development")
    app = Flask(__name__, instance_relative_config=False)
    app.config.from_object(CONFIGS[config_name])
    if overrides:
        app.config.update(overrides)
    if not app.config.get("SECRET_KEY"):
        app.config["SECRET_KEY"] = _load_secret_key(app)

    for key in ("DATA_DIR", "STORAGE_DIR", "LOG_DIR"):
        Path(app.config[key]).mkdir(parents=True, exist_ok=True)

    # --- Logging ------------------------------------------------------------
    configure_audit_file_logger(Path(app.config["LOG_DIR"]))
    logging.basicConfig(level=logging.INFO)

    # --- Master key (TB3) ----------------------------------------------------
    app.extensions["securevault_crypto"] = None
    key_file = Path(app.config["MASTER_KEY_FILE"])
    if key_file.exists():
        # Insecure permissions or a malformed key raise here: fail securely.
        master, version = load_master_key(key_file, app.config["MASTER_KEY_ENFORCE_PERMISSIONS"])
        app.extensions["securevault_crypto"] = CryptoService(master, key_version=version)
        del master
    else:
        app.logger.warning("Master key not found at %s; run `flask --app run.py init`.", key_file)

    # --- Extensions ----------------------------------------------------------
    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please sign in to continue."
    login_manager.login_message_category = "warning"
    login_manager.session_protection = "strong"

    talisman.init_app(
        app,
        force_https=app.config["FORCE_HTTPS"],
        strict_transport_security=True,
        strict_transport_security_max_age=31536000,
        strict_transport_security_include_subdomains=True,
        content_security_policy=CSP,
        frame_options="DENY",
        # "same-origin" (not "no-referrer"): Flask-WTF's strict HTTPS CSRF
        # check requires a same-origin Referer header; cross-site requests
        # still receive no referrer at all.
        referrer_policy="same-origin",
        session_cookie_secure=app.config["SESSION_COOKIE_SECURE"],
        session_cookie_http_only=True,
        session_cookie_samesite=app.config["SESSION_COOKIE_SAMESITE"],
        x_content_type_options=True,
        permissions_policy={"camera": "()", "microphone": "()", "geolocation": "()",
                            "browsing-topics": "()"},
    )

    # --- Blueprints ----------------------------------------------------------
    from .routes import admin, auditor, auth, files, main

    for module in (main, auth, files, admin, auditor):
        app.register_blueprint(module.bp)
    main.register_error_handlers(app)

    _register_request_hooks(app)

    from .cli import register_cli

    register_cli(app)

    with app.app_context():
        db.create_all()

    return app


@login_manager.user_loader
def _load_user(session_id: str):
    try:
        user_id_str, nonce = session_id.split(":", 1)
        user_id = int(user_id_str)
    except (ValueError, AttributeError):
        return None
    user = db.session.get(User, user_id)
    if user is None or user.is_locked:
        return None
    if not hmac.compare_digest(user.session_nonce, nonce):
        return None  # session was revoked (password/role change or lock)
    return user


def _register_request_hooks(app: Flask) -> None:
    @app.before_request
    def require_master_key():
        if request.endpoint == "static":
            return None
        if app.extensions.get("securevault_crypto") is None:
            abort(503, "Master key is not configured.")
        return None

    @app.before_request
    def enforce_idle_timeout():
        if request.endpoint == "static" or not current_user.is_authenticated:
            return None
        now = utcnow().timestamp()
        last = session.get("last_active")
        timeout = app.config["SESSION_IDLE_TIMEOUT"].total_seconds()
        if last is None or now - float(last) > timeout:
            log_event(Action.SESSION_EXPIRED, Result.SUCCESS, user=current_user,
                      details="idle timeout")
            logout_user()
            session.clear()
            flash("Your session expired after 15 minutes of inactivity. Please sign in again.", "warning")
            return redirect(url_for("auth.login"))
        session["last_active"] = now
        return None

    @app.before_request
    def enforce_password_change():
        if (current_user.is_authenticated and current_user.must_change_password
                and request.endpoint not in _PASSWORD_CHANGE_ALLOWED):
            return redirect(url_for("auth.change_password"))
        return None

    @app.after_request
    def no_cache_for_authenticated(response):
        if current_user.is_authenticated and request.endpoint != "static":
            response.headers["Cache-Control"] = "no-store"
            response.headers["Pragma"] = "no-cache"
        response.headers.pop("Server", None)
        return response

    @app.context_processor
    def inject_globals():
        return {"Action": Action}

    @app.errorhandler(503)
    def unavailable(e):
        from flask import render_template
        return render_template("errors/error.html", code=503, title="Service unavailable",
                               message="SecureVault is not fully configured (master key missing)."), 503
