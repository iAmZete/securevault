"""Landing route and error handlers."""
from __future__ import annotations

from flask import Blueprint, redirect, render_template, url_for
from flask_login import current_user
from flask_wtf.csrf import CSRFError

from ..security.audit import Action, Result, log_event
from .auth import home_for

bp = Blueprint("main", __name__)


@bp.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(home_for(current_user))
    return redirect(url_for("auth.login"))


ERROR_MESSAGES = {
    400: ("Bad request", "The request could not be processed."),
    403: ("Access denied", "You do not have permission to access this resource."),
    404: ("Not found", "The requested resource does not exist."),
    405: ("Method not allowed", "This action is not permitted."),
    413: ("File too large", "Uploads are limited to 10 MB."),
    429: ("Too many requests", "Too many attempts. Please wait a minute and try again."),
    500: ("Server error", "An unexpected error occurred. No details are shown for security reasons."),
}


def _render_error(code: int):
    title, message = ERROR_MESSAGES.get(code, ERROR_MESSAGES[500])
    return render_template("errors/error.html", code=code, title=title, message=message), code


def register_error_handlers(app):
    for code in (400, 403, 404, 405, 413, 500):
        app.register_error_handler(code, lambda e, c=code: _render_error(c))

    @app.errorhandler(429)
    def rate_limited(e):
        log_event(Action.RATE_LIMITED, Result.DENIED, details=str(getattr(e, "description", ""))[:100])
        return _render_error(429)

    @app.errorhandler(CSRFError)
    def csrf_error(e):
        log_event(Action.CSRF_FAILURE, Result.DENIED, details=e.description)
        return _render_error(400)
