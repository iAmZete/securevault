"""Centralised security audit logging.

Every event is written to the ``audit_events`` table (queried by the Auditor
panel) and mirrored as a JSON line to ``logs/audit.log``. Records carry a
timestamp, user, action, file id, source IP and result. Passwords, keys,
session tokens and file contents are never passed to this module; details are
additionally scrubbed and truncated as defence in depth.
"""
from __future__ import annotations

import json
import logging
import re
from logging.handlers import RotatingFileHandler
from pathlib import Path

from flask import current_app, has_request_context, request
from flask_login import current_user

from ..extensions import db
from ..models import AuditEvent, utcnow


class Action:
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    ACCOUNT_LOCKED = "account_locked"
    LOGOUT = "logout"
    SESSION_EXPIRED = "session_expired"
    PASSWORD_CHANGED = "password_changed"
    UPLOAD = "file_upload"
    UPLOAD_REJECTED = "upload_rejected"
    DOWNLOAD = "file_download"
    DELETE = "file_delete"
    INTEGRITY_FAILURE = "integrity_failure"
    ACCESS_DENIED = "access_denied"
    CSRF_FAILURE = "csrf_failure"
    RATE_LIMITED = "rate_limited"
    USER_CREATED = "user_created"
    ROLE_CHANGED = "role_changed"
    ACCOUNT_UNLOCKED = "account_unlocked"
    ACCOUNT_LOCKED_BY_ADMIN = "account_locked_by_admin"
    PASSWORD_RESET = "password_reset"

    @classmethod
    def all(cls) -> list[str]:
        return sorted(v for k, v in vars(cls).items() if k.isupper())


class Result:
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"

    @classmethod
    def all(cls) -> list[str]:
        return [cls.SUCCESS, cls.FAILURE, cls.DENIED]


_logger = logging.getLogger("securevault.audit")
_SENSITIVE = re.compile(r"(password|passwd|secret|token|key|csrf)\s*[=:]\s*\S+", re.IGNORECASE)


def configure_audit_file_logger(log_dir: Path) -> None:
    target = (log_dir / "audit.log").resolve()
    for h in list(_logger.handlers):
        if getattr(h, "_securevault", None) == target:
            return
        if getattr(h, "_securevault", None) is not None:
            _logger.removeHandler(h)
            h.close()
    log_dir.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(target, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))
    handler._securevault = target  # type: ignore[attr-defined]
    _logger.addHandler(handler)
    _logger.setLevel(logging.INFO)
    _logger.propagate = False


def _clean(text: str | None, limit: int = 500) -> str | None:
    if text is None:
        return None
    text = _SENSITIVE.sub(lambda m: f"{m.group(1)}=[REDACTED]", str(text))
    text = "".join(ch if ch.isprintable() else " " for ch in text)
    return text[:limit]


def client_ip() -> str | None:
    return request.remote_addr if has_request_context() else None


def log_event(action: str, result: str, *, user=None, username: str | None = None,
              file_id: int | None = None, details: str | None = None) -> AuditEvent:
    if user is None and has_request_context():
        try:
            if current_user and current_user.is_authenticated:
                user = current_user
        except Exception:  # pragma: no cover - outside login context
            user = None
    user_id = getattr(user, "id", None)
    username = username or getattr(user, "username", None)

    event = AuditEvent(
        timestamp=utcnow(),
        user_id=user_id,
        username=_clean(username, 64),
        action=action,
        file_id=file_id,
        source_ip=client_ip(),
        result=result,
        details=_clean(details),
    )
    db.session.add(event)
    db.session.commit()

    _logger.info(json.dumps({
        "timestamp": event.timestamp.isoformat() + "Z",
        "user_id": event.user_id,
        "username": event.username,
        "action": event.action,
        "file_id": event.file_id,
        "source_ip": event.source_ip,
        "result": event.result,
        "details": event.details,
    }, ensure_ascii=True))
    if current_app and current_app.testing is False and result != Result.SUCCESS:
        current_app.logger.warning("security event: %s %s", action, result)
    return event
