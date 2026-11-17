"""Database models.

All database access goes through the SQLAlchemy ORM, which always issues
parameterised queries (trust boundary TB2 – no string-built SQL anywhere).
"""
from __future__ import annotations

import secrets
from datetime import datetime, timezone
from enum import Enum

from flask_login import UserMixin

from .extensions import db


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Role(str, Enum):
    ADMIN = "admin"
    STAFF = "staff"
    AUDITOR = "auditor"

    @classmethod
    def values(cls) -> list[str]:
        return [r.value for r in cls]

    @property
    def label(self) -> str:
        return self.value.capitalize()


class IntegrityStatus(str, Enum):
    VERIFIED = "verified"
    FAILED = "failed"


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(16), nullable=False, default=Role.STAFF.value)
    is_locked = db.Column(db.Boolean, nullable=False, default=False)
    failed_login_count = db.Column(db.Integer, nullable=False, default=0)
    must_change_password = db.Column(db.Boolean, nullable=False, default=True)
    # Rotated on password change / lock / role change. It is embedded in the
    # Flask-Login session id, so rotating it invalidates every live session.
    session_nonce = db.Column(db.String(64), nullable=False, default=lambda: secrets.token_hex(16))
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    last_login_at = db.Column(db.DateTime)
    password_changed_at = db.Column(db.DateTime, default=utcnow)

    files = db.relationship("StoredFile", back_populates="owner", lazy="dynamic")

    # Flask-Login -----------------------------------------------------------
    def get_id(self) -> str:
        return f"{self.id}:{self.session_nonce}"

    @property
    def is_active(self) -> bool:  # locked users cannot hold a session
        return not self.is_locked

    def rotate_session_nonce(self) -> None:
        self.session_nonce = secrets.token_hex(16)

    def has_role(self, *roles: Role | str) -> bool:
        wanted = {r.value if isinstance(r, Role) else r for r in roles}
        return self.role in wanted

    @property
    def role_label(self) -> str:
        return Role(self.role).label

    def __repr__(self) -> str:  # never include the hash
        return f"<User {self.id} {self.username} {self.role}>"


class StoredFile(db.Model):
    """Metadata for one encrypted file.

    The plaintext filename supplied by the user is kept only as a display
    value; the on-disk name (``storage_name``) is a random token so that user
    input never influences a filesystem path.
    """

    __tablename__ = "files"

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    original_name = db.Column(db.String(255), nullable=False)
    storage_name = db.Column(db.String(64), unique=True, nullable=False)
    extension = db.Column(db.String(8), nullable=False)
    mime_type = db.Column(db.String(100), nullable=False)
    size_bytes = db.Column(db.Integer, nullable=False)

    # Integrity: SHA-256 of the original plaintext, hex encoded.
    sha256 = db.Column(db.String(64), nullable=False)

    # Envelope-encryption metadata.
    file_nonce = db.Column(db.LargeBinary(12), nullable=False)   # AES-GCM nonce for file data
    wrapped_dek = db.Column(db.LargeBinary(48), nullable=False)  # DEK (32 B) + GCM tag (16 B)
    dek_nonce = db.Column(db.LargeBinary(12), nullable=False)    # AES-GCM nonce for DEK wrap
    key_version = db.Column(db.Integer, nullable=False, default=1)

    integrity_status = db.Column(db.String(16), nullable=False, default=IntegrityStatus.VERIFIED.value)
    last_verified_at = db.Column(db.DateTime, default=utcnow)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    owner = db.relationship("User", back_populates="files")

    @property
    def size_display(self) -> str:
        size = float(self.size_bytes)
        for unit in ("B", "KB", "MB"):
            if size < 1024 or unit == "MB":
                return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
            size /= 1024
        return f"{self.size_bytes} B"


class AuditEvent(db.Model):
    """Structured, append-only security audit record.

    Never contains passwords, keys, session tokens or file contents.
    """

    __tablename__ = "audit_events"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    user_id = db.Column(db.Integer, nullable=True, index=True)
    username = db.Column(db.String(64), nullable=True)
    action = db.Column(db.String(40), nullable=False, index=True)
    file_id = db.Column(db.Integer, nullable=True)
    source_ip = db.Column(db.String(64), nullable=True)
    result = db.Column(db.String(16), nullable=False, index=True)
    details = db.Column(db.String(500), nullable=True)
