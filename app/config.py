"""Application configuration.

All secrets and runtime paths are read from environment variables so that
key material is never stored in source control (trust boundary TB3).
"""
from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _env_path(name: str, default: Path) -> Path:
    value = os.environ.get(name)
    return Path(value).expanduser().resolve() if value else default


class Config:
    # --- Paths -------------------------------------------------------------
    # The data tier is split into three separate locations:
    #   * DATA_DIR/securevault.db    -> SQLite metadata database
    #   * DATA_DIR/files/            -> encrypted file store (ciphertext only)
    #   * SECRETS_DIR/master.key     -> master key, kept apart from both
    DATA_DIR = _env_path("SECUREVAULT_DATA_DIR", BASE_DIR / "data")
    STORAGE_DIR = _env_path("SECUREVAULT_STORAGE_DIR", DATA_DIR / "files")
    SECRETS_DIR = _env_path("SECUREVAULT_SECRETS_DIR", BASE_DIR / "secrets")
    MASTER_KEY_FILE = _env_path("SECUREVAULT_MASTER_KEY_FILE", SECRETS_DIR / "master.key")
    SECRET_KEY_FILE = _env_path("SECUREVAULT_SECRET_KEY_FILE", SECRETS_DIR / "flask_secret.key")
    LOG_DIR = _env_path("SECUREVAULT_LOG_DIR", BASE_DIR / "logs")
    TLS_CERT_FILE = _env_path("SECUREVAULT_TLS_CERT", SECRETS_DIR / "tls" / "cert.pem")
    TLS_KEY_FILE = _env_path("SECUREVAULT_TLS_KEY", SECRETS_DIR / "tls" / "key.pem")

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "SECUREVAULT_DATABASE_URI", f"sqlite:///{(DATA_DIR / 'securevault.db').as_posix()}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Refuse to start if the master key file is readable by group/others (POSIX).
    MASTER_KEY_ENFORCE_PERMISSIONS = True

    # --- Authentication & sessions ----------------------------------------
    MAX_FAILED_LOGINS = 5
    SESSION_IDLE_TIMEOUT = timedelta(minutes=15)
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=15)
    SESSION_REFRESH_EACH_REQUEST = True
    SESSION_COOKIE_NAME = "securevault_session"
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Strict"
    REMEMBER_COOKIE_DURATION = timedelta(seconds=0)  # "remember me" is disabled
    PASSWORD_MIN_LENGTH = 12
    PASSWORD_MAX_LENGTH = 128

    # --- Uploads ------------------------------------------------------------
    MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB
    # Allow a little overhead for multipart framing; the exact 10 MB file limit
    # is enforced again in the validation module.
    MAX_CONTENT_LENGTH = MAX_UPLOAD_BYTES + 64 * 1024

    # --- Hardening ----------------------------------------------------------
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600
    WTF_CSRF_SSL_STRICT = True
    FORCE_HTTPS = True
    RATELIMIT_ENABLED = True
    RATELIMIT_STORAGE_URI = os.environ.get("SECUREVAULT_RATELIMIT_STORAGE", "memory://")
    LOGIN_RATE_LIMIT = "10 per minute"
    RATELIMIT_DEFAULT = "300 per minute"

    AUDIT_PAGE_SIZE = 50


class DevelopmentConfig(Config):
    DEBUG = False  # never expose the Werkzeug debugger, even in development


class TestingConfig(Config):
    TESTING = True
    WTF_CSRF_ENABLED = False
    WTF_CSRF_SSL_STRICT = False
    FORCE_HTTPS = False
    RATELIMIT_ENABLED = False
    SESSION_COOKIE_SECURE = False
    MASTER_KEY_ENFORCE_PERMISSIONS = False


CONFIGS = {
    "development": DevelopmentConfig,
    "production": Config,
    "testing": TestingConfig,
}
