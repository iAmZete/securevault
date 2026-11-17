"""Shared pytest fixtures: an isolated app per test with its own key, DB and store."""
from __future__ import annotations

import io
import re
import struct
import zipfile
import zlib

import pytest

from app import create_app
from app.extensions import db
from app.models import AuditEvent, Role, User
from app.security.crypto import generate_master_key_file
from app.security.passwords import hash_password

PASSWORD = "Correct-Horse-9-Battery"


@pytest.fixture
def make_app(tmp_path):
    def _make(**overrides):
        key_file = tmp_path / "secrets" / "master.key"
        if not key_file.exists():
            generate_master_key_file(key_file)
        config = {
            "SECRET_KEY": "test-secret-key",
            "DATA_DIR": tmp_path / "data",
            "STORAGE_DIR": tmp_path / "data" / "files",
            "LOG_DIR": tmp_path / "logs",
            "MASTER_KEY_FILE": key_file,
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{(tmp_path / 'data' / 'test.db').as_posix()}",
        }
        config.update(overrides)
        return create_app("testing", config)

    return _make


@pytest.fixture
def app(make_app):
    application = make_app()
    yield application
    with application.app_context():
        db.session.remove()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def create_user(app):
    def _create(username: str, role: Role = Role.STAFF, password: str = PASSWORD,
                must_change: bool = False) -> int:
        with app.app_context():
            user = User(username=username, role=role.value, password_hash=hash_password(password),
                        must_change_password=must_change)
            db.session.add(user)
            db.session.commit()
            return user.id

    return _create


@pytest.fixture
def users(create_user):
    return {
        "admin": create_user("admin", Role.ADMIN),
        "alice": create_user("alice", Role.STAFF),
        "bob": create_user("bob", Role.STAFF),
        "auditor": create_user("auditor", Role.AUDITOR),
    }


def login(client, username: str, password: str = PASSWORD, follow: bool = False):
    return client.post("/login", data={"username": username, "password": password},
                       follow_redirects=follow)


def logout(client):
    return client.post("/logout")


def upload(client, filename: str, content: bytes):
    return client.post("/files/upload", data={"file": (io.BytesIO(content), filename)},
                       content_type="multipart/form-data")


def audit_events(app, action: str | None = None) -> list[AuditEvent]:
    with app.app_context():
        q = db.select(AuditEvent).order_by(AuditEvent.id)
        if action:
            q = q.filter_by(action=action)
        events = db.session.execute(q).scalars().all()
        db.session.expunge_all()
        return events


def extract_csrf(html: bytes) -> str:
    match = re.search(rb'name="csrf_token" type="hidden" value="([^"]+)"', html) or \
        re.search(rb'name="csrf_token" value="([^"]+)"', html)
    assert match, "CSRF token not found in page"
    return match.group(1).decode()


# --- Sample files with valid signatures ------------------------------------

def make_pdf() -> bytes:
    return (b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
            b"2 0 obj<</Type/Pages/Kids[]/Count 0>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF\n")


def make_png() -> bytes:
    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data))
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    idat = zlib.compress(b"\x00\xff\x00\x00")
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def make_jpg() -> bytes:
    return b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9"


def make_docx() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml", "<w:document/>")
    return buf.getvalue()
