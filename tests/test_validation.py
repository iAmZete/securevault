"""Input validation and injection tests (VAL-xx / INJ-xx)."""
from __future__ import annotations

import pytest

from app.extensions import db
from app.models import StoredFile, User
from app.security.audit import Action
from app.security.validation import ValidationError, sanitize_filename, validate_upload

from .conftest import audit_events, login, make_pdf, make_png, upload

MB = 1024 * 1024


def _count(app):
    with app.app_context():
        return db.session.execute(db.select(db.func.count(StoredFile.id))).scalar_one()


@pytest.mark.parametrize("name,content", [
    ("malware.exe", b"MZ\x90\x00binary"),
    ("script.html", b"<script>alert(1)</script>"),
    ("shell.php", b"<?php system($_GET['c']); ?>"),
    ("archive.zip", b"PK\x03\x04junk"),
    ("noext", b"hello"),
])
def test_val01_disallowed_types_rejected(client, users, app, name, content):
    login(client, "alice")
    resp = upload(client, name, content)
    assert resp.status_code == 302
    assert _count(app) == 0
    assert audit_events(app, Action.UPLOAD_REJECTED)


def test_val02_oversized_file_rejected(client, users, app):
    login(client, "alice")
    big = b"a" * (10 * MB + 1)
    resp = upload(client, "big.txt", big)
    assert resp.status_code in (302, 413)
    assert _count(app) == 0


def test_val03_exactly_10mb_accepted(client, users, app):
    login(client, "alice")
    assert upload(client, "max.txt", b"a" * (10 * MB)).status_code == 302
    assert _count(app) == 1


def test_val04_request_body_far_over_limit_returns_413(client, users):
    login(client, "alice")
    resp = upload(client, "huge.txt", b"a" * (11 * MB))
    assert resp.status_code == 413


@pytest.mark.parametrize("name,content", [
    ("fake.pdf", make_png()),          # PNG disguised as PDF
    ("fake.png", make_pdf()),          # PDF disguised as PNG
    ("fake.jpg", b"not really a jpeg"),
    ("fake.docx", b"PK\x03\x04 not a real docx"),
    ("binary.txt", b"MZ\x90\x00\x03\x00\x00\x00"),  # Windows executable renamed .txt
    ("nullbyte.txt", b"abc\x00def"),
])
def test_val05_extension_content_mismatch_rejected(client, users, app, name, content):
    login(client, "alice")
    upload(client, name, content)
    assert _count(app) == 0
    assert "does not match" in audit_events(app, Action.UPLOAD_REJECTED)[-1].details


def test_val06_empty_file_rejected(client, users, app):
    login(client, "alice")
    upload(client, "empty.txt", b"")
    assert _count(app) == 0


@pytest.mark.parametrize("raw,expected", [
    ("../../etc/passwd.txt", "passwd.txt"),
    ("..\\..\\windows\\system32\\evil.txt", "evil.txt"),
    ("/absolute/path/report.pdf", "report.pdf"),
    ("<script>alert(1)</script>.txt", "script.txt"),
    ("re port..final.pdf", "re port.final.pdf"),
])
def test_val07_filename_sanitization(raw, expected):
    assert sanitize_filename(raw) == expected


@pytest.mark.parametrize("raw", ["", "..", "../", "CON.txt", ".txt", "\x00\x00"])
def test_val08_invalid_filenames_rejected(raw):
    with pytest.raises(ValidationError):
        sanitize_filename(raw)


def test_val09_path_traversal_upload_name_never_reaches_disk(client, users, app):
    login(client, "alice")
    upload(client, "../../../../tmp/pwned.txt", b"payload")
    with app.app_context():
        rec = db.session.execute(db.select(StoredFile)).scalar_one()
        assert rec.original_name == "pwned.txt"
        assert len(rec.storage_name) == 64


@pytest.mark.parametrize("path", [
    "/files/../../etc/passwd/download",
    "/files/..%2F..%2Fetc%2Fpasswd/download",
    "/files/%2e%2e%2f%2e%2e%2fetc%2fpasswd/download",
    "/files/1%20OR%201=1/download",
    "/files/-1/download",
])
def test_inj01_path_traversal_in_download_url(client, users, path):
    login(client, "alice")
    resp = client.get(path)
    assert resp.status_code == 404
    assert b"root:" not in resp.data


@pytest.mark.parametrize("payload", [
    "' OR '1'='1", "admin'--", "admin' OR 1=1--", "'; DROP TABLE users;--", "\" OR \"\"=\"",
])
def test_inj02_sql_injection_in_login(client, users, app, payload):
    resp = login(client, payload, payload)
    assert resp.status_code == 401
    with app.app_context():  # tables intact
        assert db.session.execute(db.select(db.func.count(User.id))).scalar_one() == 4


def test_inj03_sql_injection_in_audit_filter(client, users):
    login(client, "auditor")
    resp = client.get("/audit/", query_string={"username": "' OR 1=1 --", "action": "x' OR '1'='1"})
    assert resp.status_code == 200


def test_inj04_stored_xss_in_filename_is_escaped(client, users):
    login(client, "alice")
    # Even if a payload survived sanitisation, Jinja2 autoescaping neutralises it.
    upload(client, "<img src=x onerror=alert(1)>.txt", b"hello")
    page = client.get("/files/").data
    assert b"<img src=x" not in page and b"onerror=alert(1)>" not in page


def test_inj05_xss_in_login_username_escaped_in_audit_view(client, users, app):
    login(client, "<script>alert('xss')</script>", "x")
    auditor = app.test_client()
    login(auditor, "auditor")
    page = auditor.get("/audit/").data
    assert b"<script>alert('xss')</script>" not in page
    assert b"&lt;script&gt;" in page


def test_val10_validate_upload_unit():
    v = validate_upload("Report.PDF", make_pdf(), 10 * MB)
    assert v.extension == "pdf" and v.mime_type == "application/pdf"
