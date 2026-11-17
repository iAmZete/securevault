"""Communication hardening, CSRF, rate limiting and audit logging (SEC-xx / LOG-xx)."""
from __future__ import annotations

import json
from pathlib import Path

from app.security.audit import Action

from .conftest import PASSWORD, audit_events, extract_csrf, login, upload


def test_sec01_security_headers_present(client):
    resp = client.get("/login")
    csp = resp.headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp and "frame-ancestors 'none'" in csp
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["Referrer-Policy"] == "same-origin"


def test_sec02_hsts_on_https(client):
    resp = client.get("https://localhost/login")
    assert "max-age=31536000" in resp.headers["Strict-Transport-Security"]


def test_sec03_http_redirects_to_https_when_enforced(make_app):
    app = make_app(FORCE_HTTPS=True)
    resp = app.test_client().get("http://localhost/login")
    assert resp.status_code in (301, 302) and resp.headers["Location"].startswith("https://")


def test_sec04_csrf_token_required(make_app, create_user):
    app = make_app(WTF_CSRF_ENABLED=True)
    from app.extensions import db
    from app.models import User
    from app.security.passwords import hash_password
    with app.app_context():
        db.session.add(User(username="alice", role="staff", password_hash=hash_password(PASSWORD),
                            must_change_password=False))
        db.session.commit()
    client = app.test_client()
    # Login without token is rejected.
    resp = client.post("/login", data={"username": "alice", "password": PASSWORD})
    assert resp.status_code == 400
    assert audit_events(app, Action.CSRF_FAILURE)
    # Login with token succeeds.
    token = extract_csrf(client.get("/login").data)
    resp = client.post("/login", data={"username": "alice", "password": PASSWORD, "csrf_token": token})
    assert resp.status_code == 302
    # State-changing request without token is rejected.
    assert client.post("/logout").status_code == 400
    # Forged token is rejected.
    assert client.post("/logout", data={"csrf_token": "forged"}).status_code == 400


def test_sec04b_csrf_strict_referer_check_over_https(make_app, create_user):
    """Regression: over HTTPS Flask-WTF also requires a same-origin Referer."""
    app = make_app(WTF_CSRF_ENABLED=True, WTF_CSRF_SSL_STRICT=True)
    client = app.test_client()
    token = extract_csrf(client.get("https://localhost/login").data)
    data = {"username": "x", "password": "y", "csrf_token": token}
    no_ref = client.post("https://localhost/login", data=data)
    assert no_ref.status_code == 400  # missing Referer -> rejected
    cross = client.post("https://localhost/login", data=data, headers={"Referer": "https://evil.example/"})
    assert cross.status_code == 400   # cross-origin Referer -> rejected
    same = client.post("https://localhost/login", data=data, headers={"Referer": "https://localhost/login"})
    assert same.status_code == 401    # passes CSRF, fails credentials


def test_sec05_login_rate_limited(make_app, create_user):
    app = make_app(RATELIMIT_ENABLED=True, LOGIN_RATE_LIMIT="3 per minute")
    client = app.test_client()
    codes = [client.post("/login", data={"username": "x", "password": "y"}).status_code for _ in range(5)]
    assert codes[:3] == [401, 401, 401]
    assert 429 in codes[3:]
    assert audit_events(app, Action.RATE_LIMITED)


def test_sec06_no_server_banner_or_debug(client):
    resp = client.get("/does-not-exist")
    assert resp.status_code == 404
    assert b"Traceback" not in resp.data and b"Werkzeug" not in resp.data


def test_sec07_authenticated_pages_not_cached(client, users):
    login(client, "alice")
    assert client.get("/files/").headers["Cache-Control"] == "no-store"


def test_log01_security_events_have_required_fields(client, users, app):
    login(client, "alice", "wrong")
    login(client, "alice")
    upload(client, "a.txt", b"hello")
    for event in audit_events(app):
        assert event.timestamp and event.action and event.result
        assert event.source_ip == "127.0.0.1"
    upload_event = audit_events(app, Action.UPLOAD)[-1]
    assert upload_event.user_id is not None and upload_event.file_id is not None


def test_log02_no_secrets_in_audit_records(client, users, app):
    login(client, "alice", "My-Wrong-Secret-Pass!")
    login(client, "alice")
    upload(client, "a.txt", b"FILE-CONTENT-MARKER")
    db_text = " ".join(f"{e.username} {e.details}" for e in audit_events(app))
    log_text = (Path(app.config["LOG_DIR"]) / "audit.log").read_text()
    for secret in ("My-Wrong-Secret-Pass!", PASSWORD, "FILE-CONTENT-MARKER"):
        assert secret not in db_text and secret not in log_text


def test_log03_file_log_is_structured_json(client, users, app):
    login(client, "alice")
    lines = (Path(app.config["LOG_DIR"]) / "audit.log").read_text().strip().splitlines()
    record = json.loads(lines[-1])
    assert {"timestamp", "user_id", "action", "file_id", "source_ip", "result"} <= record.keys()


def test_log04_auditor_can_filter_events(client, users, app):
    login(client, "alice", "wrong")
    login(client, "auditor")
    resp = client.get("/audit/", query_string={"action": "login_failed", "username": "alice"})
    assert resp.status_code == 200
    assert b"login_failed" in resp.data
    resp = client.get("/audit/", query_string={"action": "file_delete"})
    assert b"No events match" in resp.data


def test_log05_auditor_view_contains_no_document_content(app, users):
    alice, auditor = app.test_client(), app.test_client()
    login(alice, "alice")
    upload(alice, "a.txt", b"TOP-SECRET-CONTENT")
    login(auditor, "auditor")
    assert b"TOP-SECRET-CONTENT" not in auditor.get("/audit/").data


def test_sec08_missing_master_key_fails_securely(make_app, tmp_path):
    app = make_app(MASTER_KEY_FILE=tmp_path / "nope" / "master.key")
    resp = app.test_client().get("/login")
    assert resp.status_code == 503


def test_sec09_insecure_master_key_permissions_refused(make_app, tmp_path):
    import os
    import pytest
    from app.security.crypto import MasterKeyError, generate_master_key_file
    if os.name != "posix":
        pytest.skip("POSIX permissions only")
    key = generate_master_key_file(tmp_path / "loose" / "master.key")
    os.chmod(key, 0o644)
    with pytest.raises(MasterKeyError):
        make_app(MASTER_KEY_FILE=key, MASTER_KEY_ENFORCE_PERMISSIONS=True)
