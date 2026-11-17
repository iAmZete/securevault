"""Authentication, lockout and session tests (AUTH-xx)."""
from __future__ import annotations

from app.extensions import db
from app.models import User, utcnow
from app.security.audit import Action

from .conftest import PASSWORD, audit_events, login, logout


def get_user(app, username):
    with app.app_context():
        user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one()
        db.session.expunge(user)
        return user


def test_auth01_login_success_redirects_to_role_home(client, users, app):
    resp = login(client, "alice")
    assert resp.status_code == 302 and resp.headers["Location"].endswith("/files/")
    assert audit_events(app, Action.LOGIN_SUCCESS)[-1].username == "alice"


def test_auth02_passwords_stored_as_argon2id(app, users):
    user = get_user(app, "alice")
    assert user.password_hash.startswith("$argon2id$")
    assert PASSWORD not in user.password_hash


def test_auth03_wrong_password_generic_message(client, users):
    resp = login(client, "alice", "wrong-password")
    assert resp.status_code == 401
    assert b"Invalid username or password, or the account is locked." in resp.data
    resp_unknown = login(client, "nobody", "wrong-password")
    assert resp_unknown.status_code == 401
    assert b"Invalid username or password, or the account is locked." in resp_unknown.data


def test_auth04_brute_force_locks_account_after_5_attempts(client, users, app):
    for _ in range(5):
        login(client, "alice", "bad-password")
    user = get_user(app, "alice")
    assert user.is_locked and user.failed_login_count == 5
    assert audit_events(app, Action.ACCOUNT_LOCKED)
    # Correct password is now rejected.
    resp = login(client, "alice", PASSWORD)
    assert resp.status_code == 401
    assert audit_events(app, Action.LOGIN_FAILED)[-1].result == "denied"


def test_auth05_admin_unlock_restores_access(client, users, app):
    for _ in range(5):
        login(client, "alice", "bad-password")
    admin = app.test_client()
    login(admin, "admin")
    admin.post(f"/admin/users/{users['alice']}/unlock")
    assert not get_user(app, "alice").is_locked
    assert login(client, "alice").status_code == 302


def test_auth06_successful_login_resets_counter(client, users, app):
    for _ in range(3):
        login(client, "alice", "bad-password")
    login(client, "alice")
    assert get_user(app, "alice").failed_login_count == 0


def test_auth07_session_expires_after_15_minutes_idle(client, users, app):
    login(client, "alice")
    with client.session_transaction() as sess:
        sess["last_active"] = utcnow().timestamp() - 16 * 60
    resp = client.get("/files/")
    assert resp.status_code == 302 and "/login" in resp.headers["Location"]
    assert audit_events(app, Action.SESSION_EXPIRED)
    # Subsequent request is anonymous.
    assert client.get("/files/").status_code == 302


def test_auth08_active_session_is_not_expired(client, users):
    login(client, "alice")
    with client.session_transaction() as sess:
        sess["last_active"] = utcnow().timestamp() - 10 * 60
    assert client.get("/files/").status_code == 200


def test_auth09_logout_requires_post_and_ends_session(client, users, app):
    login(client, "alice")
    assert client.get("/logout").status_code == 405
    logout(client)
    assert client.get("/files/").status_code == 302
    assert audit_events(app, Action.LOGOUT)


def test_auth10_change_password_flow(client, users, app):
    login(client, "alice")
    resp = client.post("/account/password", data={
        "current_password": PASSWORD, "new_password": "Brand-New-Passw0rd!",
        "confirm_password": "Brand-New-Passw0rd!"})
    assert resp.status_code == 302
    logout(client)
    assert login(client, "alice", PASSWORD).status_code == 401
    assert login(client, "alice", "Brand-New-Passw0rd!").status_code == 302


def test_auth11_weak_new_password_rejected(client, users):
    login(client, "alice")
    resp = client.post("/account/password", data={
        "current_password": PASSWORD, "new_password": "short", "confirm_password": "short"})
    assert resp.status_code == 400


def test_auth12_password_change_revokes_other_sessions(app, users):
    first, second = app.test_client(), app.test_client()
    login(first, "alice")
    login(second, "alice")
    second.post("/account/password", data={
        "current_password": PASSWORD, "new_password": "Brand-New-Passw0rd!",
        "confirm_password": "Brand-New-Passw0rd!"})
    assert first.get("/files/").status_code == 302  # old session rejected
    assert second.get("/files/").status_code == 200  # re-issued session works


def test_auth13_temporary_password_forces_change(client, create_user):
    create_user("carol", must_change=True)
    resp = login(client, "carol")
    assert resp.headers["Location"].endswith("/account/password")
    resp = client.get("/files/")
    assert resp.status_code == 302 and resp.headers["Location"].endswith("/account/password")


def test_auth14_locking_user_terminates_live_session(app, users):
    alice, admin = app.test_client(), app.test_client()
    login(alice, "alice")
    login(admin, "admin")
    admin.post(f"/admin/users/{users['alice']}/lock")
    assert alice.get("/files/").status_code == 302


def test_auth15_session_cookie_flags(make_app, create_user):
    app = make_app(SESSION_COOKIE_SECURE=True)
    with app.app_context():
        from app.security.passwords import hash_password
        db.session.add(User(username="dave", role="staff", password_hash=hash_password(PASSWORD),
                            must_change_password=False))
        db.session.commit()
    client = app.test_client()
    resp = client.post("https://localhost/login", data={"username": "dave", "password": PASSWORD})
    cookie = resp.headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=Strict" in cookie
