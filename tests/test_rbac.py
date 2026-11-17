"""Authorization tests: RBAC, IDOR and privilege escalation (RBAC-xx)."""
from __future__ import annotations

import pytest

from app.extensions import db
from app.models import StoredFile, User
from app.security.audit import Action
from app.security.rbac import ROLE_PERMISSIONS, Permission

from .conftest import audit_events, login, upload


def _first_file_id(app, owner_id):
    with app.app_context():
        return db.session.execute(db.select(StoredFile.id).filter_by(owner_id=owner_id)).scalar_one()


def test_rbac01_permission_matrix_is_least_privilege():
    assert ROLE_PERMISSIONS["admin"] == {Permission.MANAGE_USERS, Permission.CHANGE_OWN_PASSWORD}
    assert Permission.MANAGE_OWN_FILES not in ROLE_PERMISSIONS["admin"]
    assert Permission.MANAGE_OWN_FILES not in ROLE_PERMISSIONS["auditor"]
    assert Permission.VIEW_AUDIT_LOG not in ROLE_PERMISSIONS["staff"]


@pytest.mark.parametrize("path", ["/files/", "/admin/users", "/audit/", "/account/password"])
def test_rbac02_anonymous_redirected_to_login(client, path):
    resp = client.get(path)
    assert resp.status_code == 302 and "/login" in resp.headers["Location"]


@pytest.mark.parametrize("username,path,expected", [
    ("admin", "/files/", 403), ("admin", "/audit/", 403), ("admin", "/admin/users", 200),
    ("auditor", "/files/", 403), ("auditor", "/admin/users", 403), ("auditor", "/audit/", 200),
    ("alice", "/admin/users", 403), ("alice", "/audit/", 403), ("alice", "/files/", 200),
])
def test_rbac03_role_page_access(client, users, username, path, expected):
    login(client, username)
    assert client.get(path).status_code == expected


def test_rbac04_access_denials_are_logged(client, users, app):
    login(client, "alice")
    client.get("/admin/users")
    denied = audit_events(app, Action.ACCESS_DENIED)
    assert denied and denied[-1].username == "alice" and denied[-1].result == "denied"


def test_rbac05_idor_download_of_other_users_file_blocked(app, users):
    alice, bob = app.test_client(), app.test_client()
    login(alice, "alice")
    upload(alice, "case.txt", b"alice private case notes")
    file_id = _first_file_id(app, users["alice"])
    login(bob, "bob")
    resp = bob.get(f"/files/{file_id}/download")
    assert resp.status_code == 404
    assert b"alice private case notes" not in resp.data
    event = audit_events(app, Action.ACCESS_DENIED)[-1]
    assert event.username == "bob" and event.file_id == file_id


def test_rbac06_idor_delete_and_verify_blocked(app, users):
    alice, bob = app.test_client(), app.test_client()
    login(alice, "alice")
    upload(alice, "case.txt", b"alice private case notes")
    file_id = _first_file_id(app, users["alice"])
    login(bob, "bob")
    assert bob.post(f"/files/{file_id}/delete").status_code == 404
    assert bob.post(f"/files/{file_id}/verify").status_code == 404
    with app.app_context():
        assert db.session.get(StoredFile, file_id) is not None


def test_rbac07_other_users_files_not_listed(app, users):
    alice, bob = app.test_client(), app.test_client()
    login(alice, "alice")
    upload(alice, "alice-only-report.txt", b"x" * 10)
    login(bob, "bob")
    assert b"alice-only-report.txt" not in bob.get("/files/").data


def test_rbac08_admin_cannot_download_staff_files(app, users):
    alice, admin = app.test_client(), app.test_client()
    login(alice, "alice")
    upload(alice, "case.txt", b"confidential")
    file_id = _first_file_id(app, users["alice"])
    login(admin, "admin")
    assert admin.get(f"/files/{file_id}/download").status_code == 403
    assert b"case.txt" not in admin.get("/admin/users").data


def test_rbac09_auditor_cannot_download_or_modify(app, users):
    alice, auditor = app.test_client(), app.test_client()
    login(alice, "alice")
    upload(alice, "case.txt", b"confidential")
    file_id = _first_file_id(app, users["alice"])
    login(auditor, "auditor")
    assert auditor.get(f"/files/{file_id}/download").status_code == 403
    assert auditor.post(f"/files/{file_id}/delete").status_code == 403
    assert auditor.post("/audit/").status_code == 405  # read-only: no POST route
    assert auditor.post(f"/admin/users/{users['alice']}/lock").status_code == 403


def test_rbac10_staff_cannot_escalate_privileges(app, users):
    alice = app.test_client()
    login(alice, "alice")
    assert alice.post(f"/admin/users/{users['alice']}/role", data={f"u{users['alice']}-role": "admin"}).status_code == 403
    assert alice.post("/admin/users/create", data={"username": "evil", "role": "admin",
                                                   "temp_password": "Evil-Passw0rd-123"}).status_code == 403
    with app.app_context():
        assert db.session.get(User, users["alice"]).role == "staff"
        assert db.session.execute(db.select(User).filter_by(username="evil")).scalar_one_or_none() is None


def test_rbac11_admin_can_manage_users(app, users):
    admin = app.test_client()
    login(admin, "admin")
    admin.post("/admin/users/create", data={"username": "erin", "role": "staff",
                                            "temp_password": "Temp-Passw0rd-123"})
    with app.app_context():
        erin = db.session.execute(db.select(User).filter_by(username="erin")).scalar_one()
        assert erin.must_change_password and erin.password_hash.startswith("$argon2id$")
        erin_id = erin.id
    admin.post(f"/admin/users/{erin_id}/role", data={f"u{erin_id}-role": "auditor"})
    with app.app_context():
        assert db.session.get(User, erin_id).role == "auditor"
    assert audit_events(app, Action.USER_CREATED) and audit_events(app, Action.ROLE_CHANGED)


def test_rbac12_admin_cannot_demote_or_lock_self(app, users):
    admin = app.test_client()
    login(admin, "admin")
    admin.post(f"/admin/users/{users['admin']}/role", data={f"u{users['admin']}-role": "staff"})
    admin.post(f"/admin/users/{users['admin']}/lock")
    with app.app_context():
        me = db.session.get(User, users["admin"])
        assert me.role == "admin" and not me.is_locked


def test_rbac13_role_change_revokes_session(app, users):
    alice, admin = app.test_client(), app.test_client()
    login(alice, "alice")
    login(admin, "admin")
    admin.post(f"/admin/users/{users['alice']}/role", data={f"u{users['alice']}-role": "auditor"})
    assert alice.get("/files/").status_code == 302  # must sign in again
