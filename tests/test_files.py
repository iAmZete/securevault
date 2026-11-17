"""Encryption-at-rest and integrity tests (ENC-xx / INT-xx)."""
from __future__ import annotations

from pathlib import Path

from app.extensions import db
from app.models import StoredFile
from app.security.audit import Action

from .conftest import audit_events, login, make_docx, make_jpg, make_pdf, make_png, upload

SECRET = b"SYNTHETIC client 0042 - incident report: confidential plaintext marker"


def _records(app):
    with app.app_context():
        rows = db.session.execute(db.select(StoredFile).order_by(StoredFile.id)).scalars().all()
        db.session.expunge_all()
        return rows


def _path(app, record) -> Path:
    return Path(app.config["STORAGE_DIR"]) / f"{record.storage_name}.enc"


def test_enc01_upload_list_download_roundtrip(client, users, app):
    login(client, "alice")
    resp = upload(client, "incident-report.txt", SECRET)
    assert resp.status_code == 302
    listing = client.get("/files/")
    assert b"incident-report.txt" in listing.data and b"Verified" in listing.data
    record = _records(app)[0]
    resp = client.get(f"/files/{record.id}/download")
    assert resp.status_code == 200 and resp.data == SECRET
    assert "attachment" in resp.headers["Content-Disposition"]
    assert resp.headers["Cache-Control"] == "no-store"
    assert audit_events(app, Action.UPLOAD) and audit_events(app, Action.DOWNLOAD)


def test_enc02_no_plaintext_in_file_store(client, users, app):
    login(client, "alice")
    upload(client, "incident-report.txt", SECRET)
    record = _records(app)[0]
    stored = _path(app, record).read_bytes()
    assert SECRET not in stored and b"SYNTHETIC" not in stored
    assert len(stored) == len(SECRET) + 16  # ciphertext + 128-bit GCM tag
    # Random storage name: the original filename never touches the disk.
    files = list(Path(app.config["STORAGE_DIR"]).iterdir())
    assert all("incident" not in f.name for f in files)


def test_enc03_unique_key_and_nonce_per_file(client, users, app):
    login(client, "alice")
    upload(client, "a.txt", SECRET)
    upload(client, "b.txt", SECRET)
    a, b = _records(app)
    assert a.file_nonce != b.file_nonce and a.wrapped_dek != b.wrapped_dek
    assert _path(app, a).read_bytes() != _path(app, b).read_bytes()
    assert a.sha256 == b.sha256  # same plaintext digest


def test_enc04_master_key_not_in_db_or_store(client, users, app):
    login(client, "alice")
    upload(client, "a.txt", SECRET)
    key_text = Path(app.config["MASTER_KEY_FILE"]).read_bytes().split(b":", 1)[1].strip()
    db_path = Path(app.config["DATA_DIR"]) / "test.db"
    assert key_text not in db_path.read_bytes()
    log = (Path(app.config["LOG_DIR"]) / "audit.log").read_bytes()
    assert key_text not in log and SECRET not in log


def test_int01_tampered_ciphertext_blocks_download(client, users, app):
    login(client, "alice")
    upload(client, "care-plan.txt", SECRET)
    record = _records(app)[0]
    path = _path(app, record)
    data = bytearray(path.read_bytes())
    data[5] ^= 0x01
    path.write_bytes(bytes(data))

    resp = client.get(f"/files/{record.id}/download")
    assert resp.status_code == 303
    assert SECRET not in resp.data
    events = audit_events(app, Action.INTEGRITY_FAILURE)
    assert events and "gcm_tag_mismatch" in events[-1].details and events[-1].file_id == record.id
    assert _records(app)[0].integrity_status == "failed"
    assert b"Failed" in client.get("/files/").data


def test_int02_tampered_digest_metadata_detected(client, users, app):
    login(client, "alice")
    upload(client, "care-plan.txt", SECRET)
    with app.app_context():
        rec = db.session.execute(db.select(StoredFile)).scalar_one()
        rec.sha256 = "0" * 64
        db.session.commit()
        fid = rec.id
    resp = client.get(f"/files/{fid}/download")
    assert resp.status_code == 303
    assert "sha256_mismatch" in audit_events(app, Action.INTEGRITY_FAILURE)[-1].details


def test_int03_swapped_ciphertext_between_files_detected(client, users, app):
    login(client, "alice")
    upload(client, "a.txt", b"first synthetic document")
    upload(client, "b.txt", b"second synthetic document")
    a, b = _records(app)
    _path(app, a).write_bytes(_path(app, b).read_bytes())
    assert client.get(f"/files/{a.id}/download").status_code == 303


def test_int04_tampered_wrapped_key_detected(client, users, app):
    login(client, "alice")
    upload(client, "a.txt", SECRET)
    with app.app_context():
        rec = db.session.execute(db.select(StoredFile)).scalar_one()
        wk = bytearray(rec.wrapped_dek)
        wk[0] ^= 0xFF
        rec.wrapped_dek = bytes(wk)
        db.session.commit()
        fid = rec.id
    client.get(f"/files/{fid}/download")
    assert "key_unwrap_failed" in audit_events(app, Action.INTEGRITY_FAILURE)[-1].details


def test_int05_missing_ciphertext_fails_securely(client, users, app):
    login(client, "alice")
    upload(client, "a.txt", SECRET)
    record = _records(app)[0]
    _path(app, record).unlink()
    assert client.get(f"/files/{record.id}/download").status_code == 303


def test_int06_manual_verify(client, users, app):
    login(client, "alice")
    upload(client, "a.txt", SECRET)
    record = _records(app)[0]
    resp = client.post(f"/files/{record.id}/verify", follow_redirects=True)
    assert b"verified" in resp.data


def test_enc05_delete_removes_ciphertext_and_key(client, users, app):
    login(client, "alice")
    upload(client, "a.txt", SECRET)
    record = _records(app)[0]
    path = _path(app, record)
    assert client.post(f"/files/{record.id}/delete").status_code == 302
    assert not path.exists()
    assert _records(app) == []
    assert audit_events(app, Action.DELETE)[-1].file_id == record.id


def test_enc06_all_allowed_types_roundtrip(client, users, app):
    login(client, "alice")
    samples = {"a.pdf": make_pdf(), "b.png": make_png(), "c.jpg": make_jpg(), "d.docx": make_docx(),
               "e.txt": b"plain text"}
    for name, content in samples.items():
        assert upload(client, name, content).status_code == 302
    records = {r.original_name: r for r in _records(app)}
    assert set(records) == set(samples)
    for name, content in samples.items():
        resp = client.get(f"/files/{records[name].id}/download")
        assert resp.status_code == 200 and resp.data == content
