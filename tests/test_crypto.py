"""Unit tests for the cryptography module (CRY-xx)."""
from __future__ import annotations

import os

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.security.crypto import (CryptoService, IntegrityError, MasterKeyError,
                                 generate_master_key_file, load_master_key, sha256_hex)


def _svc(version=1):
    return CryptoService(AESGCM.generate_key(bit_length=256), key_version=version)


def _decrypt(svc, enc, storage="s" * 64, owner=1, version=1):
    return svc.decrypt_and_verify(enc.ciphertext, file_nonce=enc.file_nonce, wrapped_dek=enc.wrapped_dek,
                                  dek_nonce=enc.dek_nonce, storage_name=storage, owner_id=owner,
                                  key_version=version, expected_sha256=enc.sha256)


def test_cry01_roundtrip():
    svc = _svc()
    enc = svc.encrypt_file(b"hello world", "s" * 64, 1)
    assert enc.sha256 == sha256_hex(b"hello world")
    assert len(enc.file_nonce) == 12 and len(enc.wrapped_dek) == 48
    assert _decrypt(svc, enc) == b"hello world"


def test_cry02_wrong_master_key_fails():
    enc = _svc().encrypt_file(b"data", "s" * 64, 1)
    with pytest.raises(IntegrityError) as exc:
        _decrypt(_svc(), enc)
    assert exc.value.reason == "key_unwrap_failed"


def test_cry03_aad_binds_owner_and_storage_name():
    svc = _svc()
    enc = svc.encrypt_file(b"data", "s" * 64, 1)
    with pytest.raises(IntegrityError):
        _decrypt(svc, enc, owner=2)
    with pytest.raises(IntegrityError):
        _decrypt(svc, enc, storage="t" * 64)


def test_cry04_rewrap_preserves_access():
    old, new = _svc(1), _svc(2)
    enc = old.encrypt_file(b"data", "s" * 64, 1)
    dek = old.unwrap_dek(enc.wrapped_dek, enc.dek_nonce, "s" * 64, 1, 1)
    wrapped, nonce = new.wrap_dek(dek, "s" * 64, 1)
    plaintext = new.decrypt_and_verify(enc.ciphertext, file_nonce=enc.file_nonce, wrapped_dek=wrapped,
                                       dek_nonce=nonce, storage_name="s" * 64, owner_id=1,
                                       key_version=2, expected_sha256=enc.sha256)
    assert plaintext == b"data"


def test_cry05_master_key_file_lifecycle(tmp_path):
    path = generate_master_key_file(tmp_path / "k" / "master.key")
    if os.name == "posix":
        assert oct(path.stat().st_mode & 0o777) == "0o600"
    key, version = load_master_key(path)
    assert len(key) == 32 and version == 1
    with pytest.raises(MasterKeyError):
        generate_master_key_file(path)  # never overwrite silently


def test_cry06_malformed_master_key_rejected(tmp_path):
    bad = tmp_path / "bad.key"
    bad.write_text("v1:not-base64!!")
    os.chmod(bad, 0o600)
    with pytest.raises(MasterKeyError):
        load_master_key(bad)
    short = tmp_path / "short.key"
    short.write_text("v1:AAAA")
    os.chmod(short, 0o600)
    with pytest.raises(MasterKeyError):
        load_master_key(short)


def test_cry07_repr_does_not_leak_key():
    key = AESGCM.generate_key(bit_length=256)
    assert key.hex() not in repr(CryptoService(key))


def test_cry08_rotate_master_key_cli(make_app, users, app):
    from .conftest import login, upload
    client = app.test_client()
    login(client, "alice")
    upload(client, "a.txt", b"before rotation")
    runner = app.test_cli_runner()
    result = runner.invoke(args=["rotate-master-key", "--yes"])
    assert result.exit_code == 0, result.output
    _, version = load_master_key(app.config["MASTER_KEY_FILE"], enforce_permissions=False)
    assert version == 2
    # A fresh app instance loads the new key and still decrypts the file.
    app2 = make_app()
    c2 = app2.test_client()
    login(c2, "alice")
    from app.extensions import db
    from app.models import StoredFile
    with app2.app_context():
        fid = db.session.execute(db.select(StoredFile.id)).scalar_one()
    assert c2.get(f"/files/{fid}/download").data == b"before rotation"
