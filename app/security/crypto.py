"""AES-256-GCM envelope encryption and SHA-256 integrity verification.

Design
------
* Each file gets its own random 256-bit Data Encryption Key (DEK) and its own
  random 96-bit nonce. The file is encrypted with AES-256-GCM under the DEK.
* The DEK is then *wrapped* (encrypted) with the 256-bit master key, again
  with AES-256-GCM and a fresh nonce. Only the wrapped DEK is stored, in the
  database, next to the file metadata.
* The master key lives in a separate, permission-restricted file (TB3). It is
  never written to the database, the file store, or the logs.
* Associated data (AAD) binds every ciphertext to its storage name and owner,
  so an attacker cannot swap ciphertext or wrapped keys between records.
* A SHA-256 digest of the plaintext is recorded at upload and recomputed after
  decryption on every download as an additional integrity check.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_BYTES = 32    # AES-256
NONCE_BYTES = 12  # 96-bit nonce recommended for GCM


class MasterKeyError(RuntimeError):
    """The master key is missing, malformed, or insecurely stored."""


class IntegrityError(Exception):
    """Decryption or integrity verification failed. Fail securely: no data."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class EncryptedFile:
    ciphertext: bytes
    file_nonce: bytes
    wrapped_dek: bytes
    dek_nonce: bytes
    sha256: str


# ---------------------------------------------------------------------------
# Master key handling
# ---------------------------------------------------------------------------

def encode_master_key(key: bytes, version: int = 1) -> bytes:
    """Serialise a master key as ``v<version>:<base64>``."""
    return f"v{version}:".encode() + base64.b64encode(key) + b"\n"


def generate_master_key_file(path: Path, overwrite: bool = False) -> Path:
    """Create a new random master key file with owner-only permissions."""
    path = Path(path)
    if path.exists() and not overwrite:
        raise MasterKeyError(f"Master key already exists at {path}; refusing to overwrite.")
    path.parent.mkdir(parents=True, exist_ok=True)
    _restrict_dir(path.parent)
    key = AESGCM.generate_key(bit_length=256)
    _write_secret(path, encode_master_key(key, 1))
    return path


def load_master_key(path: Path, enforce_permissions: bool = True) -> tuple[bytes, int]:
    """Return ``(key, key_version)`` from a master key file."""
    path = Path(path)
    if not path.is_file():
        raise MasterKeyError(
            f"Master key file not found at {path}. Run `flask --app run.py init` "
            "or `python scripts/generate_master_key.py` first."
        )
    if enforce_permissions and os.name == "posix":
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise MasterKeyError(
                f"Master key file {path} is accessible by group/others (mode {oct(mode)}). "
                "Run: chmod 600 on the file."
            )
    raw = path.read_bytes().strip()
    version = 1
    if raw.startswith(b"v") and b":" in raw:
        prefix, raw = raw.split(b":", 1)
        try:
            version = int(prefix[1:])
        except ValueError as exc:
            raise MasterKeyError("Master key file has an invalid version prefix.") from exc
    try:
        key = base64.b64decode(raw, validate=True)
    except ValueError as exc:
        raise MasterKeyError("Master key file is not valid base64.") from exc
    if len(key) != KEY_BYTES:
        raise MasterKeyError("Master key must be exactly 256 bits.")
    return key, version


def _restrict_dir(path: Path) -> None:
    if os.name == "posix":
        try:
            os.chmod(path, 0o700)
        except PermissionError:
            pass


def _write_secret(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if sys.platform != "win32":
        flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    if os.name == "posix":
        os.chmod(path, 0o600)


# ---------------------------------------------------------------------------
# Envelope encryption
# ---------------------------------------------------------------------------

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_aad(storage_name: str, owner_id: int) -> bytes:
    return f"securevault:v1:file:{storage_name}:{owner_id}".encode()


def _dek_aad(storage_name: str, owner_id: int, key_version: int) -> bytes:
    return f"securevault:v1:dek:{storage_name}:{owner_id}:{key_version}".encode()


class CryptoService:
    def __init__(self, master_key: bytes, key_version: int = 1):
        if len(master_key) != KEY_BYTES:
            raise MasterKeyError("Master key must be exactly 256 bits.")
        self._master = AESGCM(master_key)
        self.key_version = key_version

    def __repr__(self) -> str:  # never leak key material via repr/logging
        return f"<CryptoService key_version={self.key_version}>"

    # -- DEK wrapping -------------------------------------------------------
    def wrap_dek(self, dek: bytes, storage_name: str, owner_id: int) -> tuple[bytes, bytes]:
        nonce = os.urandom(NONCE_BYTES)
        wrapped = self._master.encrypt(nonce, dek, _dek_aad(storage_name, owner_id, self.key_version))
        return wrapped, nonce

    def unwrap_dek(self, wrapped: bytes, nonce: bytes, storage_name: str, owner_id: int,
                   key_version: int) -> bytes:
        try:
            return self._master.decrypt(nonce, wrapped, _dek_aad(storage_name, owner_id, key_version))
        except InvalidTag as exc:
            raise IntegrityError("key_unwrap_failed") from exc

    # -- File encryption ----------------------------------------------------
    def encrypt_file(self, plaintext: bytes, storage_name: str, owner_id: int) -> EncryptedFile:
        dek = AESGCM.generate_key(bit_length=256)
        file_nonce = os.urandom(NONCE_BYTES)
        ciphertext = AESGCM(dek).encrypt(file_nonce, plaintext, _file_aad(storage_name, owner_id))
        wrapped, dek_nonce = self.wrap_dek(dek, storage_name, owner_id)
        return EncryptedFile(
            ciphertext=ciphertext,
            file_nonce=file_nonce,
            wrapped_dek=wrapped,
            dek_nonce=dek_nonce,
            sha256=sha256_hex(plaintext),
        )

    def decrypt_and_verify(self, ciphertext: bytes, *, file_nonce: bytes, wrapped_dek: bytes,
                           dek_nonce: bytes, storage_name: str, owner_id: int,
                           key_version: int, expected_sha256: str) -> bytes:
        """Decrypt, check the GCM tag, then compare the plaintext SHA-256.

        Raises IntegrityError on any failure; plaintext is never returned
        unless *both* checks pass.
        """
        dek = self.unwrap_dek(wrapped_dek, dek_nonce, storage_name, owner_id, key_version)
        try:
            plaintext = AESGCM(dek).decrypt(file_nonce, ciphertext, _file_aad(storage_name, owner_id))
        except InvalidTag as exc:
            raise IntegrityError("gcm_tag_mismatch") from exc
        if not hmac.compare_digest(sha256_hex(plaintext), expected_sha256):
            raise IntegrityError("sha256_mismatch")
        return plaintext
