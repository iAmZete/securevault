"""Argon2id password hashing (argon2-cffi).

Parameters follow the argon2-cffi defaults, which implement the RFC 9106
"low memory" recommended profile (Argon2id, t=3, m=64 MiB, p=4).
"""
from __future__ import annotations

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_hasher = PasswordHasher(type=Type.ID)

# Used to equalise timing when a username does not exist, so that response
# time does not reveal which accounts are valid.
_DUMMY_HASH = _hasher.hash("securevault-dummy-password-for-timing")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored_hash: str | None, password: str) -> bool:
    if stored_hash is None:
        try:
            _hasher.verify(_DUMMY_HASH, password)
        except VerificationError:
            pass
        return False
    try:
        return _hasher.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except InvalidHashError:
        return True
