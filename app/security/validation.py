"""Server-side input validation (allow-list based).

Covers usernames, passwords, display filenames and uploaded file content.
Uploaded files must pass *all* of: extension allow-list, size limit, and a
content-signature ("magic bytes") check that matches the extension.
"""
from __future__ import annotations

import io
import re
import unicodedata
import zipfile
from dataclasses import dataclass

USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{2,31}$")


class ValidationError(ValueError):
    pass


# ---------------------------------------------------------------------------
# Accounts
# ---------------------------------------------------------------------------

def normalize_username(raw: str | None) -> str:
    return (raw or "").strip().lower()


def validate_username(raw: str | None) -> str:
    username = normalize_username(raw)
    if not USERNAME_RE.fullmatch(username):
        raise ValidationError(
            "Username must be 3-32 characters: lowercase letters, digits, '.', '_' or '-', "
            "starting with a letter or digit."
        )
    return username


def validate_password_strength(password: str, username: str = "", min_length: int = 12,
                               max_length: int = 128) -> None:
    if len(password) < min_length:
        raise ValidationError(f"Password must be at least {min_length} characters long.")
    if len(password) > max_length:
        raise ValidationError(f"Password must be at most {max_length} characters long.")
    classes = sum(bool(re.search(p, password)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    if classes < 3:
        raise ValidationError(
            "Password must contain at least three of: lowercase, uppercase, digits, symbols."
        )
    if username and username.lower() in password.lower():
        raise ValidationError("Password must not contain the username.")


# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------

# extension -> MIME type sent on download
ALLOWED_TYPES: dict[str, str] = {
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "txt": "text/plain; charset=utf-8",
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
}

_SAFE_NAME_CHARS = re.compile(r"[^A-Za-z0-9 ._()\-]")
_WINDOWS_RESERVED = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}
MAX_FILENAME_LENGTH = 200


@dataclass(frozen=True)
class ValidatedUpload:
    display_name: str
    extension: str
    mime_type: str
    data: bytes


def sanitize_filename(raw: str | None) -> str:
    """Return a safe *display* name. It is never used as a filesystem path."""
    name = unicodedata.normalize("NFKC", raw or "")
    # Drop any directory components (both separators), control chars and NULs.
    name = name.replace("\\", "/").split("/")[-1]
    name = "".join(ch for ch in name if ch.isprintable())
    name = _SAFE_NAME_CHARS.sub("", name)
    name = re.sub(r"\s+", " ", name)
    name = re.sub(r"\.{2,}", ".", name).strip(" .")
    if not name or "." not in name:
        raise ValidationError("Filename is missing or has no extension.")
    stem, _, ext = name.rpartition(".")
    if not stem or stem.lower() in _WINDOWS_RESERVED:
        raise ValidationError("Filename is not allowed.")
    if len(name) > MAX_FILENAME_LENGTH:
        stem = stem[: MAX_FILENAME_LENGTH - len(ext) - 1]
        name = f"{stem}.{ext}"
    return name


def _looks_like_text(data: bytes) -> bool:
    if b"\x00" in data:
        return False
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return False
    # Reject control characters other than common whitespace.
    bad = sum(1 for ch in text if ord(ch) < 32 and ch not in "\t\n\r\f")
    return bad == 0


def _is_docx(data: bytes) -> bool:
    if not data.startswith(b"PK\x03\x04"):
        return False
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = set(zf.namelist())
            if "[Content_Types].xml" not in names or "word/document.xml" not in names:
                return False
            # Basic zip-bomb guard: refuse archives that expand hugely.
            total = sum(info.file_size for info in zf.infolist())
            if total > 100 * 1024 * 1024:
                return False
            # Refuse macro-enabled content disguised as .docx.
            if any(n.lower().endswith("vbaproject.bin") for n in names):
                return False
        return True
    except (zipfile.BadZipFile, ValueError, OSError):
        return False


_KNOWN_BINARY_SIGNATURES = (
    b"%PDF-", b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"PK\x03\x04", b"MZ", b"\x7fELF",
    b"GIF8", b"#!",
)


def content_matches_extension(ext: str, data: bytes) -> bool:
    if ext == "pdf":
        return data.startswith(b"%PDF-")
    if ext == "png":
        return data.startswith(b"\x89PNG\r\n\x1a\n")
    if ext in ("jpg", "jpeg"):
        return data.startswith(b"\xff\xd8\xff")
    if ext == "docx":
        return _is_docx(data)
    if ext == "txt":
        return _looks_like_text(data) and not data.startswith(_KNOWN_BINARY_SIGNATURES)
    return False


def validate_upload(filename: str | None, data: bytes, max_bytes: int) -> ValidatedUpload:
    display_name = sanitize_filename(filename)
    ext = display_name.rsplit(".", 1)[1].lower()
    if ext not in ALLOWED_TYPES:
        allowed = ", ".join(sorted({e.upper() for e in ALLOWED_TYPES} - {"JPEG"}))
        raise ValidationError(f"File type '.{ext}' is not allowed. Allowed types: {allowed}.")
    if len(data) == 0:
        raise ValidationError("The uploaded file is empty.")
    if len(data) > max_bytes:
        raise ValidationError(f"File exceeds the {max_bytes // (1024 * 1024)} MB size limit.")
    if not content_matches_extension(ext, data):
        raise ValidationError("File content does not match its extension.")
    return ValidatedUpload(display_name=display_name, extension=ext,
                           mime_type=ALLOWED_TYPES[ext], data=data)
