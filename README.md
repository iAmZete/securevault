# SecureVault

**Encrypted document storage with role-based access control and integrity verification.**
MCSC 6002 – Cybersecurity Architecture, Design, and Secure Software Development · Option 6: Secure File Storage System
Humber Polytechnic · Wilson Osigwe, Medalion Mahdavinia, Hemanth Kumar Venkataram

SecureVault is a Flask web application for a community-services agency that stores confidential client case files (care plans, incident reports, intake forms). Every file is encrypted at rest with AES-256-GCM under its own key, access is restricted by role and ownership, every download is integrity-checked, and all security-relevant events are written to an audit log that only the Auditor can read.

> ⚠️ Academic prototype. Use synthetic documents and test identities only. Never store real personal or health information.

---

## Features

| Area | What is implemented |
|---|---|
| Authentication | Argon2id password hashing · lockout after 5 failed attempts · 15-minute idle session timeout · forced change of admin-issued temporary passwords · password change revokes all other sessions · generic login errors (no user enumeration) · timing-equalised login for unknown users |
| Access control | Three roles (Admin, Staff, Auditor) · server-side permission checks on every protected route · per-file ownership checks (IDOR → 404 + audit) · Admin cannot read Staff documents · Auditor is read-only and cannot reach document contents · role change / lock immediately revokes live sessions |
| Input validation | Allow-list for PDF, DOCX, TXT, PNG, JPG · magic-byte content check (extension must match content) · 10 MB limit · DOCX structure, macro and zip-bomb checks · filename sanitisation · random 256-bit on-disk names · ORM-only (parameterised) SQL · Jinja2 auto-escaping |
| Encryption | AES-256-GCM per file with a unique random DEK and nonce · envelope encryption: DEK wrapped with a 256-bit master key · AAD binds ciphertext to file and owner · master key in a separate `chmod 600` file outside DB and file store · `rotate-master-key` command re-wraps all DEKs |
| Integrity | SHA-256 of plaintext recorded at upload · on every download/listing: GCM tag check **and** SHA-256 comparison · failure blocks the download, marks the file *Failed* and logs `integrity_failure` |
| Transport & headers | HTTPS (TLS) with local certificate · HSTS · strict CSP (no inline script/style) · `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy` · Secure / HttpOnly / SameSite=Strict cookies · CSRF token on every state-changing request · login rate limiting |
| Audit logging | Structured records (timestamp, user, action, file id, source IP, result, details) in the DB and as JSON lines in `logs/audit.log` · secrets/contents never logged · Auditor UI with filters by user, action, result and date |

## Architecture at a glance

```
Browser ──TB1 (TLS, CSRF, validation)──▶ Flask app ──TB2──▶ SQLite (metadata, wrapped DEKs)
                                             │       └────▶ File store (ciphertext only, random names)
                                             └──TB3──▶ master.key (separate, chmod 600, never in Git)
```

Full diagrams, trust boundaries and the permission matrix: [`docs/architecture.md`](docs/architecture.md).
STRIDE threat model: [`docs/threat_model.md`](docs/threat_model.md).
Test plan and results: [`docs/test_plan.md`](docs/test_plan.md).

## Project layout

```
app/
  __init__.py          application factory, request hooks (idle timeout, forced password change)
  config.py            configuration (paths, session, upload, hardening)
  extensions.py        SQLAlchemy, Flask-Login, CSRF, Limiter, Talisman
  models.py            User, StoredFile, AuditEvent
  forms.py             Flask-WTF forms (CSRF tokens)
  cli.py               init, create-admin, seed-demo, rotate-master-key
  security/
    passwords.py       Argon2id hashing
    rbac.py            permission matrix and decorators
    validation.py      usernames, passwords, filenames, file signatures
    crypto.py          AES-256-GCM envelope encryption, master key handling
    audit.py           centralised audit logging
  services/storage.py  encrypted file store (save / verify / delete)
  routes/              auth, files (Staff), admin, auditor, main (errors)
  templates/, static/  Jinja2 + Bootstrap 5 GUI (no CDN, CSP-friendly)
scripts/
  generate_cert.py     self-signed TLS certificate for localhost
  generate_master_key.py
  tamper_file.py       demo helper for the tampering test
tests/                 pytest suite (functional + attack scenarios)
docs/                  architecture, threat model, test plan
```

## Getting started

Requires Python 3.12+.

```bash
git clone https://github.com/hemanthkumarvenkataram/securevault.git
cd securevault
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 1. Create the master key, data directories and database
flask --app run.py init

# 2. Create a TLS certificate for https://127.0.0.1
python scripts/generate_cert.py

# 3a. Create your first administrator...
flask --app run.py create-admin
# 3b. ...or load demo accounts (admin, alice, bob, auditor) with synthetic files
flask --app run.py seed-demo

# 4. Run over HTTPS
python run.py                      # → https://127.0.0.1:5443
```

The browser will warn about the self-signed certificate; accept it for local testing.

### Where secrets and data live (all git-ignored)

| Item | Default location | Override |
|---|---|---|
| Master key (KEK) | `secrets/master.key` | `SECUREVAULT_MASTER_KEY_FILE` |
| Flask session-signing key | `secrets/flask_secret.key` | `SECUREVAULT_SECRET_KEY` or `SECUREVAULT_SECRET_KEY_FILE` |
| TLS cert / key | `secrets/tls/` | `SECUREVAULT_TLS_CERT`, `SECUREVAULT_TLS_KEY` |
| Database | `data/securevault.db` | `SECUREVAULT_DATABASE_URI` |
| Encrypted files | `data/files/` | `SECUREVAULT_STORAGE_DIR` |
| Audit log file | `logs/audit.log` | `SECUREVAULT_LOG_DIR` |

For a stronger separation, keep the master key outside the project directory entirely, e.g.
`export SECUREVAULT_MASTER_KEY_FILE=~/.securevault/master.key` before running `init`. The app refuses to start if the key file is readable by group or others.

### Master key rotation

```bash
flask --app run.py rotate-master-key
```

Generates a new master key, re-wraps every file's DEK (file ciphertext is untouched), and keeps a timestamped backup of the old key for you to destroy after verifying backups.

## Running the tests

```bash
python -m pytest -v
```

The suite (115 tests) covers functional behaviour and every attack scenario in the proposal: brute-force lockout, SQL injection, stored XSS, path traversal, IDOR, privilege escalation, file tampering (ciphertext, digest, wrapped key, swapped files), disallowed/oversized/mismatched uploads, CSRF, rate limiting, headers, session expiry and log hygiene. See [`docs/test_plan.md`](docs/test_plan.md) for the test-case table and the OWASP ZAP / Burp Suite procedures.

## Demo walkthrough (for the recording)

1. `seed-demo`, then sign in as **alice** → upload a PDF, view *Verified* status, download it.
2. Try uploading `evil.exe`, a PNG renamed to `.pdf`, and an 11 MB file → all rejected.
3. Run `python scripts/tamper_file.py --list`, then `python scripts/tamper_file.py <id>` → refresh: file shows **Failed**, download blocked.
4. Sign in as **bob**, request `/files/<alice's id>/download` → 404, logged as `access_denied`.
5. Five wrong passwords for **bob** → account locked; sign in as **admin** → unlock.
6. Sign in as **auditor** → filter by `integrity_failure`, `access_denied`, `account_locked`.
7. Inspect `data/files/*.enc` with a hex viewer → ciphertext only, random names.

## Known limitations

* The master key is protected by filesystem permissions only. In production it should live in an HSM or a managed KMS (AWS KMS, Azure Key Vault, HashiCorp Vault Transit) so that the key never leaves the hardware boundary.
* The audit log shares the application host and database; a fully compromised host could alter it. Production should forward events to an append-only/WORM store or SIEM.
* SHA-256 digests are stored alongside the metadata, so they are not an independent guarantee against an attacker who can also modify the database; AES-GCM's AAD binding provides the stronger guarantee.
* The development server (`python run.py`) is for local demonstration. A production deployment would run behind a hardened reverse proxy (nginx) with a WSGI server (gunicorn) and a CA-issued certificate.
* Rate-limit counters are in memory; use Redis (`SECUREVAULT_RATELIMIT_STORAGE=redis://…`) when running multiple workers.

## Team

| Member | Primary ownership |
|---|---|
| Wilson Osigwe | Architecture, STRIDE threat model, AES-256-GCM envelope encryption, integrity verification |
| Hemanth Kumar Venkataram | Authentication flow, Argon2id, sessions, lockout, RBAC, Admin functions |
| Medalion Mahdavinia | Validation rules, GUI, upload validation, CSRF, security headers, audit interface |
