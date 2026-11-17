# SecureVault – Test Plan & Results

**Release criterion:** all critical security tests pass. Unresolved findings are recorded with severity, rationale and compensating controls (see `threat_model.md`).

**Tools:** pytest (automated functional and security tests), OWASP ZAP (baseline dynamic scan), Burp Suite Community (manual request tampering).

Run the automated suite:

```bash
python -m pytest -v                      # all tests
python -m pytest -v -k "idor or int0"    # a subset
```

Latest run: **115 passed, 0 failed** (Python 3.13, 2026-11-16).

## 1. Automated test cases

Each row maps to a pytest function (`tests/<file>::test_<id>_…`). *Preconditions* for all cases: fresh isolated app instance with its own master key, database and file store; demo users `admin`, `alice`, `bob` (Staff) and `auditor` created by fixtures.

### Authentication & sessions (`test_auth.py`)

| ID | Objective | Steps | Expected result | Crit. | Result |
|---|---|---|---|---|---|
| AUTH-01 | Valid login | POST valid credentials | 302 to role home; `login_success` logged | ✔ | Pass |
| AUTH-02 | Passwords hashed with Argon2id | Inspect `password_hash` | Starts with `$argon2id$`, no plaintext | ✔ | Pass |
| AUTH-03 | No user enumeration | Wrong password; unknown user | Identical generic message, 401 | | Pass |
| AUTH-04 | **Brute-force → lockout** | 5 wrong passwords, then correct one | Account locked; `account_locked` logged; correct password rejected | ✔ | Pass |
| AUTH-05 | Admin unlock | Lock alice, admin unlocks | Alice can sign in again | | Pass |
| AUTH-06 | Counter reset | 3 failures then success | `failed_login_count` = 0 | | Pass |
| AUTH-07 | **Expired session** | Set `last_active` 16 min ago, request page | Redirect to login; `session_expired` logged | ✔ | Pass |
| AUTH-08 | Active session kept | `last_active` 10 min ago | 200 | | Pass |
| AUTH-09 | Logout | GET /logout, then POST | GET 405; POST ends session | | Pass |
| AUTH-10 | Password change | Change password, re-login | Old fails, new works | | Pass |
| AUTH-11 | Password policy | New password `short` | 400 | | Pass |
| AUTH-12 | Revoke other sessions | Two sessions; change password in one | Other session rejected | ✔ | Pass |
| AUTH-13 | Forced temp-password change | Login with `must_change_password` | All pages redirect to change-password | | Pass |
| AUTH-14 | Lock kills live session | Admin locks logged-in user | User's next request → login | ✔ | Pass |
| AUTH-15 | Cookie flags | Login over HTTPS | `Secure; HttpOnly; SameSite=Strict` | ✔ | Pass |

### Authorization (`test_rbac.py`)

| ID | Objective | Steps | Expected result | Crit. | Result |
|---|---|---|---|---|---|
| RBAC-01 | Least-privilege matrix | Inspect `ROLE_PERMISSIONS` | Admin/Auditor lack file permission; Staff lacks audit | ✔ | Pass |
| RBAC-02 | Anonymous access | GET protected pages | Redirect to login | ✔ | Pass |
| RBAC-03 | **Privilege escalation via URL** | Each role requests each panel | Only own panel 200; others 403 | ✔ | Pass |
| RBAC-04 | Denials audited | Staff opens /admin | `access_denied` event | | Pass |
| RBAC-05 | **IDOR download** | Bob GETs Alice's file id | 404, no content; `access_denied` with file id | ✔ | Pass |
| RBAC-06 | IDOR delete/verify | Bob POSTs delete/verify on Alice's id | 404; file still exists | ✔ | Pass |
| RBAC-07 | Listing isolation | Bob lists files | Alice's file absent | ✔ | Pass |
| RBAC-08 | Admin ≠ document access | Admin downloads Staff file | 403; no filenames in admin UI | ✔ | Pass |
| RBAC-09 | **Unauthorized Auditor actions** | Auditor download/delete/POST audit/lock user | 403 / 405 | ✔ | Pass |
| RBAC-10 | Staff self-promotion | Staff POSTs role change / create admin | 403; DB unchanged | ✔ | Pass |
| RBAC-11 | Admin user management | Create user, change role | Success; Argon2id hash; temp-password flag; events logged | | Pass |
| RBAC-12 | Admin self-protection | Admin demotes/locks self | Refused | | Pass |
| RBAC-13 | Role change revokes session | Change role of logged-in user | Old session rejected | ✔ | Pass |

### Encryption & integrity (`test_files.py`, `test_crypto.py`)

| ID | Objective | Steps | Expected result | Crit. | Result |
|---|---|---|---|---|---|
| ENC-01 | Upload/list/download | Upload TXT, list, download | Verified badge; bytes identical; attachment; `no-store` | ✔ | Pass |
| ENC-02 | **No plaintext at rest** | Read `.enc` file | Marker string absent; size = plaintext + 16-byte tag; random name | ✔ | Pass |
| ENC-03 | Unique DEK & nonce | Upload same content twice | Different nonces, wrapped DEKs and ciphertexts | ✔ | Pass |
| ENC-04 | Key separation | Search DB and audit log for master key / content | Not found | ✔ | Pass |
| ENC-05 | Delete | Delete file | Ciphertext and wrapped DEK removed; logged | | Pass |
| ENC-06 | All allowed types | Upload PDF, PNG, JPG, DOCX, TXT | Round-trip exact | | Pass |
| INT-01 | **File tampering** | Flip 1 bit of ciphertext; download | Blocked (303); `integrity_failure: gcm_tag_mismatch`; status Failed | ✔ | Pass |
| INT-02 | Digest tampering | Alter stored SHA-256 | Blocked; `sha256_mismatch` | ✔ | Pass |
| INT-03 | Ciphertext swap | Copy file B over file A | Blocked (AAD binding) | ✔ | Pass |
| INT-04 | Wrapped-key tampering | Corrupt wrapped DEK | Blocked; `key_unwrap_failed` | ✔ | Pass |
| INT-05 | Missing ciphertext | Delete `.enc` file | Fails securely | | Pass |
| INT-06 | Manual verify | POST verify | "verified" message | | Pass |
| CRY-01…08 | Crypto unit tests | Round-trip, wrong key, AAD binding, re-wrap, key file perms, malformed key, no key in `repr`, CLI rotation | As named | ✔ | Pass |

### Input validation & injection (`test_validation.py`)

| ID | Objective | Steps | Expected result | Crit. | Result |
|---|---|---|---|---|---|
| VAL-01 | **Disallowed types** | Upload `.exe`, `.html`, `.php`, `.zip`, no extension | Rejected; `upload_rejected` logged | ✔ | Pass |
| VAL-02 | **Oversized file** | Upload 10 MB + 1 byte | Rejected | ✔ | Pass |
| VAL-03 | Boundary | Upload exactly 10 MB | Accepted | | Pass |
| VAL-04 | Huge body | Upload 11 MB | 413 | | Pass |
| VAL-05 | **Extension/content mismatch** | PNG as `.pdf`, PDF as `.png`, fake JPG/DOCX, EXE as `.txt`, NUL bytes in `.txt` | Rejected "does not match" | ✔ | Pass |
| VAL-06 | Empty file | Upload 0 bytes | Rejected | | Pass |
| VAL-07 | Filename sanitisation | `../../etc/passwd.txt`, `..\..\evil.txt`, `<script>…` | Directory parts and unsafe chars stripped | ✔ | Pass |
| VAL-08 | Invalid filenames | `..`, `CON.txt`, `.txt`, NULs | Rejected | | Pass |
| VAL-09 | Traversal name never used on disk | Upload `../../../../tmp/pwned.txt` | Display name `pwned.txt`; 64-hex storage name | ✔ | Pass |
| INJ-01 | **Path traversal in download** | `/files/../../etc/passwd/download` and encoded variants | 404; no `/etc/passwd` content | ✔ | Pass |
| INJ-02 | **SQL injection (login)** | `' OR '1'='1`, `admin'--`, `'; DROP TABLE users;--` | 401; tables intact | ✔ | Pass |
| INJ-03 | SQL injection (audit filter) | Injection strings in filters | 200, no error | ✔ | Pass |
| INJ-04 | **Stored XSS (filename)** | Upload `<img src=x onerror=alert(1)>.txt` | No executable markup in listing | ✔ | Pass |
| INJ-05 | Stored XSS (login → audit) | Login as `<script>alert('xss')</script>` | Rendered escaped in Auditor view | ✔ | Pass |

### Hardening & logging (`test_hardening.py`)

| ID | Objective | Steps | Expected result | Crit. | Result |
|---|---|---|---|---|---|
| SEC-01 | Security headers | GET /login | CSP (no `unsafe-inline`, `frame-ancestors 'none'`), nosniff, `X-Frame-Options: DENY`, Referrer-Policy | ✔ | Pass |
| SEC-02 | HSTS | GET over HTTPS | `max-age=31536000` | ✔ | Pass |
| SEC-03 | HTTPS enforcement | GET over HTTP | Redirect to https:// | ✔ | Pass |
| SEC-04 | **CSRF enforcement** | POST without / with forged / with valid token | 400 / 400 / success; `csrf_failure` logged | ✔ | Pass |
| SEC-04b | CSRF Referer check (HTTPS) | Valid token with no / cross-site / same-origin Referer | 400 / 400 / passes | ✔ | Pass |
| SEC-05 | Login rate limit | Exceed limit | 429; `rate_limited` logged | ✔ | Pass |
| SEC-06 | No debug info | GET unknown URL | Custom 404, no traceback | | Pass |
| SEC-07 | No caching | Authenticated page | `Cache-Control: no-store` | | Pass |
| SEC-08 | Missing master key | Start without key | 503 – fails closed | ✔ | Pass |
| SEC-09 | Insecure key permissions | Key file mode 644 | Startup refused | ✔ | Pass |
| LOG-01 | Required fields | Generate events | timestamp, action, result, IP; user/file ids where relevant | ✔ | Pass |
| LOG-02 | **No secrets logged** | Wrong + right passwords, file upload | Passwords and contents absent from DB and file logs | ✔ | Pass |
| LOG-03 | Structured file log | Parse `audit.log` | Valid JSON with required keys | | Pass |
| LOG-04 | Auditor filters | Filter by action/user | Matching events only | | Pass |
| LOG-05 | Auditor has no content access | Inspect audit view | Document content absent | ✔ | Pass |

## 2. Manual verification (record screenshots as evidence)

| ID | Objective | Steps | Expected |
|---|---|---|---|
| MAN-01 | Ciphertext on disk | `seed-demo`; `xxd data/files/*.enc \| head` | Random bytes; names are 64 hex chars |
| MAN-02 | Tampering in GUI | `python scripts/tamper_file.py <id>`; refresh *My documents* | Status **Failed**, Download shows **Blocked**, Auditor sees `integrity_failure` |
| MAN-03 | Lockout in GUI | 5 wrong passwords for `bob` | Generic error; Admin panel shows **Locked**; Auditor sees `account_locked` |
| MAN-04 | Idle timeout | Sign in, wait 15 min, click any link | Redirect to login with expiry message |
| MAN-05 | Master key not in Git | `git status`, `git check-ignore -v secrets/master.key` | Key ignored |
| MAN-06 | TLS | Open `https://127.0.0.1:5443`, view certificate & response headers | TLS connection; HSTS, CSP present |

## 3. OWASP ZAP baseline scan

1. Start the app: `python run.py` and sign in once in the browser to accept the certificate.
2. Run a baseline (passive) scan, e.g. with Docker:
   ```bash
   docker run --rm --network host -v "$(pwd)":/zap/wrk ghcr.io/zaproxy/zaproxy:stable \
     zap-baseline.py -t https://127.0.0.1:5443/login -r zap-report.html
   ```
   or ZAP desktop → *Automated Scan* → URL `https://127.0.0.1:5443`.
3. For an authenticated scan, configure a ZAP *Context* with form-based authentication (`/login`, fields `username`, `password`, `csrf_token` via *Anti-CSRF tokens* option) using a Staff demo account.
4. Record each alert: risk, URL, evidence, and either the fix or the justification. Expected informational/low alerts for a local prototype: self-signed certificate; *Cookie without SameSite* should **not** appear.

## 4. Burp Suite Community – manual request tampering

| ID | Request | Tamper | Expected |
|---|---|---|---|
| BURP-01 | `GET /files/<own id>/download` | Change id to another user's file | 404; `access_denied` in audit log |
| BURP-02 | `POST /files/upload` | Change filename to `../../app/evil.py`, change `Content-Type` header to `application/pdf` while sending EXE bytes | Rejected (content signature); name sanitised |
| BURP-03 | `POST /admin/users/<id>/role` as Staff | Replay an Admin request with Staff cookie | 403 |
| BURP-04 | Any POST | Remove or modify `csrf_token` | 400; `csrf_failure` logged |
| BURP-05 | `POST /login` (Intruder, Sniper) | 20 password guesses | Account locked after 5; 429 after rate limit |
| BURP-06 | Session cookie | Replay cookie after logout / password change | Redirect to login (session revoked) |

## 5. Findings log

| ID | Finding | Severity | Status |
|---|---|---|---|
| F-01 | Login failed in real browsers with "referrer header is missing": `Referrer-Policy: no-referrer` conflicted with Flask-WTF strict HTTPS CSRF Referer check | Medium (availability) | **Fixed** – policy changed to `same-origin`; regression test SEC-04b added |
| F-02 | Master key protected by filesystem permissions only | Medium | Accepted for prototype – documented; HSM/KMS recommended |
| F-03 | Audit log stored in same environment as the app | Medium | Accepted – JSON-line copy; SIEM/WORM recommended |
