# SecureVault – STRIDE Threat Model

Scope: browser, Flask application, SQLite database, encrypted file store, authentication/session handling and master-key material (see trust boundaries TB1–TB3 in `architecture.md`).

Risk rating = Likelihood × Impact (L/M/H). Ratings shown are **inherent** (before mitigation) → **residual** (after mitigation). Validation tests reference pytest test IDs in `tests/` and the test plan.

## Assets

| ID | Asset | Security property |
|---|---|---|
| A1 | Client documents (plaintext) | Confidentiality, integrity |
| A2 | Encrypted file store | Integrity, availability |
| A3 | Master key (KEK) | Confidentiality |
| A4 | Wrapped DEKs & file metadata (DB) | Integrity |
| A5 | User credentials & sessions | Confidentiality, integrity |
| A6 | Audit log | Integrity, availability |

## Threats

| # | STRIDE | Component / asset | Threat & vulnerability | L | I | Inherent | Mitigation | Residual | Validation |
|---|---|---|---|---|---|---|---|---|---|
| T1 | **S**poofing | Auth (A5) | Online brute-force / credential stuffing against login | H | H | **High** | Argon2id; lockout after 5 failures; per-IP rate limit (10/min); generic errors | Low | AUTH-04, SEC-05 |
| T2 | **S**poofing | Auth (A5) | Username enumeration via error text or timing | M | M | Medium | Single generic message; dummy Argon2 verify for unknown users | Low | AUTH-03 |
| T3 | **S**poofing | Session (A5) | Session hijack / fixation / long-lived stolen session | M | H | High | `session.clear()` on login; HttpOnly/Secure/SameSite=Strict; 15-min idle timeout; nonce-based revocation on password/role change and lock | Low | AUTH-07, AUTH-12, AUTH-14, AUTH-15 |
| T4 | **S**poofing | Browser (TB1) | Cross-site request forgery on state-changing actions | M | H | High | CSRF token on every POST; strict Referer check over HTTPS; SameSite=Strict; logout is POST-only | Low | SEC-04, SEC-04b, AUTH-09 |
| T5 | **T**ampering | File store (A2) | Attacker with disk access modifies ciphertext | M | H | High | AES-GCM tag + SHA-256 check on every download/listing; failure blocks download and is logged | Low | INT-01, INT-05 |
| T6 | **T**ampering | DB (A4) | Modify digest, swap ciphertext/keys between files or owners | L | H | Medium | AAD binds ciphertext and wrapped DEK to storage name, owner and key version; digest comparison | Low | INT-02, INT-03, INT-04, CRY-03 |
| T7 | **T**ampering | App (TB2) | SQL injection via login, filters, filenames | M | H | High | ORM-only parameterised queries; allow-list filter values; escaped LIKE | Low | INJ-02, INJ-03 |
| T8 | **T**ampering | Browser | Stored XSS via filenames / usernames in tables | M | M | Medium | Filename sanitisation; Jinja2 auto-escaping; CSP without `unsafe-inline` | Low | INJ-04, INJ-05, SEC-01 |
| T9 | **T**ampering | Upload | Malicious upload (executable, web shell, polyglot, macro DOCX, zip bomb) | M | H | High | Extension allow-list + magic-byte check; DOCX structure/macro/size checks; always served as attachment with `nosniff`; never executed | Low | VAL-01, VAL-05 |
| T10 | **R**epudiation | Audit (A6) | User denies an action; insider misuse unnoticed | M | M | Medium | Structured audit events (timestamp, user, action, file, IP, result) for all security events; Auditor-only read access | Medium* | LOG-01, LOG-04 |
| T11 | **R**epudiation | Audit (A6) | Attacker with host access edits/deletes logs | L | M | Low | Duplicate JSON-line file log; documented limitation; recommend SIEM/WORM | Low/Med* | – (documented) |
| T12 | **I**nformation disclosure | Store (A1) | Stolen disk/backup exposes documents | M | H | High | AES-256-GCM at rest; master key stored separately; random file names | Low | ENC-02 |
| T13 | **I**nformation disclosure | Key (A3) | Master key committed to Git, logged, or readable by other users | M | H | High | `secrets/`, `*.key` git-ignored; startup refuses group/world-readable key; key never logged or in `repr` | Low (prototype) | ENC-04, SEC-09, CRY-07 |
| T14 | **I**nformation disclosure | Files (A1) | IDOR: accessing another user's file by id | H | H | **High** | Owner-scoped queries; 404 for foreign ids; denial audited | Low | RBAC-05, RBAC-06, RBAC-07 |
| T15 | **I**nformation disclosure | Store | Path traversal (`../../etc/passwd`) in download/upload | M | H | High | Integer-only route ids; server-generated storage names; path containment check | Low | INJ-01, VAL-07, VAL-09 |
| T16 | **I**nformation disclosure | App | Verbose errors / stack traces / caching of sensitive pages | M | M | Medium | Debug off; custom error pages; `Cache-Control: no-store` on authenticated pages | Low | SEC-06, SEC-07 |
| T17 | **I**nformation disclosure | Audit | Passwords, keys, tokens or contents written to logs | M | H | High | Only metadata passed to logger; regex redaction; truncation | Low | LOG-02, LOG-05 |
| T18 | **I**nformation disclosure | Transport | Eavesdropping / downgrade on network | M | H | High | HTTPS only; HTTP→HTTPS redirect; HSTS | Low | SEC-02, SEC-03 |
| T19 | **D**enial of service | Upload | Huge uploads / zip bombs exhaust memory or disk | M | M | Medium | `MAX_CONTENT_LENGTH`; 10 MB per-file limit; bounded read; DOCX expansion cap | Low | VAL-02, VAL-04 |
| T20 | **D**enial of service | Auth | Attacker deliberately locks out users | M | M | Medium | Admin unlock; rate limit slows attacks; lockout events visible to Auditor | Medium* | AUTH-05 |
| T21 | **E**levation of privilege | RBAC | Staff/Auditor calls Admin endpoints or changes own role | M | H | High | Server-side `permission_required` on every route; deny-by-default matrix | Low | RBAC-03, RBAC-09, RBAC-10 |
| T22 | **E**levation of privilege | RBAC | Admin reads Staff documents | M | H | High | Admin lacks `MANAGE_OWN_FILES`; admin UI exposes no file data | Low | RBAC-08 |
| T23 | **E**levation of privilege | Session | Demoted/locked user keeps old privileges in live session | M | H | High | Session nonce rotation on role change/lock; locked users fail `user_loader` | Low | RBAC-13, AUTH-14 |

\* Accepted residual risk – see below.

## Accepted residual risks & compensating controls

| Risk | Severity | Rationale | Compensating control / recommendation |
|---|---|---|---|
| Master key protected only by OS file permissions (T13) | Medium | No HSM available for an academic prototype | Separate path outside DB/store, mode 600 enforced, rotation command; production → HSM/KMS |
| Audit log on same host (T10/T11) | Medium | Single-host prototype | JSON-line file copy; production → SIEM / append-only storage with hash chain |
| Targeted lockout DoS (T20) | Low–Medium | Lockout is required by the proposal | Rate limit, admin unlock, auditor visibility; production → progressive delays / CAPTCHA |
| Self-signed certificate | Low | Local deployment only | Production → CA-issued cert behind nginx |
