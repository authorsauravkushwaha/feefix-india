# FeeFix Threat Hardening Map

Every attack class below is answered by **concrete, tested code** in this
repository — not just policy. The regression suite in
[`tests/test_security_hardening.py`](../tests/test_security_hardening.py)
proves each control. Run it with `python -m pytest`.

| # | Attack | Where it's answered | Control |
|---|--------|---------------------|---------|
| 1 | **Replay attack** | `services/auth.py`, `backend/main.py`, `web/frontend/app.js` | Opaque bearer tokens are **rotated** once they've lived `ROTATE_AFTER_S` (24 h); the fresh token returns in `X-Session-Token`. A token that was already rotated and is then **replayed after the grace window revokes the whole session family** (reuse detection). OAuth `state` and OTP codes are single-use. |
| 2 | **Clipboard attack** | `web/frontend/secure-clipboard.js`, `web/frontend/auth-gate.js` | `FeeFixClipboard.secureCopy()` **refuses to copy the auth token** (or anything token-shaped) and auto-clears the clipboard ~20 s after any copy. The OTP paste-to-fill path wipes the clipboard immediately so a copied code can't linger for malware. The token never lives in the clipboard, a URL, or a log. |
| 3 | **SQL / NoSQL injection** | `services/db.py`, `services/sqlite_store.py`, `services/otp.py` | **Every** statement is parameterized; no string-built SQL exists (a test scans the source to keep it that way). SQLite has no NoSQL/`$where` surface. Injection payloads are treated as inert data. |
| 4 | **Secret key leaks** | `.gitignore`, `agents/secret_scan.py`, CI | The OTP pepper (`runtime/.otp_pepper`) and `.env*`/`*.pem`/`*.key` are **git-ignored**. A **secret-scanning agent** gates CI — it flags provider-token shapes and secret-name assignments while ignoring URLs, test fixtures and placeholders. |
| 5 | **Long-password DoS** | `services/auth.py`, `api/schemas.py`, `services/limits.py` | Passwords are **length-capped** (`MAX_PASSWORD_LEN`) at the schema *and* service layer, and **pre-hashed with SHA-256 before PBKDF2** so KDF work is constant regardless of length — a 100 MB "password" can't burn CPU. |
| 6 | **ReDoS** | `services/limits.py`, `services/chat.py`, `api/schemas.py` | All user text is **length-capped before any regex runs**; income parsers use **bounded digit quantifiers** (`\d{1,12}`) so a long digit-run can't trigger super-linear backtracking; a timing test asserts pathological inputs finish fast. |
| 7 | **Server-side template injection** | `api/routes.py`, `web/frontend/app.js` | The API returns **JSON only** — there is no server-side template engine to inject into. The one HTML the server emits (the OAuth handoff) splices payload through `_json_html_safe()`, which neutralises `</script>`, attribute and entity breakouts. The SPA renders everything through `esc()` / `safeUrl()`. |
| 8 | **Error handling & info leakage** | `backend/main.py` | The catch-all handler **logs the traceback server-side** and returns an opaque `{"detail":"Internal server error.","request_id":…}` — never a class name, message or stack. Interactive API docs (`/docs`, `/openapi.json`) are **off unless `FEEFIX_ENABLE_DOCS` is set**. |
| 9 | **File upload security** | `services/upload.py` | A single hardened gate for any future upload: **extension allowlist**, **magic-byte content sniffing** (a renamed `shell.php`→`.pdf` is rejected), size cap, path-traversal-safe filenames, random storage names, never executable. |
| 10 | **Secret management** | `services/secrets.py` | Secrets are read **only from the environment**; `weak_secret_findings()` warns at boot if a configured secret looks like a placeholder. No secret is ever hard-coded or defaulted to a real value. |
| 11 | **Input validation** | `services/limits.py`, `api/schemas.py`, `models/student.py`, `backend/main.py` | Centralized length caps on every field; enum-constrained profiles; **1 MB request-body limit** enforced before parsing; `domicile`/`minority_community` bounded. Oversized/invalid input → `413`/`422`, never processed. |
| 12 | **Rate limiting** | `services/ratelimit.py`, `backend/main.py` | Sliding-window limits with **per-endpoint tiers** (tight limits on CPU-heavy AI endpoints), a **memory-bounded** hit table (its own DoS vector), proxy-aware client IP (`X-Forwarded-For` only behind a trusted proxy), and a `Retry-After` header on `429`. |
| 13 | **authentication ≠ authorization** | `api/routes.py` | Authentication (`_require_user`) proves *who you are*; authorization (`_authorize_session`) proves *you own this session's data*. Ownership is now enforced on **every** endpoint that touches a session — profile, tracker, match, ML rank, reminders, dispatch, events and personalised Q&A. Anonymous sessions stay open by design. |

## Defence in depth already present

PBKDF2-HMAC-SHA256 (600k rounds, per-user salt) · SHA-256-hashed revocable
session tokens · uniform login errors (no user-enumeration) · strict CSP ·
HSTS · `no-store` on `/api/*` · CORS closed by default · append-only audit log ·
SQLite WAL + foreign keys. See [`SECURITY.md`](SECURITY.md).

## Verifying it yourself

```bash
python -m pytest tests/test_security_hardening.py   # one suite per attack class
python -m agents.secret_scan                        # no committed secrets
python -m agents.verify_dataset                     # dataset + (--check-urls) liveness
```
