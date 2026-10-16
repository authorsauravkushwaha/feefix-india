# FeeFix Threat Hardening Map

Every attack class below is answered by **concrete, tested code** — not policy,
and not a checkbox. Each row names the file, the control, and the test that keeps
it honest.

> **What this document is not:** proof that FeeFix is secure. It is a map of the
> controls that exist and how they are verified. There has been **no third-party
> penetration test and no external security review** — the suite, the fuzzer and
> the audit tooling were all written by the same person who wrote the code, so
> they share its blind spots. Treat the tables below as "what was defended and
> how it is checked", never as "what is proven safe".

Run the evidence yourself:

```bash
python -m pytest                                     # suite incl. property tests
python -m pytest tests/test_rate_limit_redis.py       # multi-instance limiter (fake Redis + Lua)
python -m pytest tests/test_rate_limit_shared.py     # limiter across processes
python -m scripts.fuzz_api --requests 2000 --seed 1  # randomised API probing
python -m agents.secret_scan --history --check-ci    # secrets (this branch) + CI wiring
python -m agents.secret_scan --history --all-branches  # whole-repo audit (see note)
node --test "web/tests/*.test.mjs"                   # clipboard behaviour
pip-audit -r requirements.txt                        # dependency advisories
```

| # | Attack | Where it's answered | Control | Test |
|---|--------|---------------------|---------|------|
| 1 | **Replay attack** | `services/auth.py`, `backend/main.py` | Bearer tokens rotate after 24 h (`X-Session-Token`). A replayed superseded token is **tombstoned immediately** and reported (`X-Session-Warning`), while the live token keeps working — sustained replay (≥3 in the window) or an opt-in `FEEFIX_SESSION_REUSE_POLICY=revoke_family` escalates to revoking the family. Events are visible at `GET /api/auth/security-events`; the user's own hammer is `POST /api/auth/logout-all`. OAuth `state` and OTP codes are single-use. | `test_session_reuse_policy.py` |
| 2 | **Clipboard** | `web/frontend/secure-clipboard.js` | **The helper is UX hygiene, not a security control** — clipboard-stealing malware reads a value the instant it is written. What it *does* enforce: the session token (or any token-shaped value) is **never copied**, and the courtesy wipe only fires after reading the clipboard back and confirming it still holds our value, so the user's own clipboard content is never destroyed. Failures are reported, not swallowed. | `web/tests/clipboard.test.mjs`, `test_security_hardening.py` |
| 3 | **SQL / NoSQL injection** | `services/db.py`, `services/sqlite_store.py`, `services/otp.py` | Every statement is parameterized; a test scans the source so no string-built SQL can land. SQLite has no NoSQL surface. Injection payloads are inert data. | `test_security_hardening.py` |
| 4 | **Secret key leaks** | `agents/secret_scan.py`, `.gitignore`, CI | Scanner covers provider token shapes, **entropy** (including 40+ hex characters), **split/re-joined literals**, and every text file (not an extension allowlist). `--history` scans committed history **attributed to the real file path** (so fixtures stay exempt and `.secretscanignore` still applies) and is scoped to this branch by default; `--all-branches` is the operator-run whole-repo audit. `--check-ci` asserts the CI step is unconditional. False positives are handled with `.secretscanignore` / `# pragma: allowlist secret` / `# secret-scan: allow` instead of disabling the job. | `test_secret_scan.py`, `test_wiring_and_claims.py` |
| 5 | **Long-password DoS** | `services/auth.py`, `services/limits.py` | Passwords are length-capped in the schema *and* the service, and **pre-hashed with SHA-256** so KDF cost is independent of input size. Memory-hard hashing is itself bounded: at most `FEEFIX_KDF_CONCURRENCY` (default 4) concurrent KDFs, so 48 MiB-per-hash cannot be turned into RAM exhaustion. Saturation answers **503 + `Retry-After`** (uniformly for known/unknown/wrong credentials, so it enumerates nothing) rather than masquerading as bad credentials. | `test_password_hashing.py` |
| 6 | **ReDoS** | `services/limits.py`, `services/numerals.py` | All user text is length-capped before any regex runs; digit runs use bounded quantifiers; the income lexicon is compiled from **escaped data**, not hand-written alternations. Timing tests keep pathological inputs fast. | `test_security_hardening.py`, `test_numerals_i18n.py` |
| 7 | **Server-side template injection** | `api/routes.py`, `web/frontend/app.js` | The API returns JSON only — there is no server-side template engine. The single HTML page (OAuth handoff) splices its payload through `_json_html_safe()`, which neutralises `</script>`, entity and line-terminator breakouts, and is property-tested with arbitrary Unicode. | `test_fuzzing.py` |
| 8 | **Error handling & info leakage** | `backend/main.py` | The catch-all handler logs the traceback server-side and returns an opaque `{"detail": "Internal server error.", "request_id": …}`. The fuzzer asserts no `Traceback`, path or internal class name ever reaches a client. Interactive docs are **on by default** — hiding them never was a control; see the note below. | `test_fuzzing.py` |
| 9 | **File upload security** | `services/upload.py`, `services/documents.py`, `api/routes.py` | A real, wired-in pipeline: extension allowlist, magic-byte sniffing, size cap, sanitised filenames, random storage names **outside the web root**, `attachment` + `nosniff` on download, ownership checks, and file deletion on account erasure. Earlier this module was hardened but called by nothing; that is now covered by tests and by a static wiring check. | `test_uploads_api.py`, `test_wiring_and_claims.py` |
| 10 | **Secret management** | `services/secrets.py` | Secrets are read from the environment only. The boot check **enforces**: in strict mode (`FEEFIX_STRICT_SECRETS=1`, or production markers such as `RENDER`/`FLY_APP_NAME`/`K_SERVICE`) a placeholder or half-configured credential **aborts startup**. In development it warns loudly. | `test_boot_policy.py` |
| 11 | **Input validation** | `services/limits.py`, `services/body_limit.py`, `api/schemas.py` | Central caps, **per endpoint** (chat 64 KB, Q&A 32 KB, auth 8 KB, JSON API 256 KB, uploads their own budget) — every knob env-tunable. Bodies are counted **while they stream**, so a chunked request with no `Content-Length` cannot bypass the gate, and the 413 reports the limit and scope so a legitimate large client can adapt. | `test_body_limits.py` |
| 12 | **Rate limiting** | `services/ratelimit.py`, `backend/main.py` | Sliding-window limits with a **shared store by default** (SQLite, atomic via `BEGIN IMMEDIATE`; Redis when `FEEFIX_REDIS_URL` is set) so limits hold across worker processes and instances. The process-local store is opt-in, warns loudly when workers are configured, and is regression-tested for the multiplication it causes. Bounded counter table, proxy-aware client IP anchored to the *right* of `X-Forwarded-For`, `Retry-After` on 429, and store outages that are counted in `/api/health` (fail-closed if `FEEFIX_RATELIMIT_FAIL_MODE=closed`). | `test_rate_limit_shared.py` |
| 13 | **authentication ≠ authorization** | `api/routes.py` | `_require_user` proves identity; `_authorize_session` proves ownership — enforced on every session-scoped endpoint including documents, ML rank and events. Anonymous sessions stay open by design. | `test_uploads_api.py`, `test_security_hardening.py` |

### History-scan scope (and what a whole-repo audit will show)

`python -m agents.secret_scan --history` scans the **current branch's** lineage.
That is deliberate: a pull-request gate should fail for a secret *this* change
introduces, not for the deliberately fake credentials that some other in-flight
branch's scanner tests contain. Use `--all-branches` when you want the full
repository audit, and expect it to list test fixtures and sample tokens — that is
what those branches' test suites are made of, not a leak.

## Why interactive docs are ON

`/docs`, `/redoc` and `/openapi.json` are enabled by default. Turning them off
removed no endpoint and no attack surface — every route answered anyway — while
breaking generated clients, QA and tooling. The API is protected by auth,
ownership checks, validation, body caps and rate limits, not by hiding its shape.
`FEEFIX_DISABLE_DOCS=1` still works if you want it; treat that as cosmetic.

## Defence in depth already present

Argon2id (t=3, m=48 MiB, p=1; legacy PBKDF2 rows re-hash on next sign-in) ·
SHA-256-hashed revocable session tokens · uniform login errors (no
user-enumeration) · strict CSP · HSTS · `no-store` on `/api/*` · CORS closed by
default · append-only audit log · SQLite WAL + foreign keys + versioned
migrations. See [`SECURITY.md`](SECURITY.md).

## What is *not* covered (honest gaps)

* No external penetration test, no third-party review, no bug-bounty history.
* The fuzzer is a TestClient harness: it does not exercise real HTTP framing,
  TLS termination, proxy behaviour or browser-side logic.
* The SQLite-backed limiter shares state through *one database file* — correct
  for one host (any number of workers), not for a multi-region deployment.
  That needs Redis, and `topology_warnings()` says so at boot.
* Denial-of-service resistance is argued from bounded work per request, not
  measured under a real flood.
* The dataset's factual accuracy is a separate concern from its security.
