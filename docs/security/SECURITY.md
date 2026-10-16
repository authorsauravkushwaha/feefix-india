# FeeFix Security Model

FeeFix handles what students type about themselves — income, community, marks.
This document is the threat model and how the codebase answers it, mapped to the
**CIA triad** (Confidentiality · Integrity · Availability).

> **Scope, honestly stated.** Every control here is implemented and tested, and
> the tests are described next to each claim so you can check them. The suite,
> the fuzzer and the static checks were written by the same author as the code,
> so they encode the same assumptions — **there has been no third-party
> penetration test and no external security review**. Where a control is only a
> UX nicety (the clipboard helper) or a configuration choice (interactive docs),
> it says so out loud instead of being dressed up as defence.
>
> **Attack-by-attack detail:** [`HARDENING.md`](HARDENING.md) maps all 13 named
> attack classes to the exact file, control and test that covers each one.

## Confidentiality — who can see what

| Threat | Control | Evidence |
|---|---|---|
| Password theft from the database | **Argon2id** — memory-hard, `t=3`, `m=48 MiB`, `p=1`, 16-byte salt, 32-byte tag (OWASP range; env-tunable). Memory-hardness is the point: PBKDF2-HMAC-SHA256 at 600k iterations was CPU-cheap to parallelise on GPUs/ASICs. Legacy `pbkdf2$` rows still verify and are **re-hashed to Argon2id on the next successful sign-in**, so the weak scheme drains out of a live database with no forced resets. If `argon2-cffi` cannot be installed, the fallback is `hashlib.scrypt` (also memory-hard) and the boot log says so — never a silent downgrade to PBKDF2. | `tests/test_password_hashing.py` |
| Hash-flooding the CPU with one huge password | Passwords are length-capped **and pre-hashed to 32 bytes** before the KDF, so cost is input-size independent; at most `FEEFIX_KDF_CONCURRENCY` (default 4) hashes run at once, so 48 MiB-per-hash cannot exhaust RAM. When those slots are saturated the API answers **503 + `Retry-After`** — a retryable capacity signal, deliberately not 401/422, because reporting a busy pool as "wrong credentials" would have users and clients treat a load spike as an account problem. Unknown-email, wrong-password and known-user requests answer **identically** under back-pressure, so it leaks nothing either. | `test_password_hashing.py::TestKdfBackPressure` |
| Session-token theft from the database | Tokens are 256-bit random (`secrets.token_urlsafe`); **only the SHA-256 hash is stored** — a leaked table yields nothing replayable. | `test_auth.py` |
| User enumeration (does an account exist?) | Register/login return **uniform, identical errors**, and login always runs the KDF (even for unknown emails) so response *time* leaks nothing. | `test_auth.py` |
| Cross-origin snooping | SPA + API share one origin; **CORS is closed by default** (`FEEFIX_CORS_ORIGINS` opt-in only). | — |
| Response intermediaries caching data | `Cache-Control: no-store` on every `/api/*` response. | — |
| Cross-account reads | Account-owned sessions require the owner's bearer token (`_authorize_session`) on profile, tracker, match, ML, reminders and **documents**. Anonymous sessions remain usable by random-URL knowledge only. | `test_uploads_api.py`, `test_security_hardening.py` |
| Token replay in transit | HSTS when TLS terminates in front (`Strict-Transport-Security` behind `https`/`x-forwarded-proto: https`). | `test_security_hardening.py` |
| Session-token replay *within* the service | Tokens auto-rotate after 24 h (`X-Session-Token`). A replayed superseded token is **tombstoned at once** and surfaced (`X-Session-Warning`, `GET /api/auth/security-events`) while the live token survives — so a stale tab or an offline app no longer logs the user out everywhere. Escalation to family revocation happens on sustained replay (≥3 in the window) or via `FEEFIX_SESSION_REUSE_POLICY=revoke_family`. | `test_session_reuse_policy.py` |
| Uploaded documents being readable | Files are stored under `FEEFIX_UPLOAD_DIR` (default `runtime/uploads`) — **outside the web root**, never statically mounted, random 128-bit names, `attachment` + `nosniff` on download, and erased with the account. | `test_uploads_api.py` |

## Integrity — who can change what

| Threat | Control | Evidence |
|---|---|---|
| XSS injection | Strict **Content-Security-Policy** (`script-src 'self'`), no inline scripts, SPA escapes every interpolated value, `X-Content-Type-Options: nosniff`, `_json_html_safe()` for the one HTML page. | `test_fuzzing.py` |
| Clickjacking | `frame-ancestors` CSP directive (self + preview hosts only). | — |
| SQL injection | **Impossible by construction** — parameterized statements everywhere; a test scans the source to keep it that way. | `test_security_hardening.py` |
| Malicious uploads | Extension allowlist + magic-byte sniffing + size cap + sanitised names; a `shell.php` renamed to `.pdf` is rejected, and the wiring check refuses to let the gate become dead code again. | `test_uploads_api.py`, `test_wiring_and_claims.py` |
| Unauthorized state changes | Append-only **audit log** (register/login/rotation/replay/erase/document actions); foreign keys engine-enforced. | `test_auth.py` |
| Schema drift | Additive, versioned migrations via `PRAGMA user_version` (v1 → v4). | — |
| Shortcut "auth" via JWTs | We don't mint JWTs — **opaque, server-side, revocable** sessions only. | — |

## Availability — keeping the service up

| Threat | Control | Evidence |
|---|---|---|
| Credential brute-force | 10 auth attempts / 5 min per IP+account → 429 with `Retry-After`. | `test_security_hardening.py` |
| Request floods | 1000 req/min per IP on `/api/*`, counted in a **shared store** so the limit is not multiplied by the number of workers or instances (`FEEFIX_REDIS_URL` for multi-instance; the process-local store is opt-in and warns loudly). Verified by spawning real processes. | `test_rate_limit_shared.py` |
| Rate-limit bypass across replicas | The default store is the app's SQLite file, updated inside `BEGIN IMMEDIATE`; `/api/health` reports the backend, whether it is shared, and any topology warning. | `test_rate_limit_shared.py` |
| Limiter state growth | The counter table is bounded and pruned — the DoS shield cannot become the DoS vector. | `test_rate_limit_shared.py` |
| Password-hashing capacity (a deliberate bound) | `FEEFIX_KDF_CONCURRENCY` (default 4) caps transient hashing memory at roughly 192 MiB. Excess sign-ins get a **503 with `Retry-After: 2`** — never a wrong-credentials error — and the service recovers as slots free. | `test_password_hashing.py` |
| Limiter store outage | Failures are counted and reported (`rate_limit.degraded_events`); `FEEFIX_RATELIMIT_FAIL_MODE=closed` refuses traffic instead of failing open. | `test_rate_limit_shared.py` |
| Slow loris / giant payloads | **Per-endpoint** body caps enforced *while the body streams* — chunked requests with no `Content-Length` are bounded too, and the 413 states the limit and scope so real large uploads have a path. | `test_body_limits.py` |
| ReDoS / pathological input | User text is length-capped before any regex; digit runs bounded; the income lexicon is data-compiled and script-validated; timing tests hold. | `test_numerals_i18n.py` |
| Info leakage via errors | Opaque 500s with a `request_id`; the fuzzer asserts no traceback, path or internal class name is ever returned. | `test_fuzzing.py` |
| Model-download hang at boot | The neural embedder's weight download is bounded (`FEEFIX_AI_LOAD_TIMEOUT`, default 20 s) and degrades to the built-in offline embedder. An unbounded download previously hung the process (and the test suite) indefinitely. | `test_wiring_and_claims.py` |
| Crash consistency | SQLite **WAL mode** + `busy_timeout`. | — |
| Bad configuration shipping | Placeholder/weak secrets are **fatal in strict mode** (`FEEFIX_STRICT_SECRETS=1` or production markers) instead of a log line; unsafe limiter topology is reported (fatal in strict mode). | `test_boot_policy.py` |

## Privacy guarantees

* **Progressive enhancement** — every feature works anonymously; accounts are opt-in.
* **Data portability** — `GET /api/auth/export` returns everything the account holds.
* **Right to erasure** — `DELETE /api/auth/account` removes the user, sessions,
  owned profiles, tracker rows **and uploaded document files**.
* AI is local-only: nothing is sent to an external model or API (`ai/README.md`).

## Interactive API docs

`/docs`, `/redoc` and `/openapi.json` are **on by default**. Disabling them never
removed an endpoint or an attack surface — the routes answered regardless — while
breaking generated clients and QA. `FEEFIX_DISABLE_DOCS=1` remains available and
is documented as cosmetic, not as a control.

## Verifying the claims in this document

```bash
python -m pytest                                        # full suite
python -m pytest tests/test_rate_limit_shared.py        # limiter across processes
python -m pytest tests/test_wiring_and_claims.py        # controls are wired, docs match code
python -m scripts.fuzz_api --requests 2000 --seed 1     # randomised API probing
python -m agents.secret_scan --history --check-ci       # secrets + CI wiring
node --test "web/tests/*.test.mjs"                      # clipboard behaviour
pip-audit -r requirements.txt                           # dependency advisories
```

## Reporting a vulnerability

Open a private security advisory on the repository (or email the maintainer).
Please do not file public issues for exploitable findings.

## Hardening roadmap (free, incremental)

1. Optional TOTP second factor.
2. Redis-backed limiter as the documented default for multi-instance deploys
   (the store exists; deployments without Redis still share state per host).
3. An external review or pen test — the one thing this repository cannot
   self-supply, and the reason the gap above is stated rather than implied away.
