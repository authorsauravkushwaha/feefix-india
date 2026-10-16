# FeeFix Security Model

FeeFix handles what students type about themselves — income, community, marks.
This document is the threat model and how the codebase answers it, mapped to
the **CIA triad** (Confidentiality · Integrity · Availability).

> **Attack-by-attack detail:** [`HARDENING.md`](HARDENING.md) maps all 13 named
> attack classes (replay, clipboard, SQL/NoSQL injection, secret leaks,
> long-password DoS, ReDoS, SSTI, info leakage, file upload, secret management,
> input validation, rate limiting, auth≠authz) to the exact file, control and
> regression test that defeats each one, plus an abuse-case table.
>
> **Read that document's last section first if you are auditing us:** it lists
> what these controls do *not* prove.

## Confidentiality — who can see what

| Threat | Control |
|---|---|
| Password theft from the database | **Argon2id** (`time_cost=2`, `memory_cost=19 MiB`, `parallelism=1` — OWASP parameters) is the production default; `FEEFIX_ENV=production` or `FEEFIX_PASSWORD_ALGO=argon2id` makes a deployment **refuse to boot** without `argon2-cffi` instead of silently serving a weakened hash. Legacy `pbkdf2$600000$<salt>$<digest>` rows still verify and are **re-hashed to Argon2id on the next successful login**, when the plaintext is actually available. Tests assert the plaintext never appears in the DB bytes. |
| Session-token theft from the database | Tokens are 256-bit random (`secrets.token_urlsafe`). **Only the SHA-256 hash is stored** — a leaked table yields nothing replayable. |
| User enumeration (does an account exist?) | Register/login return **uniform, identical errors**; login always runs the KDF even for unknown emails, so response *time* leaks nothing either. |
| Cross-origin snooping | SPA + API share one origin; **CORS is closed by default** (`FEEFIX_CORS_ORIGINS` opt-in only). |
| Response intermediaries caching data | `Cache-Control: no-store` on every `/api/*` response. |
| Cross-account reads | Account-owned sessions require the owner's bearer token — enforced server-side (`_authorize_session`) on profile, tracker, match, ML, upload and dispatch endpoints. Anonymous sessions remain usable by random-URL knowledge only. |
| Token replay in transit | HSTS when TLS terminates in front (`Strict-Transport-Security` behind `https`/`x-forwarded-proto: https`). |
| Session-token replay *within* the service | Rotation after 24 h with a 15-minute overlap window, then refusal + audit while the live session survives; family revocation only after repeated refusals from a *different* device fingerprint. One stale tab must never log the user out everywhere (`HARDENING.md` #1). |
| Secrets in the repository or the environment | Scanning runs in pre-commit, pre-push and CI (first-party scanner + gitleaks); boot-time hygiene checks **refuse to start** in production when a secret is missing, placeholder-shaped, or missing its companion variable. Neither proves a secret was never leaked — rotation is still an operator duty (`HARDENING.md` #4/#10). |
| Sensitive text on the clipboard | **Not protected.** `secure-clipboard.js` refuses to copy credential-shaped values and clears after a short TTL, but any malware on the machine reads the clipboard immediately — the module itself reports `securityControl: false`. The session token is never copied, never placed in a URL, never logged. |

## Integrity — who can change what

| Threat | Control |
|---|---|
| XSS injection | Strict **Content-Security-Policy** (`script-src 'self'` — no remote code, no inline scripts), the SPA escapes every interpolated value by design, `X-Content-Type-Options: nosniff`. |
| Clickjacking | `frame-ancestors` CSP directive (self + preview hosts only). |
| SQL injection | **Impossible by construction** — every statement in the `backend/services/db.py`-backed stores is parameterized; no string-built SQL exists in the codebase. |
| Malicious uploads | Extension allowlist **and** magic-byte sniffing, byte/file quotas per session, path-traversal-safe random storage names, stored outside the static mount, never executable, ownership-checked on every read/delete. Session identifiers are validated by one rule on every route and the resolved storage path must stay inside the upload root, so a hostile id (`..`, NUL, `/`, 10 KB long) is refused before it can touch the filesystem. |
| Unauthorized state changes | Append-only **audit log** records register / login / session-bind / rotation / replay refusal / delete; foreign keys are engine-enforced (`PRAGMA foreign_keys=ON`). |
| Schema drift | Additive, versioned, **transactional** migrations via `PRAGMA user_version`; concurrent boots (multiple instances/workers) serialize on `BEGIN IMMEDIATE` and a half-applied migration self-heals instead of bricking the database. |
| Tamper-prone roll-your-own tokens | We don't mint JWTs — **opaque, server-side, revocable** sessions only. Logout and account deletion revoke instantly. |

## Availability — keeping the service up

| Threat | Control |
|---|---|
| Credential brute-force | **Sliding-window rate limit**: 10 auth attempts / 5 min per IP+account → HTTP 429, and auth buckets **fail closed** if the shared store is unreachable. |
| Request floods | Global limit 1000 req/min per IP on `/api/*`, and **shared across instances** when `FEEFIX_REDIS_URL` is set; without a shared store the app warns at boot that the effective limit is `N × instances`. |
| Rate-limit evasion by header | `X-Forwarded-For` is only honoured with `FEEFIX_TRUST_PROXY=1`, and the **rightmost** hop is used (the leftmost is client-supplied and rotating it bought unlimited buckets before the fix). |
| Slow loris / giant payloads | Body caps are enforced **per endpoint while the body streams** → `413` without buffering the payload; the blunt 1 MB global cap was replaced by 16 KB–2 MB policies per endpoint class, each env-tunable and clamped to a 16 MB absolute ceiling. Legitimate large inputs (a 20 KB notes field, a 2 MB certificate scan) get the headroom they need (`HARDENING.md` #11). |
| ReDoS / pathological input | All user text is capped before any regex runs; number parsing is table-driven with bounded quantifiers; property-based tests assert totality, bounded output and idempotence (`HARDENING.md` #6). |
| Info leakage via errors | The catch-all handler logs the traceback **server-side** and returns an opaque `Internal server error` + `request_id` — never a class, message or stack. Error *responses* are rendered through an encoding-safe class, so hostile input (e.g. a lone surrogate) yields a clean `422` rather than a client-triggered `500`. |
| Rate-limit state growth | The limiter's hit table is **memory-bounded** (pruned in O(1)) — the DoS shield can't become the DoS vector (`HARDENING.md` #12). |
| Crash consistency | SQLite **WAL mode** + `busy_timeout` — power loss mid-write cannot corrupt the store. |
| Misconfiguration at boot | In production, placeholder secrets, an unset companion secret, or a missing Argon2 backend stop the boot (fail closed) rather than serving degraded. |

## Privacy guarantees

* **Progressive enhancement** — every feature works anonymously; accounts are opt-in.
* **Data portability** — `GET /api/auth/export` returns everything the account holds, in one JSON.
* **Right to erasure** — `DELETE /api/auth/account` removes the user, all sessions
  (FK cascade), owned profiles, uploads and tracker rows.
* AI is local-only: **nothing is sent to any external model or API, ever** (`ai/README.md`).

## What green tests do and don't mean

The suite (472 tests) proves **consistency with the rules we wrote down**. It
cannot prove the rules are complete, because the tests were written by the same
authors as the code: assumptions we never questioned are assumptions we never
tested. Two of the most recent real defects — a lone surrogate turning a request
into a `500`, and a spoofable `X-Forwarded-For` giving unlimited rate-limit
buckets — were found by the property-based/adversarial suite, not by review of
passing tests.

Stronger signals, in increasing order of value: property-based tests over real
invariants (**present**), parse/encode round-trips and fuzzing (**present**),
third-party scanners in CI (**present**) — and, so the gates themselves cannot
rot into decoration, `tests/test_ci_config.py` parses the workflow, runs its
commands and asserts that demoting or mis-wiring a gate breaks the build — then
independent human review, and a penetration test against a deployed instance
(**both still on the roadmap**).

## Reporting a vulnerability

Open a private security advisory on the repository (or email the maintainer).
Please do not file public issues for exploitable findings.

## Hardening roadmap (free, incremental)

1. Independent third-party review of the auth/session and upload paths.
2. TOTP second factor + step-up re-auth for destructive actions.
3. Postgres-backed deployments inherit the same contract (`docs/deploy/DEPLOYMENT.md`).
4. Fill/embed a real corpus for the local AI layer once a model host is allowlisted.
