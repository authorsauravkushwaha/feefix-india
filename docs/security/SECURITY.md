# FeeFix Security Model

FeeFix handles what students type about themselves — income, community, marks.
This document is the threat model and how the codebase answers it, mapped to
the **CIA triad** (Confidentiality · Integrity · Availability).

## Confidentiality — who can see what

| Threat | Control |
|---|---|
| Password theft from the database | **PBKDF2-HMAC-SHA256, 600,000 iterations, 16-byte per-user salt** (stdlib `hashlib` — OWASP parameters). DB contains `pbkdf2$600000$<salt>$<digest>`; the test suite literally asserts the plaintext never appears in the DB bytes. |
| Session-token theft from the database | Tokens are 256-bit random (`secrets.token_urlsafe`). **Only the SHA-256 hash is stored** — a leaked table yields nothing replayable. |
| User enumeration (does an account exist?) | Register/login return **uniform, identical errors**; login always runs the KDF even for unknown emails, so response *time* leaks nothing either. |
| Cross-origin snooping | SPA + API share one origin; **CORS is closed by default** (`FEEFIX_CORS_ORIGINS` opt-in only). |
| Response intermediaries caching data | `Cache-Control: no-store` on every `/api/*` response. |
| Cross-account reads | Account-owned sessions require the owner's bearer token — enforced server-side (`_authorize_session`) on profile, tracker, match and ML endpoints. Anonymous sessions remain usable by random-URL knowledge only. |
| Token replay in transit | HSTS when TLS terminates in front (`Strict-Transport-Security` behind `https`/`x-forwarded-proto: https`). |

## Integrity — who can change what

| Threat | Control |
|---|---|
| XSS injection | Strict **Content-Security-Policy** (`script-src 'self'` — no remote code, no inline scripts), the SPA escapes every interpolated value by design, `X-Content-Type-Options: nosniff`. |
| Clickjacking | `frame-ancestors` CSP directive (self + preview hosts only). |
| SQL injection | **Impossible by construction** — every statement in `backend/services/db.py`-backed stores is parameterized; no string-built SQL exists in the codebase. |
| Unauthorized state changes | Append-only **audit log** records register / login / session-bind / delete; foreign keys are engine-enforced (`PRAGMA foreign_keys=ON`). |
| Schema drift | Additive, versioned migrations via `PRAGMA user_version`. |
| Tamper-prone roll-your-own tokens | We don't mint JWTs — **opaque, server-side, revocable** sessions only. Logout and account deletion revoke instantly. |

## Availability — keeping the service up

| Threat | Control |
|---|---|
| Credential brute-force | **Sliding-window rate limit**: 10 auth attempts / 5 min per IP+account → HTTP 429. |
| Request floods | Global limit 1000 req/min per IP on `/api/*`. |
| Slow loris / giant payloads | FastAPI request parsing limits; quiet 500 shield (`Internal error: <Class>` — never a stack trace). |
| Crash consistency | SQLite **WAL mode** + `busy_timeout` — power loss mid-write cannot corrupt the store. |

## Privacy guarantees

* **Progressive enhancement** — every feature works anonymously; accounts are opt-in.
* **Data portability** — `GET /api/auth/export` returns everything the account holds, in one JSON.
* **Right to erasure** — `DELETE /api/auth/account` removes the user, all sessions
  (FK cascade), owned profiles and tracker rows.
* AI is local-only: **nothing is sent to any external model or API, ever** (`ai/README.md`).

## Reporting a vulnerability

Open a private security advisory on the repository (or email the maintainer).
Please do not file public issues for exploitable findings.

## Hardening roadmap (free, incremental)

1. Argon2id when a native-free wheel is viable in the deployment environment.
2. Optional TOTP second factor.
3. Postgres-backed deployments inherit the same contract (`docs/deploy/DEPLOYMENT.md`).
