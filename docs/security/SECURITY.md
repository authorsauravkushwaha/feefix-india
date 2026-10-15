# FeeFix Security Model

FeeFix handles what students type about themselves — income, community, marks,
disability status. Some of that is more sensitive than a password. This document
is the **threat model** and how the codebase answers it, mapped to the CIA triad.

> **For what was actually exploitable and how it was fixed**, with measured
> evidence, see **[HARDENING.md](HARDENING.md)**. That is the record; this is the
> model.
>
> For reporting a vulnerability, see the root **[SECURITY.md](../../SECURITY.md)**.

Every control below has a test in
[`tests/test_security.py`](../../tests/test_security.py) named after the attack
it prevents. A control without a test is a claim, not a control.

---

## Who is the attacker?

FeeFix is a public web service handling data about minors and marginalised
groups, which shapes the threat model in ways a generic checklist misses:

| Actor | Capability | What they want | Primary defence |
|---|---|---|---|
| **Unauthenticated internet** | Any request, any volume, no cost | Enumerate accounts, brute-force credentials, exhaust resources | Rate limiting, uniform errors, hard input ceilings |
| **Authenticated student** | A valid token, one account | Read *another* student's profile, income or status | **Authorisation on every session-scoped handler** |
| **Malicious dataset contributor** | A pull request to `data/schemes/*.json` | Execute script in every student's browser | URL scheme allow-list at the sink, CSP |
| **On-path attacker** (public Wi-Fi) | Read and modify traffic | Steal a session token, replay a mutation | TLS + HSTS + certificate pinning (Android), anti-replay nonces |
| **Someone with database read access** | The whole SQLite file | Log in as anyone, read live OTP codes | Hashed passwords, digested tokens, peppered OTP HMACs |
| **Someone with a stolen device / shoulder-surfing** | Physical access to a logged-in phone | Read the student's data from the app switcher | `FLAG_SECURE`, tokens in Keystore-backed storage |
| **Compromised dependency or CI** | Arbitrary code in the build | Exfiltrate secrets, backdoor a release | `pip-audit --strict`, secret scanning incl. history, non-root container |

The **second row is the one this codebase got wrong first**, and it is the most
important thing in this document: *authenticating a request is not the same as
deciding whether that request is allowed.* See
[HARDENING §13](HARDENING.md#13-authentication--authorisation--critical-fixed).

---

## Confidentiality — who can see what

| Threat | Control |
|---|---|
| Password theft from the database | **PBKDF2-HMAC-SHA256, 600 000 iterations, 16-byte per-user salt** (stdlib `hashlib`, OWASP parameters). Stored as `pbkdf2$600000$<salt>$<digest>`. The iteration count read back from a hash row is **bounded**, so a tampered row cannot turn one login into an unbounded CPU burn. |
| Session-token theft from the database | 256-bit random (`secrets.token_urlsafe(32)`). **Only the SHA-256 digest is stored** — a leaked table yields nothing replayable. Tested by asserting the raw token appears nowhere in the DB bytes. |
| **Live OTP code disclosure** | The single most serious bug found. Codes are stored as an **HMAC with a pepper**, and the response echo requires a non-production environment *and* `FEEFIX_DEV_OTP_ECHO=1`. A configured-but-failing SMTP host returns 422 and **deletes the challenge** rather than echoing the code. See [HARDENING §4](HARDENING.md#4-secret-key-leaks--critical-fixed). |
| Account enumeration | Register, login and OTP-request return **uniform, identical responses**. Login always runs the KDF, even for an unknown email, so response *time* is not an oracle (asserted: known/unknown ratio < 3×). |
| Cross-account reads | **`backend/services/authz.py` decides, on every session-scoped handler.** Account-owned sessions require the owner's bearer token; a stranger gets **403**. Anonymous sessions remain usable by knowledge of a random URL only — that is the product's privacy-by-design promise, and it is tested. |
| Session hijack by rebinding | Ownership is **write-once**. `link-session` on an already-owned session is refused and audited as `session.claim_refused`. Authenticated writes **stamp** ownership, so a signed-in student's data never looks anonymous and claimable. |
| Chat conversation resumption | `chat_id` is 128-bit and owner-bound. A different principal presenting the same id gets a **new conversation**, not a 403 — an error there would confirm the id exists. |
| Secrets in the repository | `scripts/secret_scan.py` runs in CI on the tree **and the full history** (catching a secret deleted in a later commit). `.gitignore` ignores `runtime/*` wholesale — the OTP pepper is a dotfile with no extension, which per-extension rules missed. `.dockerignore` excludes `.env` and `runtime/`, so credentials are never baked into image layers. |
| Clipboard persistence | Sensitive copies use the async Clipboard API with a **30 s TTL**, then a placeholder is written back. OTP paste is sanitised to digits and the user is **told** when non-digits were dropped. |
| Cross-origin snooping | SPA and API share one origin; **CORS is closed by default**, opt-in via `FEEFIX_CORS_ORIGINS`. A wildcard origin is refused outright and cannot be combined with credentials. |
| Intermediary caching | `Cache-Control: no-store` on every `/api/*` response, plus `Cross-Origin-Resource-Policy: same-origin`. |
| Data visible in the app switcher | The Android home screen sets **`FLAG_SECURE`** — a student's income, community and disability status does not appear in the recent-apps carousel or in screenshots. |
| Token in transit | **HTTPS-only, enforced in code** on the Android client (not left to the manifest), HSTS behind TLS, and certificate-pinning hooks shipped in the client. |

---

## Integrity — who can change what

| Threat | Control |
|---|---|
| XSS via injected markup | Strict **CSP**: `script-src 'self'`, no `unsafe-inline`, no `unsafe-eval`, `object-src 'none'`, `base-uri 'self'`. `X-Content-Type-Options: nosniff`. |
| **XSS via `javascript:` URL** | `esc()` is correct for text and **wrong for a URL context** — `javascript:alert(1)` contains no character it escapes. Every URL sink goes through `safeUrl()`, a scheme allow-list. This was reachable through a community dataset contribution. |
| DOM built from response bodies | No `innerHTML` sink receives a server value. The OTP hint is built with `createElement` + `textContent`, masked after 120 s, and never stored or copied. |
| Clickjacking | `frame-ancestors` in CSP plus `X-Frame-Options: SAMEORIGIN`. |
| SQL injection | **Impossible by construction** — every statement is parameterised; there is no string-built SQL and no document store. Proven by an eight-payload barrage that asserts the tables survive. |
| Path traversal | `/api/i18n/{lang}` is allow-listed to `[a-z]{2}(-[A-Z]{2})?`. Upload filenames are the **content digest**, so no client string reaches the filesystem; destinations are resolved and proven inside the root. |
| Request replay | Nonce + timestamp on every mutation, single-use per client IP, ±300 s window → **409** on violation. Clients sign automatically and retry once. `off` is **refused in production**. |
| **Client identity spoofing** | `X-Forwarded-For` is honoured only from a trusted peer (`FEEFIX_TRUSTED_PROXIES` / `FEEFIX_TRUST_PROXY_PEER`), and only `FEEFIX_PROXY_HOPS` entries from the right. Otherwise anyone could rotate a header and walk past every per-IP limit. |
| Trojan Source / log forgery | C0/C1 controls and Unicode bidi overrides are stripped from every input and from every audit-log write, so one event cannot read as two. |
| Unauthorised state changes | Append-only **audit log** records register, login, session-bind, claim refusals and account deletion. Foreign keys are engine-enforced (`PRAGMA foreign_keys=ON`). |
| Schema drift | Additive, versioned migrations via `PRAGMA user_version`. |
| Roll-your-own tokens | We mint **no JWTs** — opaque, server-side, revocable sessions only. Logout, password change and account deletion revoke instantly. |
| Code modified at runtime | The container's app tree is **root-owned and read-only to the runtime user**, so an RCE cannot persist by editing a handler. |

---

## Availability — keeping the service up

| Threat | Control |
|---|---|
| Credential brute-force | 8 auth attempts / 5 min per (IP, bucket) **plus** 32 / 5 min per IP that ignores the identifier — so varying the email address does not yield a fresh budget. 429 with `Retry-After`. |
| **KDF CPU exhaustion** | 20 password hashes / min / IP, charged separately from the auth limiter. PBKDF2 at 600 k is ~200 ms of synchronous CPU; four requests per second saturates a core. |
| Request floods | 600 req/min/IP across `/api/*`. |
| **Rate-limiter memory exhaustion** | The bucket map is capped at 50 000 and evicted **on the insertion path**. A timer-driven sweep is not sufficient — a one-second burst reached 120 011 buckets before it ran. |
| OTP destination flooding | 5 / hour keyed on the **recipient**, so rotating source IPs does not help. Protects people who never used FeeFix, and protects us from paying for it. |
| Giant payloads | Body ≤256 KB (**413**), headers ≤16 KB, query ≤8 KB, path ≤2048 (**414**). A 40 MB message used to return 200 in 3 008 ms. |
| Chunked requests | **411 on `/api/*`** — a chunked body declares no length, so the ceiling cannot be checked up front. No FeeFix client uses one. |
| **ReDoS** | The shipped email pattern was quadratic (718 ms on a 20 KB string, 12 222 ms on 80 KB) on an unauthenticated endpoint. Replaced with non-overlapping character classes: **≤0.013 ms on 80 KB**. Eight attack shapes are tested for flatness, not just for correctness. |
| Slowloris / stalled connections | uvicorn `--limit-concurrency 200 --limit-max-requests 10000 --timeout-keep-alive 5`. The Android client sets a **call timeout** — OkHttp's default is infinite, so a stalled response previously hung the coroutine forever. |
| Chat session exhaustion | `chat_id` is client-chosen, so an unbounded dict keyed on it is a DoS. Bounded LRU at 5 000 with a lock. |
| Replay-nonce exhaustion | 200 000 nonces **per IP**, TTL-bounded. Flooding fills only the attacker's own bucket. |
| Cross-site tracing | **TRACE returns 405** — it reflects headers, including `Authorization`, into the response body. |
| Crash consistency | SQLite **WAL mode** + `busy_timeout` — power loss mid-write cannot corrupt the store. Audit writes are best-effort so a full database cannot become an availability incident on the request path. |
| Unbounded responses (client) | The Android client caps reads at 2 MB and refuses cross-host redirects, so a hostile intermediary cannot make the app allocate without limit or replay a token to a third party. |

---

## Privacy guarantees

* **Progressive enhancement** — every feature works anonymously; accounts are
  opt-in. The anonymous→linked flow is tested, because the authorisation changes
  could easily have broken it.
* **Data portability** — `GET /api/auth/export` returns everything the account
  holds, in one JSON document.
* **Right to erasure** — `DELETE /api/auth/account` removes the user, all
  sessions (FK cascade), owned profiles and tracker rows. The Android client
  clears local state in a `finally` block, so a failed network call cannot leave
  a live token behind.
* **Data minimisation** — audit logs store masked addresses. Error responses
  never echo a rejected value; a password submitted to a malformed form does not
  appear in the response body, a proxy log or the browser's network tab.
* **AI is local-only** — nothing is sent to any external model or API, ever
  (`ai/README.md`).
* **`FLAG_SECURE`** on screens showing eligibility data.

---

## Fail-closed by design

The single most important property of the configuration layer: **forgetting to
configure FeeFix must never relax its security.**

* `FEEFIX_ENV` unset → **`production`**. Not `development`, not a warning.
* `FEEFIX_DEV_OTP_ECHO` unset → no echo, even in development.
* `FEEFIX_ANTI_REPLAY` unset → **`enforce`**. `off` in production additionally
  requires `FEEFIX_I_ACCEPT_REPLAY_RISK=1` — a name chosen so it survives review.
* `FEEFIX_TRUSTED_PROXIES` unset → `X-Forwarded-For` is **ignored**.
* `load_secret` in production refuses a value shorter than the minimum rather
  than accepting it.
* `env_int` clamps to its bounds instead of crashing on a bad value — a typo
  cannot take the process down.
* An upload verifier that cannot determine the real type **rejects**.
* A chat id that cannot be attributed to a principal gets a **fresh**
  conversation rather than being trusted.

---

## Configuration

Every variable is optional. See [`.env.example`](../../.env.example) for the
annotated template and [`HARDENING.md`](HARDENING.md#configuration-reference)
for the full reference.

> **`FEEFIX_ENV=development` plus `FEEFIX_DEV_OTP_ECHO=1` enables the OTP code
> echo.** Never set either on a host that serves real users.

> **Prefer `FEEFIX_TRUST_PROXY_PEER=1` over `FEEFIX_TRUSTED_PROXIES=0.0.0.0/0`.**
> The wildcard is functionally correct behind a platform proxy and catastrophic
> if copy-pasted into a directly-exposed deployment. The named flag makes the
> assumption auditable.

---

## Hardening roadmap

Known gaps, none currently exploitable. Full list with rationale in
[HARDENING.md](HARDENING.md#residual-risk--roadmap).

1. **Argon2id** when a native-free wheel is viable in the deployment environment.
2. **Optional TOTP second factor** — client binding mitigates token theft; a
   second factor mitigates credential theft.
3. **Wire the upload endpoint** through `uploads.py` (tested, currently unused).
4. **Remove `style-src 'unsafe-inline'`** once the 41 inline style attributes
   become classes.
5. **Populate Android certificate pins** with two pins (primary + backup) before
   release.
6. Postgres-backed deployments inherit the same contract
   (`docs/deploy/DEPLOYMENT.md`).

---

## Reporting a vulnerability

See **[SECURITY.md](../../SECURITY.md)** at the repository root. Please do not
file public issues for exploitable findings.
