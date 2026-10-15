# FeeFix Security Hardening — Findings & Fixes

A complete record of the October 2026 security pass: what was actually
exploitable, what was changed, and how to prove the change holds.

**Read this if you are about to modify authentication, authorisation, input
handling, rate limiting, or deployment configuration.** Every control here has a
test in [`tests/test_security.py`](../../tests/test_security.py) named after the
attack it prevents. Removing a control without removing its test fails CI; the
test name tells you what you just reintroduced.

```
pytest tests/test_security.py -v      # 155 security tests
pytest -q                              # full suite, 323 tests
```

---

## Summary

| # | Attack class | Was it real? | Severity | Fixed in |
|---|---|---|---|---|
| 1 | Replay attack | **Yes** — no nonce, no timestamp, no idempotency key anywhere | High | `anti_replay.py`, `request_shield.py`, `security.js`, `FeeFixApi.kt` |
| 2 | Clipboard attack | **Yes** — GitHub token left in the paste buffer, OTP paste unsanitised | High | `security.js` (clipboard API), `gh-handoff.js`, `auth-gate.js` |
| 3 | SQL / NoSQL injection | No — every statement parameterised; no document store exists | — | `test_security.py::TestInjection` (proof, not fix) |
| 4 | Secret key leaks | **Yes, CRITICAL** — live OTP code returned in the HTTP response body | Critical | `otp.py::request_code`, `auth-gate.js` |
| 5 | Long-password DoS | **Partly** — length was not the vector; *rate* was | Medium | `input_guard.py`, `auth.py`, `ratelimit.guard_kdf` |
| 6 | ReDoS | **Yes** — quadratic email regex, 718 ms on a 20 KB string | High | `input_guard.py`, `security.py` |
| 7 | Server-side template injection | No — no template engine in the codebase | — | `test_security.py` (proof) |
| 8 | Error handling / information leakage | **Yes** — rejected values echoed, internals in messages | Medium | `main.py`, `security.py::safe_error` |
| 9 | File upload security | Latent — no upload endpoint yet, no verification layer existed | — | `uploads.py` (defence ahead of the feature) |
| 10 | Secret management | **Yes** — `.gitignore` missed the OTP pepper, `.dockerignore` missed `.env` | High | `.gitignore`, `.dockerignore`, `scripts/secret_scan.py` |
| 11 | Input validation | **Yes** — no length bounds on any field, no shape checks | High | `input_guard.py`, `schemas.py`, `request_shield.py` |
| 12 | Rate limiting | **Yes** — unbounded bucket map, bypassable key, no KDF budget | High | `ratelimit.py`, `security.py::LIMITS` |
| 13 | Authentication ≠ authorisation | **Yes, CRITICAL** — IDOR on 6 endpoints + session-hijack via rebinding | Critical | `authz.py`, `routes.py`, `sqlite_store.py`, `chat.py` |
| 14 | XSS (`javascript:` URL) | **Yes** — reachable via a community dataset contribution | High | `app.js::safeUrl`, `security.js::esc` |
| 15 | Client identity spoofing | **Yes** — `X-Forwarded-For` trusted unconditionally | High | `security.py::client_ip` |
| 16 | Deployment config | **Yes** — `render.yaml` did not parse; no non-root user | Blocking | `render.yaml`, `Dockerfile`, `.dockerignore` |

---

## 1. Replay attack

**Before.** Mutating requests carried no nonce, no timestamp and no idempotency
key. A request captured anywhere in the path — a compromised proxy, a logging
middleware, a browser extension, a misconfigured CDN — could be replayed
indefinitely. `POST /api/auth/logout`, `DELETE /api/auth/account` and
`PUT /api/students/{sid}/profile` were all replayable.

**Now.** `backend/services/anti_replay.py` requires, on every non-idempotent
request:

| Header | Rule |
|---|---|
| `X-FeeFix-Nonce` | ≥128 bits, base64url or hex, ≤64 chars, **single use per client IP** |
| `X-FeeFix-Ts` | Unix seconds, within ±300 s |

Violations return **409 Conflict**. Nonces are stored per-IP in an
`OrderedDict` with a hard ceiling (`REPLAY_MAX_NONCES = 200 000`) and a TTL
longer than the window (`660 s`), so the defence is not itself an
exhaustion vector and flooding can only fill the attacker's own bucket.

**Modes.** `FEEFIX_ANTI_REPLAY` = `enforce` (default) | `optional` | `off`.
`off` is **refused in production** unless `FEEFIX_I_ACCEPT_REPLAY_RISK=1` is
also set — a variable name chosen so it survives code review and cannot be set
by accident.

**Clients.** `web/frontend/security.js` exposes `FFSec.replayHeaders()` and
`FFSec.headers(method)`; `api()` in `app.js` and `auth-gate.js` sign every
mutation and **retry once on 409** (never on 401/403, which must not be
retried). `mobile/android/FeeFixApi.kt` does the same with `SecureRandom`.

**Why `secrets.token_urlsafe` and not hex-only.** An early validator accepted
hex only. `token_urlsafe` emits base64url, so *every legitimate nonce was
rejected* and every mutation returned 409. A validator must accept what the
generator emits — the regex is `^[A-Za-z0-9_-]{16,64}$`.

---

## 2. Clipboard attack

Three distinct clipboard problems, all client-side:

| Vector | Before | Now |
|---|---|---|
| **Credential persistence** | Copying the GitHub handoff token used `document.execCommand('copy')`, leaving the token in the system paste buffer indefinitely | `FFSec.clipboard.copy(text, {sensitive: true, ttlMs: 30000})` uses the **async Clipboard API** and writes a placeholder back after 30 s |
| **Paste injection** | OTP paste took `clipboardData.getData('text')` verbatim into a hidden input — anything pasted, including markup and bidi overrides, was accepted | `FFSec.clipboard.sanitizePaste(raw, "otp")` strips to `\d`, caps length, and **warns the user when non-digits were dropped** so a silent truncation never looks like a wrong code |
| **Screen-scraping the buffer** | Any page in the origin could read what the user last copied | Reads are never performed on sensitive values; the copy TTL bounds exposure |

`FFSec.clearSensitiveInputs(root)` wipes password and OTP inputs on logout and
after a successful verify, so a value does not survive in the DOM (and in a
crash report, or an extension's `document.body` read) after it has been used.

**Android.** `FeeFixApi.verifyOtp` filters to digits and caps at 8 before the
value reaches the wire, and `logout()` / `deleteAccount()` clear the local
token store in a `finally` block — so a failed network call cannot leave a live
token behind.

---

## 3. SQL / NoSQL injection — *not exploitable, proven*

There is no document store in this codebase; the only datastore is SQLite
(`FEEFIX_STORE=sqlite`) or an in-memory dict. Every statement is parameterised
— there is no string-built SQL to find.

`tests/test_security.py::TestInjection` runs eight payloads
(`' OR '1'='1`, `'; DROP TABLE users; --`, `' UNION SELECT password_hash FROM
users--`, `'; ATTACH DATABASE …`) against login, scheme lookup, session-scoped
reads, and search, then asserts the `users` table still exists and a real record
is still retrievable. This is a **regression proof**, not a fix — it exists so
that the first person who reaches for an f-string in a query fails a test.

`/api/i18n/{lang}` was a genuine **path traversal** candidate (the language code
became part of a filesystem path). It is now allow-listed to `[a-z]{2}(-[A-Z]{2})?`
and traversal payloads return 404.

---

## 4. Secret key leaks — *CRITICAL, fixed*

**The bug.** `POST /api/auth/otp/request` returned the live one-time code in the
response body whenever delivery reported `via == "dev"`. And `_deliver_email`
returned `"dev"` in **two** situations:

1. SMTP was not configured — a development convenience, intended.
2. **SMTP was configured and the send threw** — a production outage path,
   never intended.

So a production deployment whose SMTP host was briefly unreachable echoed every
user's OTP to the caller. That is remote account takeover of any address on the
platform, by anyone, with no authentication.

**The fix — three independent layers:**

1. **Capability is decided from configuration before a code is generated.**
   `_delivery_capability(channel)` returns `live` | `dev` | `unavailable`. In
   production an unconfigured channel is `unavailable`; it is `dev` only when
   `security.unsafe_features_allowed()`.
2. **The echo requires two switches**, both fail-closed:
   `environment() in (development, test)` **and** `FEEFIX_DEV_OTP_ECHO=1`.
   Production returns a generic 422 even with the flag set.
3. **A failed delivery deletes the challenge** (`_delete_challenge`). A code
   nobody received must not sit in the database being guessable, and must not
   burn the recipient's resend cooldown.

**Also fixed:** the code is stored as an **HMAC-SHA256 with a pepper**, not in
plaintext, so a database leak does not yield live codes. The pepper is loaded
through `security.load_secret`, which creates `runtime/.otp_pepper` at mode
**0600** and refuses a value shorter than 32 bytes in production.

**Client side.** `auth-gate.js` had two `msg.innerHTML = …dev_code…` sinks —
inner HTML built from a response body. Both are gone; `renderCodeHint()` builds
DOM nodes with `document.createElement` + `textContent`, strips to `\d{0,8}`,
**masks to `••••••` after 120 s**, and never stores or copies the value.

`/api/auth/methods` reports `dev_otp_echo: true|false` so an operator can see at
a glance whether the dangerous path is live — but it only ever reports `true`
when it actually is.

---

## 5. Long-password DoS — *the hypothesis was wrong, the control is still right*

**What was measured.** PBKDF2-HMAC-SHA256 cost is *iteration*-bound, not
length-bound. At 600 000 iterations:

| Password length | Hash time |
|---|---|
| 64 chars | ≈196 ms |
| 10 000 000 chars | ≈242 ms |

A 10 MB password costs 23 % more than a 64-character one. **"Long password DoS"
as usually described does not exist against PBKDF2.** Do not spend effort on it.

**The real risk is `KDF cost × request rate`.** 200 ms of synchronous CPU per
call means four requests per second saturates a core. The fix is a separate,
much tighter budget for KDF-bearing routes:

```python
KDF_LIMIT = (LIMITS.KDF_RPM, 60)      # 20 password hashes / min / IP
```

charged by `ratelimit.guard_kdf(client_ip)` on register, login and
change-password — independent of the general auth limiter, so an attacker who
stays inside the auth rules still cannot grind the CPU.

**Length ceilings remain, as defence in depth** (`MAX_PASSWORD_LEN = 128`,
enforced at the route, the schema, *and* inside `auth.hash_password` so an
internal caller cannot bypass it). A 1 MB password now returns 413/422 without
ever reaching the KDF; a 1 KB one returns 422 pre-hash.

---

## 6. ReDoS

**Before.** `backend/services/auth.py` used:

```python
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
```

Because `.` matches inside `[^@\s]`, the two quantifiers overlap and a *failing*
input makes the engine try every possible split. Measured on the shipped code:

| Input length | Time |
|---|---|
| 2 003 chars | 7.65 ms |
| 20 003 chars | 718 ms |
| 80 003 chars | **12 222 ms** |

Quadratic, and reachable from an **unauthenticated** endpoint: 100 requests per
minute with 80 KB emails keeps a worker busy 20 minutes per minute of wall
clock.

**Lesson: always probe with ≥20 KB payloads.** A 100-character test string
shows nothing, and "no catastrophic backtracking" is a different claim from "no
quadratic blowup".

**Now.** `input_guard.valid_email` rejects on length first (254 / 64 / 253 / 63
per RFC 5321), then matches a pattern with **non-overlapping character classes**
and no nested quantifiers:

| Input length | Time |
|---|---|
| 80 003 chars | **≤0.013 ms** |

That is a 1.1 M× improvement and, more importantly, **flat** — the test suite
asserts the 500-char and 20 000-char cases differ by less than 200× (linear
would be 40×; the vulnerable pattern was ~1600×).

Eight attack shapes are parameterised (overlapping dots, many hyphens, many
`@`, no TLD, trailing space, alternating, unicode homoglyph, nested groups), and
`valid_phone`, `valid_session_id`, `valid_scheme_id`, `valid_nonce`,
`safe_filename` and `valid_bearer_token` are each asserted to finish a 100 KB
hostile input in under 50 ms.

`otp.E164_RE` was checked separately and is genuinely safe — digit classes do
not overlap.

---

## 7. Server-side template injection — *not applicable*

There is no template engine. No Jinja2, Mako, or `str.format` on user input
reaches an evaluator. The one HTML document built in Python
(`backend/api/routes.py::_HANDOFF_HTML`) composes its dynamic part with
`json.dumps`, which is an escaping function, not a template.

The related risk — **client-side** injection — was real and is covered in §14.

---

## 8. Error handling & information leakage

| Leak | Before | Now |
|---|---|---|
| **Rejected value echoed** | Pydantic's default 422 handler returns `input` — the offending value. For a password field that reflects the password into the response body, every proxy log and the browser network tab | Custom handler returns `{loc, msg, type}` only. Tested with a 21-char password: absent from `r.text` |
| **Exception class names** | `Internal error: <Class>` in 500 responses | `security.safe_error()` returns a generic message; the class goes to the audit log only |
| **Stack traces** | Possible through unhandled exception propagation | Middleware shield; the test suite asserts no `Traceback`, `File "`, `sqlite3.`, `OperationalError` or `KeyError` appears in any error body |
| **Server banner** | Uvicorn's `Server:` header advertises software and version | `--no-server-header` in the Dockerfile; header stripped in `main.py`. Asserted absent |
| **Interactive docs in production** | `/docs` and `/openapi.json` published the full API surface | 404 when `is_production()` |
| **Health endpoint** | — | Exposes liveness and counts only. Test asserts no env-var name, store path or `runtime/` string appears |
| **Log forgery** | An injected newline makes one audit event read as two | `scrub_text()` strips C0/C1 before the audit write |
| **Audit log contents** | OTP requests logged the full address | Masked at the call site (`audit-me@example.com` never appears); test asserts it |

`/api/i18n/xx` returns 404 rather than an error naming the directory it looked
in. A 3 KB path returns 414, not a 500 with the path in it.

---

## 9. File upload security

FeeFix has **no upload endpoint yet** — students will eventually attach income
certificates and mark sheets, so the verification layer exists ahead of the
feature. `backend/services/uploads.py` is what any future endpoint must call;
it is fully tested so it cannot be written wrong later.

Checks, cheapest first (so rejection cost cannot be amplified):

1. **Declared length** vs `MAX_UPLOAD_BYTES` (5 MB) — before reading the buffer.
2. **Magic-byte sniffing** — the declared `Content-Type` is treated as a claim
   to be *verified against*, never trusted.
3. **MIME mismatch** → reject.
4. **Forbidden content markers** → reject. This one had a subtle bug worth
   recording: scanning for the 2-byte `MZ` marker *anywhere* in the file
   false-rejected legitimate PDFs, because a 2-byte pattern occurs ~76 times by
   chance in 5 MB of compressed data. **Short prefixes are matched at offset 0
   only; markers of ≥3 bytes are matched anywhere.**
5. **Image dimension parse** → reject absurd widths/heights (decompression bomb).
6. **Extension allow-list** — `.php`, `.jsp`, `.aspx`, `.html`, `.svg`, `.exe`,
   `.sh` refused. **SVG is excluded from the image policy**: it is XML and can
   carry `<script>`.
7. **Stored name is the SHA-256 digest** of the content, plus an allow-listed
   extension. No part of the client filename reaches the filesystem — so
   traversal, NUL bytes and Windows device names (`con`) are structurally
   impossible rather than merely filtered.
8. **`safe_destination()`** resolves the path and asserts it is strictly inside
   the resolved root, defeating a pre-planted symlink. Existing symlinks at the
   destination are refused.
9. **Written 0600 via atomic rename**, so a partial write can never be observed
   or served as complete.

Rejection reasons are **machine-readable internally, generic externally**.
Telling an attacker "the magic bytes said PHP but you claimed PNG" hands them
the exact feedback loop needed to iterate toward a payload that passes.

---

## 10. Secret management

Four separate ways a secret could have left the repository:

| Path | Before | Now |
|---|---|---|
| **`.gitignore`** | Listed `runtime/*.db`, `runtime/*.json`, `*.env`. The OTP pepper lives at `runtime/.otp_pepper` — a **dotfile with no extension**, matching none of those. The first `git add -A` would have committed it | `runtime/*` + `!runtime/.gitkeep`. Fail-closed: everything in the runtime directory is ignored unless explicitly allow-listed |
| **`.dockerignore`** | Missing `.env`, `runtime/`, `secrets/`, key material. Credentials would have been **baked into image layers** — pushed to a registry, and permanent even if a later layer deletes them | All excluded |
| **`render.yaml`** | Unparseable (see §16), and secrets had committed `value:` fields | All 11 secrets use `sync: false`, so Render prompts for them and they never appear in the blueprint |
| **Secrets in code** | No scanner | `scripts/secret_scan.py` in CI, on both the tree and the **full history** |

### `scripts/secret_scan.py`

~380 lines, stdlib only. Exit `0` clean / `1` findings / `2` scanner error.

* **11 content patterns** (AWS, GitHub, Slack, Stripe, Google, Postgres/MySQL
  URLs, PEM blocks, generic high-entropy assignments, …).
* **Forbidden-tracked-file policy** — `.env`, `runtime/*`,
  `*.pem|key|p12|pfx|keystore|jks`, `secrets/*` may not be committed at all,
  regardless of content. `runtime/.gitkeep` is allow-listed.
* **`.gitignore` coverage verified by running `git check-ignore`**, not by
  reading the file — text-reading is not authoritative, and the pepper bug above
  is exactly the kind of mistake reading produces.
* **`--history`** walks `rev-list` + `ls-tree` over 200 commits and catches a
  secret that was **deleted in a later commit** — invisible to a working-tree
  scan, permanently cloneable. It performs two checks:
  1. a **forbidden path** committed at any point (`.env` removed in a follow-up);
  2. a **credential inside an ordinary file that was later edited out** — an AWS
     key pasted into `backend/config.py`, committed, then removed. The file is
     clean at HEAD, so only its history is dirty.

  Check 2 is what makes `--history` worth its runtime, and it did not exist
  originally: the first version compared *filenames only*, so it could never see
  a credential that lived inside normal source. Cost is bounded by
  de-duplicating on **blob SHA** — history repeats the same blobs across
  hundreds of commits, so scanning unique blobs is a fraction of scanning unique
  (commit, file) pairs — plus skipping blobs identical to HEAD, which the
  working-tree scan already covers, and a `MAX_HISTORY_BLOBS` ceiling so a
  vendored-dependency commit cannot turn a CI gate into a multi-minute job.
* **`--json`** for machine consumption; an allow-list keyed on `path:line` with
  **mandatory reasons**, so an exemption is a documented decision.
* **Previews are redacted** (`{first3}…{last3}`) so the scanner cannot itself
  leak a secret into CI logs.

**Three scanner bugs found by self-testing — each would have made it worthless:**

1. The `{16,}` unbroken-token pre-filter was **tighter than the patterns it
   guards**. The longest unbroken run in a Postgres URL is the 15-character
   password; `-----BEGIN` is 10 characters. Both were silently skipped. Lowered
   to `{8,}`.
2. `.pem` was in `SKIP_SUFFIXES` as "binary". That is backwards — **PEM is text,
   and it is the most common home for a private key.** Removed.
3. The forbidden-path predicate was **duplicated inline in the history scan** and
   the two copies diverged. The tree scan exempted `runtime/.gitkeep`; the
   history scan did not, so `--history` raised a CRITICAL "history rewrite +
   credential rotation required" finding for a zero-byte placeholder — on every
   run. Extracted to one `is_forbidden_path()` used by both.

   Bug 3 is the most instructive. A gate that is wrong on every run gets
   disabled, and once `--history` is disabled the *real* finding it exists for —
   a key committed in 2024, deleted in 2025, still cloneable today — stops being
   caught at all. **Two copies of a security predicate will diverge**; the fix is
   one predicate, not two carefully-maintained ones. The same bug also produced
   a false positive on `.env.example`, the committed template, because
   `(^|/)\.env(\..+)?$` matches any `.env.*` suffix.

Bugs 1–3 all came from the same discipline: **self-test a scanner against
known-bad *and* known-good fixtures.** `tests/test_security.py::TestSecretManagement`
now asserts 4/4 dirty files caught, 0/3 clean files flagged, 17 forbidden paths
blocked, 10 legitimate paths allowed, every allow-list entry scoped to a path and
carrying a real reason — and, in
`test_scanner_history_catches_a_secret_deleted_in_a_later_commit`, builds a
throwaway Git repository containing a secret that is clean at HEAD and asserts
the history scan still finds it. A scanner that always passes is worse than no
scanner, because it produces confidence.

### Runtime secret loading

`security.load_secret(env_var, *, fallback_path, min_bytes)`:

* reads the environment first;
* otherwise creates a random secret at `fallback_path`, mode **0600**;
* **refuses a value shorter than `min_bytes` in production** (`SecretError`);
* never logs the value.

---

## 11. Input validation

There were no length bounds on any field. `backend/services/input_guard.py` is
now the single source of truth, and `backend/api/schemas.py` re-declares the
same bounds so FastAPI rejects before a handler runs.

| Control | Behaviour |
|---|---|
| **Request framing** | Body ≤256 KB (**413** over), headers ≤16 KB, query ≤8 KB, path ≤2048 (**414** over) |
| **Chunked requests** | **411 on `/api/*`.** A chunked body declares no length, so the ceiling cannot be checked up front. No FeeFix client uses one |
| **Identity fields** | email ≤254, local-part ≤64, domain ≤253, label ≤63, phone ≤32 (E.164), password 8–128, name ≤80, ids ≤64 |
| **User content** | chat message ≤2000, question ≤1000, search ≤200, lang ≤8 |
| **Collections** | ≤64 items — stops a "list of 10 million" body |
| **Invisible characters** | C0/C1 controls and Unicode bidi overrides (`U+202A–202E`, `U+2066–2069`, ZWSP, BOM, soft hyphen) stripped. **Trojan Source**: these make a string *display* as something other than its bytes, and they survive into logs |
| **Truncation order** | Normalise **then** truncate, so a strip cannot re-expose what was cut |
| **Filenames** | `safe_filename("../../etc/passwd")` → `passwd`; `a\x00.jpg` → `a.jpg`; `con` → `None`; `élan.pdf` → `elan.pdf` (ASCII-folded, not mangled to `lan.pdf`); 300 chars → 128 |
| **Phone normalisation** | `9876543210` → `+919876543210`; `+1 (415) 555-2671` → `+14155552671`; rejects `abc`, `+0912345678`, 19 digits |
| **Query parameters** | Unknown filter values are **dropped, not applied**; `k` is clamped to ≤15 |

A 40 MB `message` used to return **200 in 3 008 ms**. It now returns **413**.

---

## 12. Rate limiting

Four distinct failures:

**(a) Unbounded bucket map — memory-exhaustion DoS.** Buckets were never
removed. 5 000 requests left 5 008 live entries forever; 60 000 distinct keys
produced **120 011** buckets. A timer-driven sweep is *not* sufficient: a
one-second burst reaches the ceiling before it runs. **The ceiling must be
enforced on the insertion path** — `_bound_size()` evicts the oldest entries
synchronously. Now exactly **50 000** buckets regardless of key count.

**(b) Bypassable key.** The auth key was `(ip, "auth:" + email)`, so an attacker
varying the address got a fresh budget per attempt. Now `AUTH_PER_IP_LIMIT`
charges a per-IP budget that **ignores the identifier**: 80 login attempts with
80 different addresses engages 429.

**(c) No KDF budget.** See §5 — `guard_kdf`, 20/min/IP.

**(d) OTP destination flooding.** `guard_otp_destination` keys on the
**recipient**, not the sender, so rotating source IPs does not help. This
protects a person who has never used FeeFix from being SMS-bombed, and protects
us from paying for it. 5/hour/destination.

| Limiter | Budget | Window |
|---|---|---|
| Global (`/api/*`) | 600 req / IP | 60 s |
| Auth | 8 / (IP, bucket) | 300 s |
| Auth per IP | 32 / IP | 300 s |
| KDF | 20 / IP | 60 s |
| OTP destination | 5 / destination | 3600 s |
| OTP verify | 5 attempts / challenge | — |
| OTP resend | 40 s cooldown | — |

Every 429 carries a `Retry-After` header (asserted in tests). The existing
contract — `test_login_rate_limited` tolerating ≤10 non-429 attempts — is
preserved: `AUTH_ATTEMPTS = 8`.

---

## 13. Authentication ≠ authorisation — *CRITICAL, fixed*

This was the most serious finding in the pass, and the one the original
documentation claimed was already handled.

### 13a. IDOR on six endpoints

Endpoints accepted a `session_id` and acted on it with no ownership test. An
**unauthenticated** caller got **200** on:

* `GET  /api/students/{sid}/reminders`
* `POST /api/students/{sid}/reminders/dispatch`
* `POST /api/events`
* `POST /api/ask?session_id=…`
* `GET  /api/ml/rank/{sid}`
* `POST /api/chat` with a client-supplied `chat_id`

All now return **403**. `backend/services/authz.py` owns the decision;
`routes.py` calls it on every session-scoped handler.

**Status code choice matters.** An anonymous caller on an *owned* session gets
**403, not 401** — the SPA treats 401 as "your session ended" and logs the user
out, so 401 there would have been a self-inflicted denial of service for anyone
who bookmarked a shared link.

### 13b. Account takeover via session rebinding

`POST /api/auth/link-session` let **Mallory read Alice's profile and lock Alice
out of her own account**. Reproduced before the fix:

1. Alice signs in and saves a profile under session `S`.
2. Mallory signs in and calls `link-session` with `S`.
3. Mallory gets **200**, then `GET /api/students/S/profile` → Alice's data.
4. Alice, with a **valid token**, gets **403** on her own profile.

Two independent causes, both of which had to be fixed:

* **`bind_owner` used `ON CONFLICT DO UPDATE SET user_id`** — ownership was
  mutable, so binding was a *transfer*. Now **write-once**: an existing owner is
  never replaced, `bind_owner` returns `bool`, and a refusal is audited as
  `session.claim_refused`.
* **`save_profile` inserted `user_id = NULL` unconditionally.** So a signed-in
  student's own data looked *anonymous* to `owner_of`, and was therefore
  claimable by anyone. Now `save_profile(..., owner_id=)` stamps ownership on
  write.

**Stamping ownership in `bind_owner` alone is not enough.** Writes must stamp it
too, or every authenticated session still looks anonymous. Both
`tests/test_security.py::test_authenticated_write_establishes_ownership` and
`test_tracker_write_establishes_ownership_too` exist because the second path
(tracker rows without a profile row) was missed on the first attempt.

The **anonymous-then-sign-in flow still works** — use FeeFix without an account,
then link and keep your progress. That is the product's privacy-by-design
promise and it is tested.

### 13c. Chat conversation resumption

`chat_id` was the same IDOR shape one level up. Now:

* ids are **32-hex / 128-bit** (`uuid4().hex`), not the old 48-bit prefix;
* `_SESSIONS` is a bounded LRU (`_MAX_SESSIONS = 5 000`) with a lock — a
  client-chosen key in an unbounded dict was a memory-exhaustion DoS reachable
  without authentication (6 000 ids previously left 6 000 live sessions);
* each session carries `owner_id` / `owner_fp`;
* `resolve_chat_id()` gives a **different principal a new conversation** rather
  than a 403. Returning 403 would confirm the id exists and turn this into an
  enumeration oracle.

---

## 14. XSS via `javascript:` URL

`web/frontend/app.js` rendered a scheme's application URL straight into an
anchor:

```js
href="${esc(s.application.url)}"
```

`esc()` escapes `<`, `>`, `"`, `&`, `'`. **It does not neutralise a
`javascript:` URL** — that string contains none of those characters. A community
dataset contribution (this repository accepts them) could therefore execute
script in the origin of every student who opened the scheme drawer.

Fixed with `safeUrl(v, opts)` — a **scheme allow-list** (`http`, `https`,
`mailto`, `tel`, and relative paths) applied at the sink, plus
`rel="noopener noreferrer"` on every external anchor. `esc()` now delegates to
`FFSec.esc` so there is one escaping implementation, and the drawer gained a
`copyApplyUrl` button that routes through the sensitive-clipboard path (§2).

**The general rule: escaping is not validation.** `esc()` is correct for text
content and wrong for a URL context. Every sink needs a check appropriate to
*that* sink.

---

## 15. Client identity spoofing

`client_ip()` read `X-Forwarded-For` from any peer. Anyone could rotate that
header and walk past **every** per-IP limit in §12.

Now `X-Forwarded-For` is honoured only when the immediate peer is trusted:

* `FEEFIX_TRUSTED_PROXIES` — CIDR list, parsed once (`lru_cache`);
* `FEEFIX_PROXY_HOPS` — how many entries from the right to trust. `hops=1` takes
  the rightmost, so a client-forged value to the left of it is not believed.

**The footgun this avoids:** on Render the platform proxy is the only reachable
peer, so `FEEFIX_TRUSTED_PROXIES=0.0.0.0/0` is *functionally correct* — and
catastrophic if copy-pasted into a directly-exposed deployment.
`FEEFIX_TRUST_PROXY_PEER=1` exists so the assumption is **named and auditable**
instead of expressed as a wildcard. `render.yaml` sets the flag; the test suite
asserts the wildcard is never used.

Malformed or empty `X-Forwarded-For` falls back to the peer address.

---

## 16. Deployment configuration

**`render.yaml` did not parse.** A stray `J` and a swallowed newline had merged
`buildCommand` and `startCommand` onto line 8 — `mapping values are not allowed
here`. Every blueprint deploy was failing. This is why CI now asserts the file
parses, has non-empty commands, and contains no wildcard CORS.

Rewritten with:

* `healthCheckPath: /api/health`
* `FEEFIX_ENV=production`, `FEEFIX_STORE=sqlite`, `FEEFIX_DB` on the persistent disk
* `FEEFIX_TRUST_PROXY_PEER=1`, `FEEFIX_PROXY_HOPS=1`
* `FEEFIX_ANTI_REPLAY=enforce`, `FEEFIX_BIND_CLIENT=1`
* **all 11 secrets `sync: false`**

**`Dockerfile`:**

* non-root `feefix` user, uid/gid **10001**, `nologin`, `--no-create-home`
* `/app/runtime` created **0700** and chowned (excluded from the build context)
* the **app tree is root-owned 644/755** — the runtime user can read code but
  cannot modify it, so an RCE cannot persist by editing a handler
* `PYTHONDONTWRITEBYTECODE`, `PYTHONUNBUFFERED`, `PIP_NO_CACHE_DIR`
* `HEALTHCHECK --fail-critical` via `python -c` + `urllib` (no curl dependency)
* uvicorn `--limit-concurrency 200 --limit-max-requests 10000
  --timeout-keep-alive 5 --no-server-header` — the last two are slowloris
  mitigations and the banner suppression from §8

---

## Transport & headers

Applied to **every** response (`backend/services/secure_headers.py`):

```
Content-Security-Policy: default-src 'self'; script-src 'self';
  style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
  img-src 'self' data:; font-src 'self' data: https://fonts.gstatic.com;
  connect-src 'self'; manifest-src 'self'; worker-src 'self';
  object-src 'none'; frame-ancestors 'self' https://*.e2b.app;
  base-uri 'self'; form-action 'self'; upgrade-insecure-requests
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 0
X-Permitted-Cross-Domain-Policies: none
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(),
  usb=(), magnetometer=(), gyroscope=(), accelerometer=(), fullscreen=(self)
Cache-Control: no-store
```

* **`X-XSS-Protection: 0` is deliberate**, per OWASP: the legacy auditor is
  itself an attack surface and is ignored by every current browser.
* **`script-src 'self'`** with no `unsafe-inline` and no `unsafe-eval`.
  `style-src` keeps `'unsafe-inline'` because the SPA sets 41 inline style
  attributes; that is a considered trade, not an oversight — `style-src` is not
  a script-injection vector and the alternative is rewriting all of them.
* **HSTS is emitted only over TLS** (`x-forwarded-proto: https`), so it never
  pins a development host.
* **TRACE returns 405** — it reflects headers, including `Authorization`, into
  the response body (cross-site tracing).
* `/.well-known/security.txt` is served, giving researchers a contact path.
* `index.html` sets `<meta name="referrer">`, a `<noscript>` fallback to
  `/noscript.html`, and loads `security.js` **first** via `defer` — `defer`
  preserves document order, which is a hard guarantee rather than a race.

---

## Sessions & tokens

| Control | Value |
|---|---|
| Token entropy | 256 bits (`secrets.token_urlsafe(32)`) |
| Storage | **SHA-256 digest only** — a leaked table yields nothing replayable |
| Idle expiry | 30 days, rolling |
| **Absolute expiry** | **90 days** — a rolling window never expires for a token used monthly, which turns a stolen token into permanent access |
| Max sessions / user | 20, oldest evicted first |
| **Client binding** | `FEEFIX_BIND_CLIENT=1`: a token replayed from a different user agent is **revoked immediately**, including the legitimate session. Forced re-authentication beats silently sharing a session with an intruder |
| Password change | Revokes **every** session, and requires the current password |
| Weak passwords | Refused against a common-password list |
| **KDF iteration pinning** | `verify_password` bounds the iteration count read from the hash row — a tampered row claiming 10¹² rounds would otherwise turn one login into an unbounded CPU burn |
| Password hashing | PBKDF2-HMAC-SHA256, 600 000 iterations, 16-byte per-user salt, `compare_digest` |
| OTP | 6 digits, HMAC'd with a pepper, 300 s TTL, 5 attempts, single use |

---

## User enumeration

Register, login and OTP-request all return **uniform, identical responses**.
Login always runs the KDF, even for an unknown email, so response *time* is not
an oracle either — `test_login_timing_is_similar` asserts the known/unknown ratio
stays under 3× over three samples each.

`/api/auth/methods` reports capability, not account state.

---

## Confirmed safe — do not "fix" these

Audited and found sound. Recording them here so the next pass does not redo the
work:

* **SQL injection** — all parameterised, no NoSQL store (§3).
* **SSTI** — no template engine (§7).
* **Password crypto** — PBKDF2-SHA256 600 k + 16 B salt + `compare_digest`,
  OWASP parameters.
* **Session tokens** — 256-bit, stored as SHA-256 only.
* **OTP construction** — HMAC'd with a pepper, single-use, TTL and attempt caps.
* **AI** — local-only; nothing is sent to an external model or API, ever.

---

## Residual risk & roadmap

Known gaps, in priority order. None is currently exploitable; all should be
closed before the platform takes real user volume.

1. **Argon2id** when a wheel-free native build is viable in the deployment
   environment. PBKDF2 at 600 k is OWASP-acceptable but memory-hard KDFs are
   strictly better against GPU/ASIC attackers.
2. **TOTP second factor.** Client binding (§Sessions) mitigates token theft; a
   second factor mitigates credential theft.
3. **Upload endpoint wiring.** `uploads.py` is tested and unused — the first
   endpoint that accepts a file must call `verify()` / `store()` and nothing
   else.
4. **`style-src 'unsafe-inline'`.** Removable once the 41 inline style
   attributes become classes.
5. **Subresource Integrity** if any third-party script is ever added. There are
   none today, and CSP forbids them.
6. **Certificate pinning on Android** is implemented but ships with an empty pin
   list. Populate it with **two** pins (primary + backup) before release — a
   single pin that cannot be rotated turns a certificate renewal into an app
   that cannot reach its own backend.
7. **Dependency auditing.** `pip-audit --strict` runs in CI on every push. A
   finding fails the build; do not downgrade it to a warning.

---

## Configuration reference

Every variable is **optional** and **fail-closed** — an unset variable produces
the stricter behaviour. See [`.env.example`](../../.env.example) for the
annotated template.

### New in this pass

| Variable | Default | Purpose |
|---|---|---|
| `FEEFIX_ENV` | `production` | `production` \| `staging` \| `development` \| `test`. **Unset means production** |
| `FEEFIX_DEV_OTP_ECHO` | unset | Second switch for the OTP echo (§4). Requires a non-production env *and* this flag |
| `FEEFIX_BIND_CLIENT` | unset | Revoke a session token used from a different user agent |
| `FEEFIX_ANTI_REPLAY` | `enforce` | `enforce` \| `optional` \| `off`. `off` refused in production |
| `FEEFIX_I_ACCEPT_REPLAY_RISK` | unset | Required *in addition* to allow `off` in production |
| `FEEFIX_TRUSTED_PROXIES` | unset | CIDR list of peers whose `X-Forwarded-For` is honoured |
| `FEEFIX_TRUST_PROXY_PEER` | unset | Trust the immediate peer as a proxy. **Prefer this over a `0.0.0.0/0` CIDR** (§15) |
| `FEEFIX_PROXY_HOPS` | `1` | Entries to trust from the right of `X-Forwarded-For` |

### Pre-existing

`FEEFIX_CORS_ORIGINS` · `FEEFIX_CORS_CREDENTIALS` · `FEEFIX_STORE` ·
`FEEFIX_DB` · `FEEFIX_OTP_PEPPER` · `FEEFIX_BASE_URL` ·
`RENDER_EXTERNAL_HOSTNAME` · `OTP_SMTP_HOST|PORT|USER|PASS|FROM|TIMEOUT_S` ·
`OTP_TWILIO_SID|TOKEN|FROM` · `GITHUB_CLIENT_ID|SECRET`

> **`FEEFIX_ENV=development` enables the OTP echo** if `FEEFIX_DEV_OTP_ECHO=1`
> is also set. Never set either on a host that serves real users.

---

## Verification

```bash
# Full suite (323 tests)
PYTHONPATH=. .venv/bin/python -m pytest -q

# Security regression suite only (152 tests)
PYTHONPATH=. .venv/bin/python -m pytest tests/test_security.py -v

# Secret scan — working tree
python scripts/secret_scan.py

# Secret scan — full history (catches secrets deleted in a later commit)
python scripts/secret_scan.py --history

# Frontend syntax
for f in web/frontend/*.js; do node --check "$f"; done

# Deployment blueprint parses, no wildcard CORS
python -c "import yaml,pathlib; d=yaml.safe_load(pathlib.Path('render.yaml').read_text()); print(len(d['services'][0]['envVars']),'envVars')"
```

CI runs all of these (`.github/workflows/ci.yml`). The `test` job **depends on**
the `security` job, so a secret-scan or dependency-audit finding stops the build
before tests are even collected.
