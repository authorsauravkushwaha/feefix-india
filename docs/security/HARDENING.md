# FeeFix Threat Hardening Map

Every attack class below is answered by **concrete, tested code** in this
repository — not just policy. Each row names the control, the file that
implements it, and the suite that proves it.

Two rules this document follows, because the alternative is security theatre:

1. **If it isn't tested, it isn't a control.** Every claim links to a test.
2. **Say what a control does *not* do.** Controls presented as stronger than
   they are create risk (they stop people from doing the thing that would
   actually help). Where a measure is cosmetic, hardening-by-default, or only
   a speed bump, it says so in the row.

Run everything:

```bash
python -m pytest                       # 400+ tests, ~70 s
python -m agents.secret_scan           # no committed secrets
bandit -q -r backend agents ai ml -x tests -ll   # SAST, 0 medium+
pip-audit -r requirements.txt          # dependency CVEs
```

---

## The 13 attack classes

| # | Attack | Where it's answered | Control (and its honest limits) |
|---|--------|---------------------|---------------------------------|
| 1 | **Session replay** | `backend/services/auth.py`, `tests/test_session_replay_policy.py` | Opaque bearer tokens rotate after `ROTATE_AFTER_S` (24 h); the replacement returns in `X-Session-Token`. A superseded token inside `OVERLAP_S` (15 min) is *healed* for the same device and tolerated for others — in-flight requests from a stale tab must not log anyone out. Beyond the window the token is refused and audited (`auth.token_replay_rejected`) while **the live session keeps working**. The live session is **not** revoked because a rotated token was replayed — a phone holding the previous token, or a tab that missed the rotation header, must not log the user out everywhere. Strikes are audited only. `FEEFIX_REPLAY_POLICY=strict` is the explicit opt-in that still revokes the family; `lenient` only logs. A superseded token is healed at most once, and only when the client fingerprint actually matches, so omitting `User-Agent` cannot mint a new long-lived token. |
| 2 | **Clipboard** | `web/frontend/secure-clipboard.js`, `tests/js/clipboard.test.mjs` | **This is a usability measure, not a security control** — `describe()` returns `securityControl: false` and the module says so in its own header. `copyWithHygiene()` refuses credential-shaped values (token, 6-digit OTP, 40-char token shape, anything equal to `feefix.token`), clears on `visibilitychange`, and expires the copy after a short TTL (default 20 s). What it cannot do: malware already on the machine reads the clipboard the moment it is set, and the TTL is a browser-dependent timer that fails silently if the tab is closed. Treat clipboard secrecy as unavailable; the token is never placed there, never in a URL, and never logged. |
| 3 | **SQL / NoSQL injection** | `backend/services/db.py`, `backend/services/otp.py` | Every statement is parameterized; a test scans the source to keep it that way. SQLite has no NoSQL/`$where` surface. Injection payloads are inert data. |
| 4 | **Secret leaks in the repo** | `agents/secret_scan.py`, `.github/workflows/ci.yml`, `.pre-commit-config.yaml` | A committed-secret scanner runs **in CI, in pre-commit (staged files) and in pre-push (full tree)**, so a leak cannot be pushed by accident. It catches provider-token shapes, high-entropy assignments, base64-obfuscated keys, `"a" + "b"` string-split secrets and DSNs with passwords — including in unusual file extensions. **Limits:** pattern + entropy detection is not proof of absence, obfuscation it has never seen will pass, and a scanner is bypassed by `# secret-scan: allow <reason>` or branch protection being off. It raises the cost of an accident; it does not replace rotation. Third-party scanning (gitleaks) runs alongside it in CI, so a miss by one is a hit for the other. |
| 5 | **Long-password DoS / weak hashing** | `backend/services/passwords.py`, `tests/test_password_hashing.py` | **Argon2id** (`time_cost=2`, `memory_cost=19 MiB`, `parallelism=1` — OWASP parameters) is the production default: `FEEFIX_ENV=production` or `FEEFIX_PASSWORD_ALGO=argon2id` makes a deployment **refuse to start** without `argon2-cffi` rather than silently falling back. PBKDF2-HMAC-SHA256 (600k rounds) remains for stdlib-only/dev use and existing hashes, which are **re-hashed to Argon2id on the next successful login** (the plaintext is only available then). Passwords are length-capped at the schema *and* service layer and pre-hashed with SHA-256 before the KDF, so KDF work is constant regardless of submitted length. |
| 6 | **ReDoS in parsing** | `backend/services/numerals.py`, `tests/test_numerals.py`, `tests/test_fuzz_security.py` | Income/number parsing is **table-driven** (`i18n` rules + digit-translation maps) instead of per-script `\uXXXX` regexes; every user string is length-capped before any regex runs and quantifiers are bounded. A generated corpus + fuzz suite asserts totality (never raises), bounded output (`0 ≤ n ≤ 10¹³`) and idempotence. The old hand-maintained escape tables conflated Devanagari AA (अा) with Bengali AA (আ) — the bug class this replaced. |
| 7 | **Server-side template injection** | `backend/api/routes.py`, `web/frontend/app.js` | The API returns JSON only; there is no server-side template engine. The one HTML the server emits (OAuth handoff) passes through `_json_html_safe()`, which neutralises `</script>`, attribute and entity breakouts. The SPA escapes every interpolated value (`esc()`/`safeUrl()`). |
| 8 | **Error handling & info leakage** | `backend/main.py`, `backend/api/responses.py` | The catch-all handler logs the traceback server-side and returns an opaque `{"detail":"Internal server error.","request_id":…}`. Validation errors are rendered through `SafeJSONResponse`, which can always encode: a lone surrogate (`"\ud800"`, valid JSON that Python happily parses) used to reach the response renderer and turn a client typo into a 500 — the fuzz suite found it, schema validation now rejects lone surrogates with a clean 422, and the response class is the backstop. **Docs note:** `/docs`, `/redoc` and `/openapi.json` are **on by default**. Gating them removes no endpoint and no attack surface — the API answers identically without them — so the toggle exists only for operators who want a documentation-free surface, and the docs say so instead of implying a control. |
| 9 | **File upload** | `backend/services/upload.py`, `backend/services/uploads.py`, `backend/api/routes.py` | A single hardened gate: extension allowlist, magic-byte sniffing (renamed `shell.php` → `.pdf` is rejected), per-file and per-session byte quotas, file-count quota, path-traversal-safe names, random storage names, never executable, and stored **outside** the static mount (`FEEFIX_UPLOAD_DIR`). It is **wired into real routes** (`POST/GET/DELETE /api/uploads/{session_id}…`), not just a library: a test asserts the routes exist and another asserts the gate is the only writer, so a future endpoint cannot bypass it without deleting an assertion. Session identifiers follow **one rule on every route** (short, printable, separator-free, not dot-only) and the resolved storage path must stay inside the upload root — checked in the service so it cannot depend on a URL parser (`ensure_session_id`, `_session_dir`). |
| 10 | **Secret management** | `backend/services/secrets.py`, `tests/test_secret_hygiene.py` | Secrets come from the environment only. At boot `enforce_secret_hygiene()` **refuses to start** in production when a secret is missing, still a placeholder (`CHANGE_ME`, `changeme`, `test`, `xxx`…), too short, or paired with an unset companion variable. `FEEFIX_SECRETS_STRICT=0` does **not** override production — that hatch was the advisory check (a deploy on `CHANGE_ME` kept serving). Outside production, `FEEFIX_SECRETS_STRICT=1` opts in. **Limit:** this checks *shape and presence*, not whether the value is real or already leaked — rotation policy is still an operator responsibility. |
| 11 | **Input validation & body limits** | `backend/services/limits.py`, `backend/services/request_limits.py`, `tests/test_body_limits.py` | Limits are **per endpoint**, not one blunt 1 MB cap: 64 KB for a chat turn, 32 KB for events, 16 KB for auth, 256 KB for a profile, ~28 KB for long-form notes, 2 MB + multipart overhead for uploads — each tunable via `FEEFIX_MAX_BODY_*` without a code change, each clamped to `ABSOLUTE_MAX_BODY_BYTES` (16 MB) so a config mistake cannot remove the outer bound. Enforcement happens **while the body streams in**, not by trusting `Content-Length`; a body that overruns its policy is aborted mid-stream and answered with `413`. Field caps are env-tunable with the same clamp logic. Oversized input is refused before parsing, never processed. |
| 12 | **Rate limiting** | `backend/services/ratelimit.py`, `tests/test_ratelimit_distributed.py` | Sliding-window limits with per-endpoint tiers (tight on CPU-heavy AI endpoints), a memory-bounded hit table, `Retry-After` on 429, and **a shared store across workers/instances**: set `FEEFIX_REDIS_URL` (or `FEEFIX_RATELIMIT_BACKEND=redis`) and all workers share one counter set. Without it the app says so loudly at boot (`status()["distributed"] is False` plus a warning): with N instances the effective limit is N× and an attacker just spreads requests. Fail mode is per-bucket (`auth`/expensive endpoints fail **closed**, cheap ones stay open, `FEEFIX_RATELIMIT_FAIL_MODE`). Proxy awareness: `X-Forwarded-For` is honoured **only** with `FEEFIX_TRUST_PROXY=1`, and then the **rightmost** hop is used — the leftmost value is client-supplied, so trusting it let anyone rotate a header for unlimited buckets (a fuzz-suite finding, regression-tested). |
| 13 | **authentication ≠ authorization** | `backend/api/routes.py` | Authentication (`_require_user`) proves *who you are*; authorization (`_authorize_session`) proves *you own this session's data*. Ownership is enforced on every endpoint that touches a session — profile, tracker, match, ML rank, reminders, dispatch, events, uploads and personalised Q&A. Anonymous sessions stay open by design (random-URL knowledge only, no PII). |

---

## OTP delivery: a code the student never receives is not a second factor

`backend/services/otp.py` · `tests/test_otp_delivery.py` · `tests/test_otp_auth.py`

Sign-in codes are only meaningful if the code reaches the device the student
proved they control. The rules the module now enforces:

* **A configured gateway is the path.** Email: SMTP (Gmail app password and any
  relay), Brevo, Resend, or your own HTTPS endpoint. SMS: Twilio, MSG91,
  Fast2SMS, Vonage, or your own endpoint. The response says which one carried
  the code and whether it was accepted.
* **No gateway, no pretense.** Outside production the console fallback writes
  the code to the server log + `runtime/otp_outbox.jsonl` and returns it as a
  *labelled demo* (`demo: true`, `dev_code`, a DEMO banner in the UI). In
  production the API answers **503** with the variables to set, the UI hides
  that door, and the boot log reports it. Production never echoes a code —
  `FEEFIX_OTP_DEV_ECHO*=1` is refused at boot (`SecretHygieneError`), because a
  flag that hands a sign-in code back to the caller is a vulnerability, not a
  setting.
* **Failures are visible, never silent.** A gateway that refuses answers 502,
  the provider's own message is written to `audit_log` (`otp.send_failed.<ch>`)
  and shown to the operator (`GET /api/health` → `otp_delivery`,
  `scripts/check_otp_delivery.py`). A failed send is *rolled back*: the
  challenge is deleted and the send does not consume the student's hourly/daily
  budget, so a relay outage cannot lock anyone out.
* **The counters that cap spending count real sends.** `otp_sends` (24 h
  retention) backs the ≤5/hour and ≤10/day per-destination limits. Previously
  the challenge rows were swept on expiry, which quietly turned "5 per hour"
  into "5 per five minutes" — irrelevant when nothing was sent, a billing
  incident once every message costs money (SMS pumping).
* **Verification stays single-use and constant-time.** The read-modify-write of
  the attempt counter happens under one lock, so two concurrent guesses cannot
  both be accepted on the last attempt; the code is compared with
  `hmac.compare_digest` against a salted HMAC, and the challenge is destroyed on
  success. Failures are honest about *why* (401 wrong, 410 expired, 429 burned)
  while keeping the same wording for an address with an account and one without
  (no enumeration).

**Honest limits.** Delivery still depends on a paid SMS gateway — no free
gateway exists, and a deployment without one cannot text anybody. Email lands
in spam folders for unreputed domains (use a real sender + SPF/DKIM, or an
established relay). Indian SMS requires DLT-registered templates, so the
message text must match what you registered (`OTP_SMS_TEMPLATE`). The dev
outbox is a plaintext file by definition and is never written in production.

---

## Abuse-case table (what happens when it goes wrong)

Design decisions are easier to audit as behaviour than as prose. Each row is
asserted by a test.

| Abuse case | Behaviour | Test |
|---|---|---|
| Replay an old token from a stale tab | Refused after the overlap window; **the live session survives** | `test_session_replay_policy.py` |
| Replay a stolen token from another device | Strikes accumulate; family revoked only after `REPLAY_STRIKES` foreign-client refusals | `test_session_replay_policy.py` |
| Rotate `X-Forwarded-For` to get new buckets | Ignored without `FEEFIX_TRUST_PROXY`; rightmost hop used when enabled | `test_ratelimit_distributed.py` |
| Spread requests across instances | Shared counter set when `FEEFIX_REDIS_URL` is set; boot warning when not | `test_ratelimit_distributed.py` |
| Send a 100 MB body | Aborted mid-stream → `413`, no full-buffer allocation | `test_body_limits.py` |
| Send a legitimate-but-large notes field | Accepted under its own (larger) endpoint policy | `test_body_limits.py` |
| Upload `payload.pdf` that is really a script | Magic-byte mismatch → refused | `tests/test_uploads.py` |
| Upload to another user's session | Ownership check → `404`/`403`, never a leak | `tests/test_uploads.py` |
| Put `"\ud800"` in a chat message | Clean `422` (was: 500 from the renderer) | `tests/test_fuzz_security.py` |
| Commit a base64 AWS key or a split string token | Scanner finding in CI/pre-commit, exit 1 | `tests/test_secret_hygiene.py` |
| Boot with `CHANGE_ME` as a secret in production | Refuses to start | `tests/test_secret_hygiene.py` |
| Boot in production with the OTP demo echo on | Refuses to start (a live code would be returned to the caller) | `tests/test_otp_delivery.py` |
| Request a code in production with no gateway configured | `503` naming the variables to set — never a fake code | `tests/test_otp_delivery.py` |
| SMTP/Twilio/MSG91 refuses the message | `502`, provider text in `audit_log`, send **not** counted against the student's budget | `tests/test_otp_delivery.py` |
| Gateway answers `HTTP 200 {"return": false}` | Treated as a failure, not a delivered code | `tests/test_otp_delivery.py` |
| Guess codes five times | Attempt counter burns the challenge; both wrong-code paths answer identically with or without an account | `tests/test_otp_auth.py` |
| Two instances migrating the same SQLite file at once | Serialized; loser waits instead of crashing on duplicate DDL | `tests/test_schema_migrations.py` |
| Crash mid-migration | Rolls back; a half-applied DB self-heals on next boot | `tests/test_schema_migrations.py` |

---

## Defence in depth already present

Argon2id (or PBKDF2-HMAC-SHA256 600k for legacy/dev) · SHA-256-hashed revocable
session tokens · uniform login errors (no user enumeration) · strict CSP · HSTS ·
`no-store` on `/api/*` · CORS closed by default · append-only audit log · SQLite
WAL + foreign keys + race-safe versioned migrations · non-root container.

## Supply chain & automation gates

| Gate | Where | What it catches |
|---|---|---|
| Secret scan (first-party) | `.github/workflows/ci.yml`, `pre-commit` | Provider tokens, entropy finds, split/base64-obfuscated secrets |
| gitleaks (third-party) | `ci.yml` job `secret-scan-third-party` | Catches what a first-party regex misses — two independent detectors |
| SAST | `ci.yml` job `sast-and-dependencies` | `bandit -ll` — medium+ findings fail the build |
| Dependency CVEs | same job | `pip-audit -r requirements.txt` |
| Dataset liveness | scheduled `dataset-liveness` job | Dead source URLs and schema drift in `data/` |
| Dead source URLs | scheduled `dataset-liveness` job | Probes every official portal URL and reports each failure as a finding. Verified against a fully blocked network: it reports, exits 0 and never raises — a liveness job that dies when a portal is down is a job somebody disables. |
| Flakiness | `flake-watch` CI job | Runs the concurrency, property and migration suites **three times per build**. Intermittent failures in those files — real subprocesses, real ports, real clocks, randomised input — otherwise show up as a green/red lottery, and a gate people do not trust is a gate people skip. |
| The gates themselves | `tests/test_ci_config.py` | Silent rot: a gate that references a renamed module, a dropped test file, a demoted job (`continue-on-error`), a shallow clone that cannot see history, or an action still on a retired runtime. The workflow is parsed as data, its commands are run for real where they are cheap, and the mutations above are asserted to fail the build. |

## Verifying it yourself

```bash
python -m pytest                                   # full suite (472 tests)
python -m pytest tests/test_fuzz_security.py        # property-based/adversarial
python -m pytest tests/test_ci_config.py            # the gates themselves
bandit -q -r backend agents ai ml -x tests -ll
pip-audit -r requirements.txt
python -m agents.secret_scan                        # repo scan (exit 1 on findings)
python -m agents.secret_scan --staged               # pre-commit mode
python -m agents.verify_dataset                     # + --check-urls for liveness
pre-commit run --all-files                          # what a developer's loop runs
./scripts/verify.sh                                 # every CI gate, one command
```

## What this document does **not** claim

Hand-written tests by the same author as the code prove *consistency*, not
security. Same-author suites systematically miss the assumptions the author
never questioned (this map's most recent findings — the surrogate 500, the XFF
bucket bypass, the session-id rule, and a calendar-day-dependent assertion that
went red with no code change — came from the fuzz/CI-contract suites and a live
server probe, not from review of the passing tests). The
controls above reduce the cost and blast radius of the mistakes we know about;
they are not a substitute for independent review, a real penetration test
against a deployed instance, or a bug-bounty. Those are on the roadmap below,
and no amount of green checkmarks replaces them.

## Roadmap (free, incremental)

1. Independent third-party review of the auth/session and upload paths.
2. TOTP second factor + step-up re-auth for destructive actions.
3. Postgres-backed deployments inherit the same contract (`docs/deploy/DEPLOYMENT.md`).
4. Fill/embed a real corpus for the local AI layer once a model host is allowlisted.
