# Response to the security review

Ten findings were raised against the v1.1 hardening work. This document records
what changed for each one, what it now is, and how it is verified. **None of the
ten was closed with documentation alone** — every row ends in code, config or a
test that fails if the finding comes back.

Verification commands:

```bash
python -m pytest                                    # 455 passed
bandit -q -r backend agents ai ml -x tests -ll       # exit 0, 0 medium+
pip-audit -r requirements.txt                        # no known vulnerabilities
python -m agents.secret_scan                         # 0 findings on this repo
pre-commit run --all-files                           # the developer-loop gates
```

Test count went from **217 → 455**. The additions are the point of the exercise:
the old suite proved consistency, the new one probes the assumptions.

| Test file | What it adds |
|---|---|
| `test_password_hashing.py` | Argon2id parameters, fail-closed boot, PBKDF2→Argon2id migration |
| `test_ratelimit_distributed.py` | two real worker processes, shared counters, header spoofing, fail modes |
| `test_session_replay_policy.py` | overlap heals a stale tab; the live session survives a replay |
| `test_body_limits.py` | per-endpoint caps, mid-stream `413`, env overrides, absolute clamp |
| `test_uploads.py` | the gate behind real routes: magic bytes, quotas, traversal, ownership |
| `test_numerals.py` | table-driven income parsing across 4 scripts |
| `test_secret_hygiene.py` | scanner bypasses, strict boot, false-positive quality |
| `test_schema_migrations.py` | concurrent boots, crashed migrations, rollback |
| `test_clipboard_js.py` + `tests/js/clipboard.test.mjs` | the module *executed*, not grepped |
| `test_fuzz_security.py` (hypothesis) | property-based/invariant pass over parsers, sanitisers, middleware |
| `test_ci_config.py` | the CI/pre-commit gates parsed, resolved and executed — so they cannot rot into decoration |

---

## 1. Docs-off was security theatre

**Was:** `/docs`, `/redoc`, `/openapi.json` gated behind `FEEFIX_ENABLE_DOCS`,
presented as hardening. It hides documentation, never an endpoint: the API
answers identically with the switch flipped, so it removed no attack surface
while breaking Swagger, generated clients and QA tooling.

**Now:** docs are **on by default**; `FEEFIX_DISABLE_DOCS=1` /
`FEEFIX_ENABLE_DOCS=0` remain for operators who want a documentation-free
surface, and `docs_enabled()` states in its docstring that it is cosmetic.
`apply_security_headers` still covers `/openapi.json`.

**Verified:** `test_docs_are_enabled_by_default_and_can_be_opted_out` (both
directions, including that the OpenAPI schema lists the upload routes).

## 2. PBKDF2 600k instead of Argon2id

**Was:** 600k PBKDF2 rounds because the project had a self-imposed stdlib-only
rule — a hard ceiling on crack resistance for a memory-hard-vs-CPU-bound
tradeoff nobody had actually chosen.

**Now:** **Argon2id is the production default** (`time_cost=2`,
`memory_cost=19 MiB`, `parallelism=1`; OWASP parameters) via `argon2-cffi`.
`FEEFIX_ENV=production` or `FEEFIX_PASSWORD_ALGO=argon2id` makes a deployment
**refuse to start** without the backend rather than silently downgrading.
PBKDF2 remains for legacy rows and stdlib-only development, and those hashes are
**re-hashed to Argon2id on the next successful login** — the only moment the
plaintext exists.

**Verified:** `test_password_hashing.py` (parameters, refusal-to-boot, migration
on login, plaintext-absence proof). Live: `/api/health` reports
`"password_hashing": "argon2id"`.

## 3. In-memory rate limiter multiplies with workers

**Was:** per-process counters. With `N` workers/instances the effective limit
was `N ×` the configured one, and an attacker just spreads requests.

**Now:** a `RedisBackend` shares one sliding window across every worker and
instance (`FEEFIX_REDIS_URL` or `FEEFIX_RATELIMIT_BACKEND=redis`), with
`fakeredis` for tests. Fail mode is per-bucket: **auth and expensive endpoints
fail closed** when the store is unreachable, cheap ones stay open. When no
shared store is configured the app says so loudly at boot and in
`GET /api/health` (`ratelimit.distributed: false` + `recommendation`) rather
than quietly limiting per process — a single instance is fine, and now it says
*why* it is fine.

**Two further bypasses found while testing this:**

* `X-Forwarded-For` was read **leftmost** — proxies append, so the leftmost
  value is client-supplied and rotating it bought a fresh bucket per request.
  Now the **rightmost** hop is used, and only when `FEEFIX_TRUST_PROXY=1`.
* Docker/Render deployments behind a proxy without `FEEFIX_TRUST_PROXY` made
  every user share one bucket; the variable is now wired in `render.yaml` and
  documented in `Dockerfile`/`DEPLOYMENT.md`.

**Verified:** `test_ratelimit_distributed.py` — including
`test_two_instances_without_redis_multiply_the_limit`, which reproduces the
original finding with **two real uvicorn processes**, and the new spoofing
tests.

## 4. Replay detection revoked the whole session family (self-DoS)

**Was:** any replayed, already-rotated token revoked the family — one stale tab
logged the user out of every device.

**Now:** `FEEFIX_REPLAY_POLICY=balanced` (default):

* inside `OVERLAP_S` (15 min) a superseded token from the **same device** is
  healed (a fresh sibling token is minted, so the stale tab stops replaying);
  from a different client it is tolerated as an in-flight request;
* beyond the window the token is **refused and audited**
  (`auth.token_replay_rejected`) while **the live session keeps working**;
* family revocation requires a real theft signal: `REPLAY_STRIKES` refusals from
  a **different client fingerprint**.

`strict` (old behaviour) and `lenient` remain explicit opt-ins.

**Verified:** `test_session_replay_policy.py` (11 tests) plus the migrated
`test_aged_token_rotates_and_a_stale_replay_does_not_kill_the_live_session` in
the original hardening suite.

## 5. `secure-clipboard.js` gave false confidence

**Was:** presented as "clipboard-attack hardening". Malware reads the clipboard
the instant it is set; a ~20 s TTL is a browser-dependent timer that fails
silently when the tab closes.

**Now:** the module says what it is: `describe()` returns
`{securityControl: false, limitations: [...]}` naming clipboard malware
explicitly, the header comment states it is a usability measure, and the docs
repeat it (`HARDENING.md` #2, `SECURITY.md`, README no longer implies
protection). The behaviour that *is* real is kept and hardened:
`copyWithHygiene()` refuses credential-shaped values (including anything equal to
the stored session token), clears on `visibilitychange`, and reports a reason
(`copied | refused-credential-shaped-value | clipboard-unavailable |
denied-or-unfocused`) instead of failing silently.

**Verified:** `tests/js/clipboard.test.mjs` **executes** the module in node (18
checks) and `tests/test_clipboard_js.py` wraps it, including an assertion that
the module still declares `securityControl: false` — the honesty is a test, not
a promise.

## 6. Secret scanning was advisory and bypassable

**Was:** a regex scanner as the only gate, and a boot check that `log.warning`ed
about `CHANGE_ME` and served anyway. Entropy/pattern matching misses obfuscated
secrets; nothing enforced anything.

**Now:** four independent layers —

* **Enforcement:** `enforce_secret_hygiene()` **raises** in production (or
  `FEEFIX_SECRETS_STRICT=1`) when a secret is missing, placeholder-shaped, too
  short, or missing its companion variable, and the message names the variable
  and the escape hatch. `FEEFIX_SECRETS_STRICT=0` is an explicit, auditable
  downgrade. Verified live: `OTP_SMTP_PASS=CHANGE_ME` in production exits 1;
  the same value in development boots with a warning.
* **Automation:** scanning runs in **pre-commit (staged)**, **pre-push (full
  tree)** and **CI**, plus a second, independent scanner (**gitleaks**) in CI —
  so a miss by one detector is a hit for the other.
* **Detection depth:** provider-token shapes, entropy-based assignment
  detection, **base64-encoded** provider prefixes, `"a" + "b"` split literals,
  DSNs with real passwords, and text sniffing in unusual file extensions.
* **Quality:** documented placeholders (`postgres://user:password@host`,
  `{password}` templates, `<...>`) are no longer findings — a scanner people
  must waive is a scanner they disable. The waiver path (`# secret-scan: allow
  <reason>`, `.secretscanignore`) is tested to be **per line**.

Honest limits, now written down: pattern + entropy detection is not proof of
absence, and no scanner replaces rotation policy.

**Verified:** `test_secret_hygiene.py` (33 tests), `python -m agents.secret_scan`
→ 0 findings on this repository.

## 7. `upload.py` was dead code

**Was:** a hardened upload gate that no route called — a control protecting
nothing, and nothing forcing a future endpoint to use it.

**Now:** the gate is wired into real routes — `POST /api/uploads/{session_id}`,
`GET …/{upload_id}/content`, `DELETE …/{upload_id}` — through
`services/uploads.py`, which owns storage (random names outside the static
mount, per-session quotas) and delegates validation to `upload.py`. Ownership is
enforced on every read and delete.

**Verified:** `test_upload_gate_is_wired_into_a_route` (asserts the routes exist
in the OpenAPI schema, so deleting them breaks the build) and
`tests/test_uploads.py` (24 tests: magic bytes, quotas, traversal, ownership).

## 8. i18n income parsing was brittle

**Was:** hand-maintained `\uXXXX` escape tables per script — incomplete, easy to
corrupt, and already wrong (Devanagari AA `अा` conflated with Bengali AA `আ`).

**Now:** parsing is **table-driven** (`backend/services/numerals.py`): explicit
digit-translation maps per script plus script-aware unit words (লাখ / लाख / லட்சம்
/ thousand / crore …), building on the i18n rules module instead of duplicating
escapes. Numerals are NFD/NFC-normalised once, and the parser is total.

**Verified:** `tests/test_numerals.py` (46 tests) across English, Bengali, Hindi
and Tamil, plus fuzz invariants in `test_fuzz_security.py`: `parse_amount` never
raises, always returns `0 ≤ n ≤ MAX_AMOUNT`, normalisation is idempotent, and
ASCII thousands/lakh/crore round-trip.

## 9. The 1 MB cap and fixed length limits were blunt

**Was:** one global 1 MB body cap and field caps that rejected legitimate input
(a long notes field) while being far too generous for a 2000-character chat
turn.

**Now:** **per-endpoint body policies** in `services/limits.py`, enforced
**while the body streams in** (`services/request_limits.py`) rather than by
trusting `Content-Length`:

| Endpoint class | Cap | Why |
|---|---|---|
| `/api/uploads*` | `MAX_UPLOAD_BYTES` + 64 KB | multipart envelope around a capped file |
| `/api/students/{id}/profile` | 256 KB | free-text profile notes |
| `/api/students/{id}/notes` | `MAX_NOTES_LEN` + 8 KB | long-form notes (20 KB default) |
| `/api/ask|chat|match` | 64 KB | a bounded conversation turn |
| `/api/events` | 32 KB | small telemetry payload |
| `/api/auth/*` | 16 KB | credentials are tiny; the KDF must never see a large body |
| everything else (`/api/*`) | 1 MB | catch-all, unchanged for compatibility |

Every number is env-tunable (`FEEFIX_MAX_BODY_*`) **and clamped** to
`ABSOLUTE_MAX_BODY_BYTES` (16 MB), so a config mistake cannot remove the outer
bound. An overrun is aborted mid-stream and answered `413` with the policy name
and the limit — the client learns which limit it hit instead of a generic
refusal. Field length caps are env-tunable with the same clamp logic.

**Verified:** `test_body_limits.py` (19 tests) + live check: a 100 KB chat body
→ `413 {"policy": "conversation", "limit_bytes": 64000}`, while a notes body up
to its own policy is accepted.

## 10. "217 passed" proves consistency, not security

**Was:** hand-written tests by the same author as the code, no fuzzing, no
third-party review, and a distributed bypass that a single-process suite
structurally cannot see.

**Now:**

* **Property-based/fuzz suite** (`test_fuzz_security.py`, hypothesis) over
  parsers, sanitisers, middleware and scanner output — totality, boundedness,
  idempotence, "no 5xx for any input", JSON/JSON-in-HTML safety.
* **Multi-process tests** (`test_ratelimit_distributed.py`) that boot real
  uvicorn workers — the class of bug the old suite was blind to.
* **Third-party tooling in CI**: gitleaks, bandit (`-ll`, medium+ fails the
  build), pip-audit, plus a scheduled dataset-liveness job.
* **An honest "what this does not claim" section** in `HARDENING.md` and
  `SECURITY.md`, with independent review and a pen test on the roadmap.

This immediately paid for itself — four real defects were found by the new
tests, not by review of the passing ones:

| Found | Defect | Fix |
|---|---|---|
| fuzz | a lone surrogate (`"\ud800"`) reached the response renderer → **500** on any endpoint that echoes input | schema rejects it (`422`), `SafeJSONResponse` can always encode, validation errors are sanitised |
| distributed | `X-Forwarded-For` read leftmost → **unlimited rate-limit buckets** | rightmost hop, trusted-proxy-only |
| distributed | two instances migrating one SQLite DB → **crash loop** (`duplicate column name`); a crashed migration poisoned every later boot | `BEGIN IMMEDIATE` + guarded `ALTER TABLE` + transactional DDL; a half-applied DB self-heals |
| secret hygiene | the scanner flagged its own documentation placeholders (`.env.example` DSNs), which is how scanners get waived into uselessness | placeholder-aware DSN detection, with tests that a *real* password is still caught |

**Verified:** 435 tests, `bandit` exit 0, `pip-audit` clean, repo scan 0
findings, and a live server smoke test (`/api/health`, `/openapi.json`, `/docs`,
413/422 paths, security headers).

---

## Deployment changes that follow from this

`render.yaml` and `Dockerfile` now pin the production posture:

* `FEEFIX_ENV=production`, `FEEFIX_PASSWORD_ALGO=argon2id`,
  `FEEFIX_SECRETS_STRICT=1` → **fail closed** on weak config;
* `FEEFIX_REDIS_URL` (+ `FEEFIX_RATELIMIT_FAIL_MODE=auth`) → shared counters;
* `FEEFIX_TRUST_PROXY=1` → correct client identity behind Render/nginx/ingress;
* `FEEFIX_DB` / `FEEFIX_UPLOAD_DIR` on a volume → state survives deploys;
* non-root container user; `--proxy-headers` with uvicorn's own trusted-peer
  rules.

`.env.example` documents every knob, and `docs/deploy/DEPLOYMENT.md` separates
"must set in production" from "rarely needed".

## What is still open (deliberately)

These are not fixed, and claiming otherwise would repeat the original mistake:

1. **Independent third-party review / penetration test.** Same-author tests
   cannot see the assumptions their authors never questioned.
2. **Multi-region or Postgres deployments.** SQLite + Redis covers a modest
   scale-out; the Postgres path is documented, not implemented.
3. **Step-up authentication** for destructive actions (TOTP is on the roadmap).
4. **Bot/abuse protection beyond rate limits** (no CAPTCHA, no device
   reputation) — relevant once the OTP endpoints face real traffic.


---

# Second pass: verifying the verification

A security review's sharpest point is usually the meta one — *"who checks the
checkers?"* The response above added four gates and claimed they work. That
claim was itself unverified, so the second pass tested it, and found three more
issues (one in a gate, one test defect, one production rule).

## A. The gates were configuration, not code — now they are executed

`ci.yml` and `.pre-commit-config.yaml` had never been run. Both were validated
for real:

| Check | Result |
|---|---|
| `pre-commit validate-config` | valid |
| `pre-commit run --all-files` | secret scan, security suites, bandit — all pass |
| `pre-commit run --all-hooks --hook-stage pre-push` | full suite runs before a push |
| The hook actually **fails** on a staged leak | planted a Stripe-shaped key → hook exit 1, finding named with file:line |
| Every command in `ci.yml` run locally | `secret_scan --json` (clean + report written), `verify_dataset` (71 schemes, 0 findings), `ml.experiments.simulate_outcomes`, `agents.reminder_scheduler --dry-run` — all exit 0 |

New: **`tests/test_ci_config.py` (14 tests)** parses both files as data and
asserts that the gates exist, cover the branch this work happens on, run with
least privilege, are *blocking* (not `continue-on-error`), have timeouts, pin a
third-party scanner that is not ours, scan full history, and that every module
and path they name still resolves — plus it runs the cheap commands for real.
Mutation-tested: reintroducing a stale module name, demoting the SAST job to
advisory, or downgrading the scanner to a shallow v2 clone each **fails the
build**.

Two real fixes came out of this:

* **`bandit`/`pip-audit` were not in `requirements.txt`** — the CI job installed
  them ad hoc, so a fresh clone could not reproduce the gate locally, and the
  new test caught it. Now declared.
* **gitleaks pinned at `@v2` (retired Node 20 runtime)** and would have tried to
  comment on PRs with a read-only token. Now `@v3` with comments off and a
  documented reason, plus `workflow_dispatch` and `concurrency` cancellation.

## B. A test that went red because the calendar moved

`tests/test_ranking.py::test_expired_pushed_to_bottom` asserted "nothing has
expired yet" at `date.today() + 10 days`. On 2026-10-16 the 2026-10-25 NSP
deadline fell inside that window, so **the suite started failing with no code
change at all** — the worst kind of flake, because the natural response is to
loosen the assertion.

Fixed properly: the tests are now anchored to the **dataset's own calendar**
(earliest matched deadline ± a day), the windows are derived rather than
hard-coded (with an explicit message naming the arithmetical precondition if a
curator ever narrows the fixture), and a new
`test_expiry_ordering_holds_on_every_day` sweeps **every day in the dataset's
range**, asserting the ranker's invariants — expired-last ordering, descending
scores per partition, and `expired == (days_left < 0)` — on all of them. The
suite was then run under three `PYTHONHASHSEED` values to rule out ordering
flakes: 455 passed each time.

## C. Session identifiers: one rule, enforced on every path

Driving the live deployment (not just the test client) surfaced a real
inconsistency: `POST /api/uploads/<id>` validated the session id (`422` over the
limit) while `GET /api/uploads/<id>` did not — a 10 KB identifier was refused on
upload but **echoed back** in the listing response, and ids containing NUL or
`/` reached the storage layer, creating directories that only survived because
the sanitiser happened to rewrite them. Worse, in the service the rule was
`len(session_id) > 64` written inline, and `..` — a legal string that resolves
to the upload root's *parent* — passed it. The routing layer happened to reject
`..` first, which is not somewhere a filesystem guarantee should live.

Now: `ensure_session_id()` is the single rule for all four uploads routes
(short, printable, separator-free, not dot-only) and `_session_dir()` verifies
the **resolved** path stays inside the upload root, so a future refactor of the
sanitiser cannot silently reintroduce traversal. Verified live against the
running deployment: `..`, NUL, newline, 10 KB ids → `422` on upload, list,
download and delete, with **nothing written to disk**; legitimate ids still
work; and a cross-session read of a hostile id's upload → `404`.

## What the second pass says about the first

Both new findings were in places the first pass had *claimed* coverage: "the
gates are in CI" (they were never run) and "session ids are sanitised" (they
were sanitised in one path only). That is the same lesson as finding #10 one
level up — a claim about a control is not the control, and a check that has
never been seen to fail is not evidence. Hence the mutation tests above: each
new assertion was verified to fail when the thing it protects is broken.
