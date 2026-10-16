# FeeFix India — notes for AI agents working in this repo

## What this codebase is

A FastAPI app (`backend/main.py`) serving a REST API under `/api` **and** a
build-step-free SPA from `web/frontend/` — one origin, one port. Domain logic
lives in `backend/matching_engine/`, `backend/services/`; the dataset is JSON
under `data/schemes/` (71 records, validated in CI by `agents/verify_dataset.py`).

## Run it

```bash
./scripts/dev.sh           # create .venv, install deps, serve on :8000
./scripts/dev.sh --test    # full suite
python -m pytest           # the whole suite (~40 s; no network needed)
```

Offline environments: set `FEEFIX_AI_BACKEND=ngram`. The neural embedder's model
download is bounded (`FEEFIX_AI_LOAD_TIMEOUT`, default 20 s) and falls back
automatically, so the suite never blocks on the network — it used to, forever.

## Security invariants — do not regress these

Several of these are the *result* of a deliberate hardening pass; each has a test
that will fail if the old behaviour comes back.

1. **Docs stay ON by default.** `/docs`, `/redoc`, `/openapi.json` are a
   client/QA contract. Hiding them removed no endpoint and no attack surface.
   `FEEFIX_DISABLE_DOCS=1` exists and is cosmetic. (Hiding them again is a
   regression — `tests/test_boot_policy.py`.)
2. **New passwords are Argon2id** (`argon2-cffi`), never PBKDF2. Legacy
   `pbkdf2$` rows still verify and are re-hashed on the next successful login.
   If argon2 cannot be imported the fallback is `hashlib.scrypt` (also
   memory-hard) + a loud boot log — never a silent downgrade.
   (`tests/test_password_hashing.py`.)
3. **The rate limiter's default store is shared** (SQLite, atomic via
   `BEGIN IMMEDIATE`; Redis when `FEEFIX_REDIS_URL` is set). A process-local dict
   multiplies every limit by the worker count — that is why `MemoryStore` is
   opt-in and `topology_warnings()` exists. (`tests/test_rate_limit_shared.py`
   spawns real processes.)
4. **Replay detection quarantines, it does not log everyone out.** A replayed
   superseded token is tombstoned (`replayed_at`) and reported via
   `X-Session-Warning` / `GET /api/auth/security-events`; the live token keeps
   working. Escalation after `FEEFIX_SESSION_REUSE_ESCALATE` replays, or opt-in
   `FEEFIX_SESSION_REUSE_POLICY=revoke_family`.
   (`tests/test_session_reuse_policy.py`.)
5. **The clipboard helper is UX hygiene, not a control** — and it must never
   blind-wipe the user's clipboard: it reads the value back first.
   (`web/tests/clipboard.test.mjs`.)
6. **Secrets are enforced at boot.** Strict mode (`FEEFIX_STRICT_SECRETS=1` or
   production markers) refuses to start on placeholder/half-configured values.
   The scanner's history mode must keep *attributing real file paths* (so the
   test-fixture exemption and `.secretscanignore` apply) and must stay scoped to
   the current branch by default — `--all-branches` is the opt-in whole-repo
   audit, and it reports other branches' fake fixtures by design.
   (`tests/test_secret_scan.py`.)
7. **The upload gate is called by routes.** `services/upload.py` (validation) +
   `services/documents.py` (storage outside the web root) are wired into
   `/api/students/{sid}/documents`. A static test fails if a new module starts
   writing user bytes to disk.
8. **The income lexicon is data.** `language/regional_support/numerals.json` in
   real Unicode, script-validated by `numerals.validate_lexicon()`. Never reintroduce
   `\uXXXX` escapes for Indic scales in Python source.
9. **Body caps are per endpoint** and enforced while the body streams
   (`services/body_limit.py`) — a chunked request with no `Content-Length` must
   still be rejected. (`tests/test_body_limits.py`.)
10. **Claims must match code.** `tests/test_wiring_and_claims.py` fails if a
    documented control is unwired, a CI security job is disabled
    (`continue-on-error`), or the docs start overclaiming (e.g. quoting a test
    count as a security result, or advertising PBKDF2 as current).

## Testing conventions

* `tests/conftest.py` pins the offline AI backend and gives every test a fresh
  SQLite database; the limiter's shared store therefore starts empty per test.
* Property-based tests use `hypothesis` (marked in `tests/test_fuzzing.py`),
  multi-process tests are marked `slow`.
* The fuzzer doubles as a test and a CLI: `python -m scripts.fuzz_api
  --requests 2000 --seed 1`. It fails on 5xx, on a >timeout request, or on a
  leaked traceback/internal name.
* Frontend behaviour is tested with Node's built-in runner:
  `node --test "web/tests/*.test.mjs"`.

## Honesty rules for docs

State verified facts with the test that proves them, and state the gaps: there is
**no third-party pen test or external review**, the fuzzer is a TestClient
harness (no TLS/proxy/browser), DoS resistance is argued from bounded work per
request, and the SQLite limiter is one-host only. Removing those caveats is a
regression that `test_wiring_and_claims.py` is designed to catch.
