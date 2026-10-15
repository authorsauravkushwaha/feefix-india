# Security Policy

FeeFix India handles data that students disclose about their household income,
community, marks and disability status. Some of it concerns minors. We treat a
vulnerability in this system as a privacy incident for real people, not a bug
report.

## Reporting a vulnerability

**Please do not open a public issue for an exploitable finding.**

Use either channel:

1. **[GitHub private security advisory](https://github.com/authorsauravkushwaha/feefix-india/security/advisories/new)**
   — preferred. It keeps the report private, lets us discuss and develop a fix
   in the same thread, and supports a coordinated disclosure and CVE request.
2. **Email `security@feefix.local`** — if you would rather not use GitHub.

The running service publishes the same contact details at
[`/.well-known/security.txt`](https://github.com/authorsauravkushwaha/feefix-india/blob/main/backend/main.py)
(RFC 9116).

### What to include

* The affected endpoint, file and line if you know them.
* The **minimum** steps to reproduce. A single `curl` command is ideal.
* Whether the issue is exploitable unauthenticated, or requires an account.
* Whether you have accessed, stored or modified any real user data. **Please do
  not.** If proving the bug required touching real data, tell us how much and we
  will treat it as an incident.

Please give us a reasonable window before publishing. We would rather fix it
than argue about it.

### What to expect

| When | What we do |
|---|---|
| **Within 72 hours** | Acknowledge the report and confirm whether we can reproduce it |
| **Within 7 days** | Tell you our assessment: severity, affected versions, and a planned fix date |
| **On fix** | Ship the fix, add a named regression test to `tests/test_security.py`, and credit you in the advisory (unless you prefer not to be named) |
| **After disclosure** | Publish an advisory describing the class of bug, so the control is understood and not re-broken |

We do not currently run a paid bounty programme. We will not pursue legal action
against a researcher who reports in good faith and does not access other users'
data.

## Supported versions

FeeFix is developed on `main` and deployed as a single service — there are no
long-lived release branches or maintained older versions. **Only the current
`main` receives security fixes.** If you are running a fork or an old checkout,
update it.

## Scope

In scope, and most welcome:

* `backend/` — the FastAPI service, authentication, authorisation, storage,
  rate limiting, anti-replay, input validation, uploads
* `web/frontend/` — the vanilla-JS SPA
* `mobile/android/` — the Kotlin reference client
* `data/` — the scheme dataset, **including a malicious contribution to it**.
  Dataset content reaches student browsers, so a payload in a scheme URL is a
  real XSS vector, not a data-quality issue
* Deployment configuration: `Dockerfile`, `render.yaml`, `.github/workflows/`

Out of scope:

* Findings that require physical access to an already-unlocked device
* Reports that a dependency has a known CVE, **unless** you can show a reachable
  path — `pip-audit --strict` already runs in CI on every push
* Social engineering of maintainers
* Denial-of-service by raw traffic volume (we have no CDN or scrubbing layer to
  test against); resource-exhaustion via a *protocol* feature — ReDoS, unbounded
  maps, KDF cost, oversized bodies — is very much in scope and has been fixed

## Security architecture

| Document | Contents |
|---|---|
| **[docs/security/SECURITY.md](docs/security/SECURITY.md)** | The threat model — who the attacker is, and every control mapped to Confidentiality, Integrity and Availability |
| **[docs/security/HARDENING.md](docs/security/HARDENING.md)** | The October 2026 hardening pass — what was actually exploitable, with measured evidence, and how each fix works |
| **[tests/test_security.py](tests/test_security.py)** | 155 regression tests, one named per attack prevented |
| **[.env.example](.env.example)** | Every configuration variable, its default, and why the default is fail-closed |
| **[scripts/secret_scan.py](scripts/secret_scan.py)** | Secret scanning, run in CI on the tree and the full history |

### Design rules

Two properties the whole system is built around:

**Fail closed.** Forgetting to configure FeeFix must never relax its security.
`FEEFIX_ENV` unset means **production**. An unset variable produces the stricter
behaviour, always. Disabling the anti-replay defence in production requires
setting `FEEFIX_I_ACCEPT_REPLAY_RISK=1` — a name chosen so it survives code
review.

**Authentication is not authorisation.** Knowing *who* is asking does not answer
*whether they may do this*. Every session-scoped handler calls
`backend/services/authz.py`; ownership is write-once and stamped on write. This
was the most serious class of bug found in the hardening pass, and the tests
named after it are the ones to read first if you touch an endpoint that takes a
`session_id`.

### Verifying the controls yourself

```bash
pytest tests/test_security.py -v     # 155 security regression tests
pytest -q                            # full suite
python scripts/secret_scan.py        # secrets in tracked content
python scripts/secret_scan.py --history   # ...and in the last 200 commits
```

## Past advisories

| Date | Class | Severity | Detail |
|---|---|---|---|
| 2026-10 | OTP code disclosed in response body when SMTP delivery failed | **Critical** | [HARDENING §4](docs/security/HARDENING.md#4-secret-key-leaks--critical-fixed) |
| 2026-10 | IDOR on six session-scoped endpoints; account takeover via session rebinding | **Critical** | [HARDENING §13](docs/security/HARDENING.md#13-authentication--authorisation--critical-fixed) |
| 2026-10 | Quadratic email regex on an unauthenticated endpoint (ReDoS) | High | [HARDENING §6](docs/security/HARDENING.md#6-redos) |
| 2026-10 | Unbounded rate-limiter bucket map (memory exhaustion) | High | [HARDENING §12](docs/security/HARDENING.md#12-rate-limiting) |
| 2026-10 | `X-Forwarded-For` trusted from any peer, defeating every per-IP limit | High | [HARDENING §15](docs/security/HARDENING.md#15-client-identity-spoofing) |
| 2026-10 | `javascript:` URL rendered into an anchor via a dataset contribution (XSS) | High | [HARDENING §14](docs/security/HARDENING.md#14-xss-via-javascript-url) |
| 2026-10 | OTP pepper and `.env` not covered by ignore rules; secrets in image layers | High | [HARDENING §10](docs/security/HARDENING.md#10-secret-management) |
| 2026-10 | No request body ceiling; no replay defence; no per-IP KDF budget | High | [HARDENING §1](docs/security/HARDENING.md#1-replay-attack), [§5](docs/security/HARDENING.md#5-long-password-dos--the-hypothesis-was-wrong-the-control-is-still-right), [§11](docs/security/HARDENING.md#11-input-validation) |

All were found by internal review, fixed, and covered by named regression tests
before this policy was published. None was reachable in a deployment that had
never been made public.
