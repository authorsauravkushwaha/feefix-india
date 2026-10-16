# Deploy FeeFix free — phone-accessible in minutes

FeeFix is deliberately **one origin, one port, one process**: a single FastAPI
app serves the REST API *and* the web experience. That means any free tier
that can run Python can host the whole product, and the URL you get works
immediately in any phone browser (add-to-home-screen = instant "app").

## Prerequisite

```bash
./scripts/dev.sh --test   # 151 tests green locally
```

---

## Option A — Render (free web service)

1. Push this repo to GitHub (it renders native `web.StaticFiles`, no build step).
2. Render dashboard → **New Web Service** → connect the repo.
3. Settings:
   * **Build command**: `pip install -r requirements.txt`
   * **Start command**: `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`
4. Add a **Render Disk** (1 GB free) mounted at `/opt/render/project/src/runtime`
   so `runtime/feefix.db` (accounts, tracker, outcome events) survives restarts.
5. Free tier sleeps when idle — first visit takes ~30s, then it's instant.
6. Set the service URL as the repo's **Website** link on GitHub.

## Option B — Fly.io (free allowance)

```bash
fly launch --no-deploy       # picks up the repo; choose Python
fly volumes create feefix_data --size 1   # persists runtime/
fly deploy
```

`fly.toml` (one file; this repo needs no other changes):

```toml
app = "feefix-india"
[build]
[env]
  PORT = "8080"
[http_service]
  internal_port = 8080
  force_https = true
[[mounts]]
  source = "feefix_data"
  destination = "/app/runtime"
```

Then: `fly open` — save the link on the repo home page; it opens in any phone browser.

## Option C — Hugging Face Spaces (free forever)

* Create a Space → **Docker** → point at this repo with a `Dockerfile`:

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install --no-cache-dir -r requirements.txt
RUN chmod -R 777 /app/runtime 2>/dev/null || true
EXPOSE 7860
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "7860"]
```

Spaces gives a permanent public URL (`https://<you>-feefix.hf.space`) — perfect "website link" for the GitHub repo.

## Real OTP delivery — codes to a real inbox / phone

Code sign-in is only as real as the gateway behind it. FeeFix picks the first
configured gateway (or the one you pin with `OTP_EMAIL_PROVIDER` /
`OTP_SMS_PROVIDER`) and sends the 6-digit code there:

| Channel | Gateways (first configured wins) | Cost |
|---|---|---|
| Email | `smtp` (`OTP_SMTP_*`) · `brevo` · `resend` · `webhook` | free tiers exist (Gmail app password, Brevo 300/day, Resend 3 k/month); SES/Postmark/Mailgun ride on `smtp` |
| SMS | `twilio` · `msg91` (India) · `fast2sms` (India) · `vonage` · `webhook` | **never free** — every gateway bills per message |

**With no gateway configured**, outside production the code is written to the
server log + `runtime/otp_outbox.jsonl` and returned as a clearly labelled
**demo** (`dev_code`, a DEMO banner in the UI, `GET /api/auth/otp/dev-inbox`).
In production there is no demo at all: the endpoint answers **503**, the UI
hides that door, and the boot log says so — a code that only exists in a log
is a credential leak, not a fallback.

### 1. Email with Gmail (2 minutes, works for any Gmail address)

1. Google Account → **Security** → 2-Step Verification → **App passwords** →
   create one named "FeeFix" (16 characters; spaces are ignored).
2. Set:

```bash
FEEFIX_ENV=production
FEEFIX_OTP_PEPPER=<32 random characters>     # required once a channel is configured
OTP_SMTP_HOST=smtp.gmail.com
OTP_SMTP_PORT=587                            # STARTTLS; 465 = implicit TLS
OTP_SMTP_USER=you@gmail.com
OTP_SMTP_PASS=abcdefghijklmnop               # the app password, not your account password
OTP_SMTP_FROM=you@gmail.com
```

Gmail caps free sending at ~500 messages/day and rewrites the `From` address to
the account you authenticated as. For volume, use Brevo/Resend/SES instead
(`OTP_BREVO_API_KEY` / `OTP_RESEND_API_KEY` — same code path, HTTPS instead of
SMTP, which also helps on hosts that block outbound port 587).

### 2. SMS in India (MSG91 or Fast2SMS)

Indian transactional SMS needs a **DLT-registered template** on the operator's
registry; the message body must match it. Set the exact registered text as the
template and FeeFix substitutes the code:

```bash
OTP_MSG91_AUTH_KEY=<auth key>
OTP_MSG91_TEMPLATE_ID=<flow template id>
OTP_MSG91_MODE=flow
OTP_SMS_TEMPLATE="{code} is your verification code for FeeFix. Valid for {minutes} minutes."
```

Or the cheapest route, Fast2SMS (Indian numbers only, `+91` enforced):

```bash
OTP_FAST2SMS_KEY=<api key>
OTP_FAST2SMS_ROUTE=q          # quick route; dlt also supported (needs sender + template id)
```

### 3. SMS anywhere else (Twilio / Vonage / your own gateway)

```bash
OTP_TWILIO_SID=<account sid>
OTP_TWILIO_TOKEN=<auth token>
OTP_TWILIO_FROM=+15005550006            # or OTP_TWILIO_MESSAGING_SERVICE_SID
# …or any provider you already have:
OTP_SMS_WEBHOOK_URL=https://your-endpoint/send-sms   # POST {to, code, text}
OTP_SMS_WEBHOOK_TOKEN=<bearer token, optional>
```

Twilio trial accounts can only message **verified** numbers — an unverified
number comes back as `The number is unverified` in the audit log
(`otp.send_failed.phone`), which is the single most common "it doesn't work".

### 4. Prove it works

```bash
python scripts/check_otp_delivery.py --email you@gmail.com
python scripts/check_otp_delivery.py --phone +919876543210
```

It prints which gateway was selected, whether it accepted the message (with the
provider's own error text when it did not), and exits non-zero if nothing real
was sent. `GET /api/health` reports the same facts as `otp_delivery`, which is
the fastest way to answer "did the SMS actually go out?" on a live deployment.

### 5. Limits that protect your bill

| Guard | Default | Env |
|---|---|---|
| Resend cooldown | 40 s | `FEEFIX_OTP_RESEND_S` |
| Codes per destination per hour | 5 | `FEEFIX_OTP_PER_HOUR` |
| Codes per destination per day (SMS-pumping defence) | 10 | `FEEFIX_OTP_DAILY_CAP` |
| Wrong-code attempts before the code burns | 5 | `FEEFIX_OTP_ATTEMPTS` |
| Code lifetime | 300 s | `FEEFIX_OTP_TTL_S` |

Failed sends are **not** counted: if your relay is down the student can try
again immediately instead of being locked out by a cooldown for a message
nobody received.

## Environment knobs

### Must-set in production

| Var | Default | Effect |
|---|---|---|
| `FEEFIX_ENV` | *(unset)* | `production` turns on fail-closed boot guards (see below) |
| `FEEFIX_PASSWORD_ALGO` | `auto` → argon2id in prod | Argon2id is required for new hashes; a production deploy **refuses to start** if `argon2-cffi` is missing rather than silently downgrading to PBKDF2 |
| `FEEFIX_SECRETS_STRICT` | *prod is always strict* | `1` refuses to boot on a placeholder/missing secret outside production too. `FEEFIX_SECRETS_STRICT=0` does **not** let a production deploy on `CHANGE_ME` start |
| `FEEFIX_DB` | `runtime/feefix.db` | SQLite path — point at a **mounted volume**, or every deploy starts empty |
| `FEEFIX_UPLOAD_DIR` | `runtime/uploads` | Uploaded documents — also belongs on the volume, and **not** inside a static mount |
| `FEEFIX_REDIS_URL` | *(unset)* | **Required when `FEEFIX_INSTANCES` > 1.** Without it the process refuses to start — a warning used to keep serving and the limit was `N ×`. One host with several workers shares `FEEFIX_RATELIMIT_DB` (SQLite) instead. `render.yaml` wires a Key Value instance |
| `FEEFIX_TRUST_PROXY` | `0` | `1` when TLS/HTTP terminates in front (Render, Fly, nginx, k8s ingress). Without it every request looks like it came from the proxy and all users share one bucket. The forwarded header is read **rightmost** (the hop your proxy observed), so a client cannot forge its identity |
| `FEEFIX_OTP_PEPPER` | *random file* | 16+ characters. **Required once any delivery channel is configured** — without it each instance/restart gets its own pepper from `runtime/.otp_pepper` and codes stop verifying across them |
| OTP delivery (`OTP_SMTP_*`, `OTP_TWILIO_*`, `OTP_MSG91_*`, …) | *(unset)* | See **Real OTP delivery** above. Unset in production = code sign-in answers 503 and the UI hides it (never a fake code) |

### Rarely needed

| Var | Default | Effect |
|---|---|---|
| `FEEFIX_CORS_ORIGINS` | *(empty)* | Comma-separated origins if you ever split web/API — **keep empty** otherwise |
| `FEEFIX_STORE` | `sqlite` | `json` reverts to the legacy JSON tracker store |
| `FEEFIX_REPLAY_POLICY` | `balanced` | `lenient` (never revoke) / `strict` (revoke the session family on any stale replay — logs users out everywhere, opt in knowingly) |
| `FEEFIX_RATELIMIT_FAIL_MODE` | `auth` | Which buckets fail **closed** when the shared store is down (`auth`, `all`, `none`) |
| `FEEFIX_RATELIMIT_BACKEND` | `auto` | `memory` forces the in-process store (single-worker only) |
| `FEEFIX_MAX_*`, `FEEFIX_MAX_BODY_*` | per-endpoint defaults | Raise/lower a body cap or field length for *your* traffic without a code change; every value is clamped to `FEEFIX_ABSOLUTE_MAX_BODY_BYTES` (16 MB) |
| `FEEFIX_DISABLE_DOCS` / `FEEFIX_ENABLE_DOCS` | *docs on* | Cosmetic only — gates `/docs`, `/redoc`, `/openapi.json`. It hides no endpoint and removes no attack surface, so it is off by default and documented as optical |

### Fail-closed boot

With `FEEFIX_ENV=production` (or `FEEFIX_SECRETS_STRICT=1`) the app refuses to
start when a required secret is missing, still a `CHANGE_ME`-style placeholder,
too short, or unaccompanied by its companion variable (`OTP_SMTP_PASS` without
`OTP_SMTP_USER`, an SMS webhook token without its URL). The error names the
variable and what to fix; `FEEFIX_SECRETS_STRICT=0` downgrades it to a log
warning if you accept the risk knowingly.

A production deploy also **refuses to start with `FEEFIX_OTP_DEV_ECHO=1`** (any
`FEEFIX_OTP_DEV_ECHO*` switch). That flag returns live sign-in codes in API
responses: useful on a laptop, and a way to hand anyone a victim's sign-in code
in production. Production is never allowed to echo a code, flag or not.

## Postgres migration path (when the workload outgrows SQLite)

The store contract (`set_status / board / save_profile / load_profile / board`)
is SQL-shaped by design. Swap `backend/services/sqlite_store.py` for a
`psycopg`-backed module with the same methods and `? → %s` placeholders;
nothing above it changes. DB remains a single connection-string decision.

## Android APK

`mobile/android/` builds in Android Studio (free): opens the same REST API.
For wide distribution without an app store, publish the APK as a **GitHub
Release asset** (free) and link it from the README.
