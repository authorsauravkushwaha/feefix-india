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
`OTP_SMTP_USER`, a Stripe secret without its publishable key). The error names
the variable and what to fix; `FEEFIX_SECRETS_STRICT=0` downgrades it to a log
warning if you accept the risk knowingly.

## Postgres migration path (when the workload outgrows SQLite)

The store contract (`set_status / board / save_profile / load_profile / board`)
is SQL-shaped by design. Swap `backend/services/sqlite_store.py` for a
`psycopg`-backed module with the same methods and `? → %s` placeholders;
nothing above it changes. DB remains a single connection-string decision.

## Android APK

`mobile/android/` builds in Android Studio (free): opens the same REST API.
For wide distribution without an app store, publish the APK as a **GitHub
Release asset** (free) and link it from the README.
