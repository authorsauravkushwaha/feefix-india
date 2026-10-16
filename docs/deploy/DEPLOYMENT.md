# Deploy FeeFix free — phone-accessible in minutes

FeeFix is deliberately **one origin, one port, one process**: a single FastAPI
app serves the REST API *and* the web experience. That means any free tier
that can run Python can host the whole product, and the URL you get works
immediately in any phone browser (add-to-home-screen = instant "app").

## Prerequisite

```bash
./scripts/dev.sh --test   # full suite green locally
```

---

## Option A — Render (free web service)

1. Push this repo to GitHub (it renders native `web.StaticFiles`, no build step).
2. Render dashboard → **New Web Service** → connect the repo.
3. Settings:
   * **Build command**: `pip install -r requirements.txt`
   * **Start command**: `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`
4. Add a **Render Disk** (1 GB free) mounted at `/opt/render/project/src/runtime`
   so `runtime/feefix.db` (accounts, tracker, outcome events, rate-limit
   counters, uploaded documents) survives restarts.
5. Environment variables worth setting in production:

   | Variable | Why |
   |---|---|
   | `FEEFIX_TRUSTED_PROXY_COUNT=1` | Render terminates TLS in front of the app, so the real client IP is the *rightmost* `X-Forwarded-For` entry — required for correct rate limiting (and never spoofable). |
   | `FEEFIX_STRICT_SECRETS=1` | Fail startup on placeholder/half-configured secrets instead of warning. Production markers (`RENDER`, `FLY_APP_NAME`, `K_SERVICE`) already enable strict mode automatically. |
   | `FEEFIX_REDIS_URL` | Only for **more than one instance**: the sqlite limiter shares counters across worker processes on one host, but a multi-instance deployment needs Redis to keep one limit. |
   | `FEEFIX_DB` | Point the SQLite file at the mounted disk. |
   | `FEEFIX_UPLOAD_DIR` | Where uploaded documents live (default `runtime/uploads`, on the disk). |
   | `FEEFIX_AI_BACKEND=ngram` | Skip the neural-model download on a tiny/free instance (faster boots, no egress). |

   The app logs its effective configuration at boot
   (`hashing=…, rate-limit store=…, secrets=strict|advisory`) and reports it on
   `GET /api/health` — verify rather than assume.
5. Free tier sleeps when idle — first visit takes ~30s, then it's instant.
6. Set the service URL as the repo's **Website** link on GitHub.

> **Workers and the rate limiter.** The limiter's default store is the app's
> SQLite file, so `--workers 4` on one host still enforces one shared limit
> (verified by tests that spawn real processes). Horizontal scaling to multiple
> instances needs `FEEFIX_REDIS_URL`; without it, `services/ratelimit.py` logs a
> loud topology warning at boot (and refuses to start in strict mode) rather
> than silently multiplying every limit by the number of replicas.

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

| Var | Default | Effect |
|---|---|---|
| `FEEFIX_DB` | `runtime/feefix.db` | SQLite path — point at a mounted volume in prod |
| `FEEFIX_STORE` | `sqlite` | `json` reverts to the legacy JSON tracker store |
| `FEEFIX_CORS_ORIGINS` | *(empty)* | Comma-separated origins if you ever split web/API — **keep empty** otherwise |

## Postgres migration path (when the workload outgrows SQLite)

The store contract (`set_status / board / save_profile / load_profile / board`)
is SQL-shaped by design. Swap `backend/services/sqlite_store.py` for a
`psycopg`-backed module with the same methods and `? → %s` placeholders;
nothing above it changes. DB remains a single connection-string decision.

## Android APK

`mobile/android/` builds in Android Studio (free): opens the same REST API.
For wide distribution without an app store, publish the APK as a **GitHub
Release asset** (free) and link it from the README.
