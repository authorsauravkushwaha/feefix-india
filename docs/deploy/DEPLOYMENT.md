# Deploy FeeFix free — phone-accessible in minutes

FeeFix is deliberately **one origin, one port, one process**: a single FastAPI
app serves the REST API *and* the web experience. That means any free tier
that can run Python can host the whole product, and the URL you get works
immediately in any phone browser (add-to-home-screen = instant "app").

## Prerequisite

```bash
./scripts/dev.sh --test   # 323 tests green locally
python scripts/secret_scan.py   # no secrets in tracked content
```

---

## Option A — Render (free web service)

1. Push this repo to GitHub (it renders native `web.StaticFiles`, no build step).
2. Render dashboard → **New +** → **Blueprint** → connect the repo. Render reads
   the committed [`render.yaml`](../../render.yaml) and provisions the service,
   the disk and every environment variable in one step.

   > **Use the blueprint, not a hand-configured Web Service.** The blueprint is
   > parsed by CI, so the build command, start command, health check and security
   > variables cannot drift from what the code expects. Setting them by hand is
   > how `FEEFIX_ENV` ends up unset and `FEEFIX_TRUSTED_PROXIES` ends up as a
   > wildcard.

3. Render will prompt for the **11 secrets** — every one is declared
   `sync: false` precisely so it is never committed to the blueprint. Generate the
   OTP pepper with:

   ```bash
   python -c "import secrets; print(secrets.token_hex(32))"
   ```

4. The disk is mounted at `/opt/render/project/src/runtime` so `runtime/feefix.db`
   (accounts, tracker, outcome events) survives restarts.
5. Free tier sleeps when idle — first visit takes ~30s, then it's instant. The
   configured `healthCheckPath` is `/api/health`, which returns counts only and
   no configuration.
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

* Create a Space → **Docker** → point at this repo. It uses the committed
  [`Dockerfile`](../../Dockerfile) as-is; no Space-specific variant is needed.

Spaces gives a permanent public URL (`https://<you>-feefix.hf.space`) — perfect
"website link" for the GitHub repo.

> **Do not write a Space-specific Dockerfile.** An earlier draft of these docs
> suggested `RUN chmod -R 777 /app/runtime`, which makes the SQLite database
> **and the generated OTP pepper** world-writable and world-readable inside the
> container. Any code-execution foothold — or any other process in the image —
> could then read live OTP codes. The committed Dockerfile creates `runtime/`
> at **0700**, owned by an unprivileged `feefix` user (uid 10001, no shell),
> and leaves the application tree root-owned and read-only to that user.

### What the container image does

| Property | Why |
|---|---|
| Non-root `feefix` uid/gid 10001, `nologin`, `--no-create-home` | Code execution as root inside a container is one runtime bug away from the host |
| `runtime/` at **0700**, chowned | Holds the database and the OTP pepper |
| App tree root-owned **644/755** | A foothold cannot also modify the application on disk |
| `PYTHONDONTWRITEBYTECODE=1` | A writable `.pyc` is a persistence mechanism |
| `.dockerignore` excludes `.env`, `runtime/`, `secrets/`, key material | Credentials baked into a layer are pushed to the registry and are **permanent**, even if a later layer deletes them |
| `HEALTHCHECK --fail-critical` on `/api/health` | An orchestrator restarts a wedged process instead of routing traffic to it |
| uvicorn `--limit-concurrency 200 --limit-max-requests 10000 --timeout-keep-alive 5 --no-server-header` | Slowloris mitigation, worker recycling, and no version banner to fingerprint |

## Environment knobs

Every variable is optional and **fail-closed**: leaving one unset produces the
stricter behaviour, never the more convenient one. The annotated template is
[`.env.example`](../../.env.example); the full rationale is in
[`docs/security/HARDENING.md`](../security/HARDENING.md#configuration-reference).

### Core

| Var | Default | Effect |
|---|---|---|
| `FEEFIX_ENV` | **`production`** | `production` \| `staging` \| `development` \| `test`. **Unset means production** — forgetting to configure must never relax security |
| `FEEFIX_DB` | `runtime/feefix.db` | SQLite path — point at a mounted volume in prod |
| `FEEFIX_STORE` | `sqlite` | `json` reverts to the legacy JSON tracker store |
| `FEEFIX_CORS_ORIGINS` | *(empty)* | Comma-separated origins if you ever split web/API — **keep empty** otherwise. A wildcard is refused outright and cannot be combined with credentials |
| `FEEFIX_BASE_URL` | *(unset)* | Public origin, used for links in notifications |

### Secrets — set these in the platform's secret store, never in a file

| Var | Purpose |
|---|---|
| `FEEFIX_OTP_PEPPER` | ≥32 bytes. If unset, one is generated at `runtime/.otp_pepper` (mode 0600) — **which does not survive an ephemeral filesystem**, so set it explicitly anywhere `runtime/` is not a mounted volume. A short value is *refused* in production |
| `OTP_SMTP_HOST` / `PORT` / `USER` / `PASS` / `FROM` / `TIMEOUT_S` | Email OTP delivery. Unset in production ⇒ the channel reports unavailable and requests return 422 rather than echoing a code |
| `OTP_TWILIO_SID` / `TOKEN` / `FROM` | SMS OTP. `SID` must match `^AC[A-Za-z0-9]{16,40}$` |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | OAuth handoff |

### Security behaviour

| Var | Default | Effect |
|---|---|---|
| `FEEFIX_ANTI_REPLAY` | **`enforce`** | Nonce + timestamp required on every mutation ⇒ 409 on replay. `off` is **refused in production** unless `FEEFIX_I_ACCEPT_REPLAY_RISK=1` is also set |
| `FEEFIX_I_ACCEPT_REPLAY_RISK` | *(unset)* | The second switch required to disable replay defence in production. Named so it survives code review |
| `FEEFIX_BIND_CLIENT` | *(unset)* | Set to `1` to revoke a session token replayed from a different user agent — including the legitimate session |
| `FEEFIX_DEV_OTP_ECHO` | *(unset)* | Second switch for the development OTP echo. Requires a non-production env **and** this flag. **Never set on a host serving real users** |
| `FEEFIX_TRUST_PROXY_PEER` | *(unset)* | Set to `1` when the platform proxy is the only reachable peer, so `X-Forwarded-For` is honoured. **Prefer this over a wildcard CIDR** |
| `FEEFIX_TRUSTED_PROXIES` | *(empty)* | CIDR list of peers whose `X-Forwarded-For` is honoured. Empty ⇒ the header is **ignored**, so anyone can rotate it without walking past the per-IP limits |
| `FEEFIX_PROXY_HOPS` | `1` | Entries to trust from the right of `X-Forwarded-For`. `1` ⇒ a client-forged value to the left is not believed |

> **`FEEFIX_TRUSTED_PROXIES=0.0.0.0/0` is a footgun.** On Render it is
> *functionally correct* — the platform proxy is the only reachable peer — and
> catastrophic if copy-pasted into a directly-exposed deployment, where it lets
> any client forge `X-Forwarded-For` and bypass every per-IP limit. Use
> `FEEFIX_TRUST_PROXY_PEER=1` so the assumption is named and auditable. CI
> asserts the wildcard is never in `render.yaml`.

## Postgres migration path (when the workload outgrows SQLite)

The store contract (`set_status / board / save_profile / load_profile / board`)
is SQL-shaped by design. Swap `backend/services/sqlite_store.py` for a
`psycopg`-backed module with the same methods and `? → %s` placeholders;
nothing above it changes. DB remains a single connection-string decision.

## Android APK

`mobile/android/` builds in Android Studio (free): opens the same REST API.
For wide distribution without an app store, publish the APK as a **GitHub
Release asset** (free) and link it from the README.

Before a public release:

1. **Populate the certificate pins.** `FeeFixApi(certificatePins = …)` ships
   empty. Add **two** SHA-256 SPKI pins — a primary and a backup — because a
   single pin that cannot be rotated turns a certificate renewal into an app
   that cannot reach its own backend. Mirror them in
   `res/xml/network_security_config.xml`; the checklist is in
   [`mobile/android/README.md`](../../mobile/android/README.md#security).
2. **Point it at the production `https://` origin.** The constructor refuses
   anything else, in code rather than via the manifest.
3. **Implement `TokenStore` with EncryptedSharedPreferences**
   (`androidx.security.crypto`). Plain `SharedPreferences` puts the bearer token
   in a device backup in cleartext.
4. Set the base URL from `BuildConfig`, never from a user-editable field — an
   editable API host is an account-takeover feature.
