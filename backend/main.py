"""FeeFix India — FastAPI application entrypoint.

Serves the REST API under ``/api`` and the web experience (static SPA) at
``/``. Run with::

    uvicorn backend.main:app --host 0.0.0.0 --port 8000

One origin, one port — the web app only ever makes relative API calls, so the
deployment is immune to host/origin mismatches behind any proxy.

Boot policy (all of it fail-fast, none of it cosmetic):

* **Interactive docs are ON by default** (``/docs``, ``/redoc``,
  ``/openapi.json``). Skipping them was never a security control: every route
  still answered, so turning the docs off only broke generated clients, QA and
  tooling while looking like hardening. The API surface is protected by auth,
  ownership checks, validation and rate limits — not by hiding it. A deployment
  that genuinely wants them off sets ``FEEFIX_ENABLE_DOCS=0`` (documented as a
  cosmetic switch, not a defence).
* **Secrets are enforced, not just logged** — see ``services/secrets.py``; in
  strict/production mode a placeholder credential aborts startup.
* **Rate-limiter topology is checked** — if the process-local limiter would be
  used with multiple workers/instances, that is reported (and fatal in strict
  mode) instead of silently multiplying every limit.
* **Every request body is capped per endpoint while it streams** — see
  ``services/body_limit.py``.
"""

from __future__ import annotations

import logging
import os
import secrets

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.api.routes import router as api_router
from backend.notifications import (
    ConsoleNotifier,
    NotificationRouter,
    WhatsAppOutboxNotifier,
)
from backend.services import ratelimit
from backend.services.auth import AuthBusy as _AuthBusy
from backend.services.body_limit import BodyLimitMiddleware
from backend.services.dataset import DatasetService
from backend.services.secure_headers import SecurityHeadersMiddleware
from backend.services.sqlite_store import SQLiteStore
from backend.services.tracker import TrackerStore
from backend.services.secrets import enforce_secret_policy, strict_mode, secret_status

log = logging.getLogger("feefix")

WEB_DIR = __import__("pathlib").Path(__file__).resolve().parents[1] / "web" / "frontend"


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


# CORS: the SPA is served same-origin, so cross-origin browser access stays
# CLOSED by default. Deployments that genuinely need it opt in via env var.
_CORS_ORIGINS = [
    o.strip() for o in os.environ.get("FEEFIX_CORS_ORIGINS", "").split(",") if o.strip()
]
_STORE = os.environ.get("FEEFIX_STORE", "sqlite")


def docs_enabled() -> bool:
    """Interactive API docs: on unless explicitly disabled.

    ``FEEFIX_ENABLE_DOCS`` is still honoured (``0``/``false`` disables), and
    ``FEEFIX_DISABLE_DOCS=1`` is the explicit off-switch. Disabling is a
    cosmetic choice: it removes no endpoint and no attack surface.
    """
    raw = os.environ.get("FEEFIX_ENABLE_DOCS")
    if raw is not None and raw.strip():
        return raw.strip().lower() in ("1", "true", "yes", "on")
    return not _env_flag("FEEFIX_DISABLE_DOCS")


def _check_boot_policy() -> None:
    """Enforce secrets + limiter topology before the app starts serving."""
    enforce_secret_policy()  # raises in strict/production mode

    warnings = ratelimit.topology_warnings()
    for warning in warnings:
        log.error("[ratelimit] topology: %s", warning)
    if warnings and strict_mode():
        raise RuntimeError(
            "Refusing to start: rate-limiter topology is unsafe "
            f"({'; '.join(warnings)}). Set FEEFIX_REDIS_URL, or "
            "FEEFIX_STRICT_SECRETS=0 to run without enforcement."
        )
    status = secret_status()
    from backend.services import auth as auth_svc

    log.info(
        "[feefix] boot: hashing=%s, rate-limit store=%s (shared=%s), secrets=%s",
        auth_svc.hash_backend_note(),
        ratelimit.describe()["backend"],
        ratelimit.describe()["shared_across_processes"],
        "strict" if status["strict"] else "advisory",
    )


def create_app() -> FastAPI:
    show_docs = docs_enabled()
    app = FastAPI(
        title="FeeFix India",
        version="1.2.0",
        description=(
            "Personalized scholarship & fee-waiver matching platform for "
            "Indian students — discover, understand, apply, track.\n\n"
            "Interactive docs are enabled by default: they are a client/QA "
            "contract, not an attack surface (set `FEEFIX_ENABLE_DOCS=0` to "
            "hide them). Every response is JSON; every request body is capped "
            "per endpoint (`GET /api/health` reports the effective limits)."
        ),
        docs_url="/docs" if show_docs else None,
        redoc_url="/redoc" if show_docs else None,
        openapi_url="/openapi.json" if show_docs else None,
        openapi_tags=[
            {"name": "meta", "description": "Health, capabilities and limits"},
            {"name": "auth", "description": "Accounts, sessions, OTP, OAuth"},
            {"name": "schemes", "description": "Scholarship catalogue"},
            {"name": "matching", "description": "Eligibility matching"},
            {"name": "students", "description": "Profiles and documents"},
            {"name": "tracker", "description": "Application tracking"},
            {"name": "ai", "description": "Semantic search, Q&A, chat"},
        ],
    )

    if _CORS_ORIGINS:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=_CORS_ORIGINS,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    _check_boot_policy()

    # --- security middleware (outermost wins) -------------------------------- #
    # Body cap is added last so it is the outermost layer: an oversized body is
    # rejected before auth, rate limiting and parsing ever run, and it can wrap
    # the receive channel to bound chunked/unknown-length requests too.
    app.add_middleware(SecurityHeadersMiddleware)

    from starlette.middleware.base import BaseHTTPMiddleware

    class _SessionMiddleware(BaseHTTPMiddleware):
        """Resolve the bearer session once per request and rotate aged tokens.

        Anti-replay: a token in continuous use for more than a day is silently
        rotated and the fresh token handed back in ``X-Session-Token``. A
        *detected replay* surfaces as ``X-Session-Warning`` so the client can
        prompt a re-login rather than being mysteriously logged out.
        """

        async def dispatch(self, request: Request, call_next):
            from backend.services import auth as auth_svc

            header = request.headers.get("authorization", "")
            token = header[7:].strip() if header.lower().startswith("bearer ") else None
            user, new_token, warning = auth_svc.resolve_and_rotate(
                token, client=ratelimit.client_ip(request)
            )
            request.state.user = user
            # One resolution per request: without this flag a handler that needs
            # the user would resolve the token a second time, which double-counts
            # security events (a replay would look like two replays) and doubles
            # the session lookup cost.
            request.state.session_resolved = True
            response = await call_next(request)
            if new_token:
                response.headers["X-Session-Token"] = new_token
            if warning:
                response.headers["X-Session-Warning"] = warning
            return response

    app.add_middleware(_SessionMiddleware)

    class _RateLimitMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Request, call_next):
            path = request.url.path
            if path.startswith("/api/") and path != "/api/health":
                client = ratelimit.client_ip(request)
                bucket = "global"
                if path.startswith(ratelimit.EXPENSIVE_PATHS):
                    bucket = "expensive"
                allowed = (
                    ratelimit.check_expensive(client, bucket)
                    if bucket == "expensive"
                    else ratelimit.check_global(client)
                )
                if not allowed:
                    return JSONResponse(
                        status_code=429,
                        content={"detail": "Too many requests — slow down."},
                        headers={
                            "Retry-After": str(ratelimit.retry_after(client, bucket)),
                            "X-RateLimit-Scope": bucket,
                        },
                    )
            return await call_next(request)

    app.add_middleware(_RateLimitMiddleware)
    app.add_middleware(BodyLimitMiddleware)

    # Application state — hardened SQLite store by default (WAL, FKs,
    # parameterized); FEEFIX_STORE=json keeps the legacy JSON store.
    dataset = DatasetService()
    dataset.load()
    app.state.dataset = dataset
    app.state.tracker = SQLiteStore() if _STORE == "sqlite" else TrackerStore()
    app.state.store_kind = _STORE
    app.state.notifier = NotificationRouter(
        [ConsoleNotifier(), WhatsAppOutboxNotifier()]
    )
    app.state.docs_enabled = show_docs

    # AI layer — free, local embeddings + grounded Q&A (never a paid API).
    from ai.qa import QaEngine

    app.state.qa = QaEngine(dataset)

    @app.exception_handler(_AuthBusy)
    async def _busy_handler(request: Request, exc: Exception) -> JSONResponse:
        """Back-pressure from the bounded KDF pool → retryable 503 (never a 500)."""
        return JSONResponse(
            status_code=503,
            content={"detail": "Service is busy — please retry shortly."},
            headers={"Retry-After": "2"},
        )

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):  # pragma: no cover - safety net
        # Log the real error + stack server-side; the client gets only an opaque
        # message and a correlation id — never a class name, message or trace.
        request_id = secrets.token_hex(8)
        log.exception("unhandled error [request_id=%s] %s", request_id, request.url.path)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error.", "request_id": request_id},
        )

    app.include_router(api_router)

    if WEB_DIR.exists():
        app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")

    return app


app = create_app()
