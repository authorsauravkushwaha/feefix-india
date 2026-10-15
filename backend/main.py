"""FeeFix India — FastAPI application entrypoint.

Serves the REST API under ``/api`` and the web experience (static SPA) at
``/``. Run with::

    uvicorn backend.main:app --host 0.0.0.0 --port 8000

One origin, one port — the web app only ever makes relative API calls, so the
deployment is immune to host/origin mismatches behind any proxy.
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
from backend.services.dataset import DatasetService
from backend.services.limits import MAX_BODY_BYTES
from backend.services.secure_headers import SecurityHeadersMiddleware
from backend.services.sqlite_store import SQLiteStore
from backend.services.tracker import TrackerStore

log = logging.getLogger("feefix")

WEB_DIR = __import__("pathlib").Path(__file__).resolve().parents[1] / "web" / "frontend"

# CORS: the SPA is served same-origin, so cross-origin browser access stays
# CLOSED by default. Deployments that genuinely need it opt in via env var.
_CORS_ORIGINS = [
    o.strip() for o in os.environ.get("FEEFIX_CORS_ORIGINS", "").split(",") if o.strip()
]
_STORE = os.environ.get("FEEFIX_STORE", "sqlite")
# Interactive API docs (Swagger / ReDoc / openapi.json) expose the full API
# surface — handy in development, pure attack-surface in production. Off unless
# explicitly enabled.
_ENABLE_DOCS = os.environ.get("FEEFIX_ENABLE_DOCS", "").lower() in ("1", "true", "yes", "on")


def create_app() -> FastAPI:
    app = FastAPI(
        title="FeeFix India",
        version="1.1.0",
        description=(
            "Personalized scholarship & fee-waiver matching platform for "
            "Indian students — discover, understand, apply, track."
        ),
        docs_url="/docs" if _ENABLE_DOCS else None,
        redoc_url="/redoc" if _ENABLE_DOCS else None,
        openapi_url="/openapi.json" if _ENABLE_DOCS else None,
    )

    if _CORS_ORIGINS:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=_CORS_ORIGINS,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # --- security middleware (outermost wins) --------------------------------
    app.add_middleware(SecurityHeadersMiddleware)

    from starlette.middleware.base import BaseHTTPMiddleware

    class _BodyLimitMiddleware(BaseHTTPMiddleware):
        """Reject oversized request bodies before any handler parses them.

        A giant-payload / long-password flood never reaches PBKDF2, a regex, or
        the JSON parser. Clients that stream without a Content-Length are still
        bounded by the per-field length caps in the pydantic schemas.
        """

        async def dispatch(self, request: Request, call_next):
            if request.method in ("POST", "PUT", "PATCH"):
                raw = request.headers.get("content-length")
                if raw and raw.isdigit() and int(raw) > MAX_BODY_BYTES:
                    return JSONResponse(
                        status_code=413,
                        content={"detail": "Payload too large."},
                    )
            return await call_next(request)

    app.add_middleware(_BodyLimitMiddleware)

    class _SessionMiddleware(BaseHTTPMiddleware):
        """Resolve the bearer session once per request and rotate aged tokens.

        Anti-replay: a token in continuous use for more than a day is silently
        rotated and the fresh token handed back in ``X-Session-Token``. The
        resolved user is cached on ``request.state`` so the whole request shares
        one lookup (and one rotation decision).
        """

        async def dispatch(self, request: Request, call_next):
            from backend.services import auth as auth_svc

            header = request.headers.get("authorization", "")
            token = header[7:].strip() if header.lower().startswith("bearer ") else None
            user, new_token = auth_svc.resolve_and_rotate(token)
            request.state.user = user
            response = await call_next(request)
            if new_token:
                response.headers["X-Session-Token"] = new_token
            return response

    app.add_middleware(_SessionMiddleware)

    class _RateLimitMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            path = request.url.path
            if path.startswith("/api/"):
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
                        headers={"Retry-After": str(ratelimit.retry_after(client, "global"))},
                    )
            return await call_next(request)

    app.add_middleware(_RateLimitMiddleware)

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

    # AI layer — free, local embeddings + grounded Q&A (never a paid API).
    from ai.qa import QaEngine

    app.state.qa = QaEngine(dataset)

    # Warn (never crash) if a configured secret looks like a placeholder.
    from backend.services.secrets import weak_secret_findings

    for _finding in weak_secret_findings():
        log.warning("[secrets] %s", _finding)

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
