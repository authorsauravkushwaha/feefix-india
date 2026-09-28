"""FeeFix India — FastAPI application entrypoint.

Serves the REST API under ``/api`` and the web experience (static SPA) at
``/``. Run with::

    uvicorn backend.main:app --host 0.0.0.0 --port 8000

One origin, one port — the web app only ever makes relative API calls, so the
deployment is immune to host/origin mismatches behind any proxy.
"""

from __future__ import annotations

import os

from fastapi import FastAPI
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
from backend.services.secure_headers import SecurityHeadersMiddleware
from backend.services.sqlite_store import SQLiteStore
from backend.services.tracker import TrackerStore

WEB_DIR = __import__("pathlib").Path(__file__).resolve().parents[1] / "web" / "frontend"

# CORS: the SPA is served same-origin, so cross-origin browser access stays
# CLOSED by default. Deployments that genuinely need it opt in via env var.
_CORS_ORIGINS = [
    o.strip() for o in os.environ.get("FEEFIX_CORS_ORIGINS", "").split(",") if o.strip()
]
_STORE = os.environ.get("FEEFIX_STORE", "sqlite")


def create_app() -> FastAPI:
    app = FastAPI(
        title="FeeFix India",
        version="1.1.0",
        description=(
            "Personalized scholarship & fee-waiver matching platform for "
            "Indian students — discover, understand, apply, track."
        ),
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

    class _RateLimitMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request, call_next):
            if request.url.path.startswith("/api/"):
                client = request.client.host if request.client else "unknown"
                if not ratelimit.check_global(client):
                    return JSONResponse(
                        status_code=429, content={"detail": "Too many requests — slow down."}
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

    @app.exception_handler(Exception)
    async def unhandled(request, exc):  # pragma: no cover - safety net
        return JSONResponse(
            status_code=500,
            content={"detail": f"Internal error: {exc.__class__.__name__}"},
        )

    app.include_router(api_router)

    if WEB_DIR.exists():
        app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")

    return app


app = create_app()
