"""FeeFix India — FastAPI application entrypoint.

Serves the REST API under ``/api`` and the web experience (static SPA) at
``/``. Run with::

    uvicorn backend.main:app --host 0.0.0.0 --port 8000

One origin, one port — the web app only ever makes relative API calls, so the
deployment is immune to host/origin mismatches behind any proxy.
"""

from __future__ import annotations

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
from backend.services.dataset import DatasetService
from backend.services.tracker import TrackerStore

WEB_DIR = __import__("pathlib").Path(__file__).resolve().parents[1] / "web" / "frontend"


def create_app() -> FastAPI:
    app = FastAPI(
        title="FeeFix India",
        version="1.0.0",
        description=(
            "Personalized scholarship & fee-waiver matching platform for "
            "Indian students — discover, understand, apply, track."
        ),
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Application state (swap fasteners for real infra in production).
    dataset = DatasetService()
    dataset.load()
    app.state.dataset = dataset
    app.state.tracker = TrackerStore()
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
