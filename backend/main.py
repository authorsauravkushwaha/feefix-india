"""FeeFix India — FastAPI application entrypoint.

Serves the REST API under ``/api`` and the web experience (static SPA) at
``/``. Run with::

    uvicorn backend.main:app --host 0.0.0.0 --port 8000

One origin, one port — the web app only ever makes relative API calls, so the
deployment is immune to host/origin mismatches behind any proxy.

Boot sequence (fail *loudly* before serving, never halfway):

1. password-hashing policy is resolved (Argon2id; a production deployment that
   demands Argon2id and lacks ``argon2-cffi`` refuses to start),
2. secret hygiene is enforced (placeholders block a strict/production boot),
3. the rate-limit store is selected and checked against the detected topology
   (multi-worker without a shared store is reported as an error, not ignored).
"""

from __future__ import annotations

import logging
import os
import secrets

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.api.responses import SafeJSONResponse, sanitize_for_json
from backend.api.routes import router as api_router
from backend.notifications import (
    ConsoleNotifier,
    NotificationRouter,
    WhatsAppOutboxNotifier,
)
from backend.services import ratelimit
from backend.services.dataset import DatasetService
from backend.services.middleware import RateLimitMiddleware, SessionMiddleware
from backend.services.request_limits import (
    BodyLimitMiddleware,
    BodyTooLarge,
    payload_too_large_handler,
)
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


def docs_enabled() -> bool:
    """Interactive docs are **on by default**.

    Turning them off never removed a single endpoint: ``/api/...`` answers with
    or without ``/docs``, so the "security" was optical — while breaking
    Swagger/ReDoc, generated clients and QA tooling. The switch is kept only for
    operators who genuinely want a documentation-free surface, and it is honest
    about being cosmetic.

    * ``FEEFIX_ENABLE_DOCS=0`` (or any falsy value) → off
    * ``FEEFIX_DISABLE_DOCS=1`` → off (alias)
    * anything else, or unset → on
    """
    explicit = os.environ.get("FEEFIX_ENABLE_DOCS")
    if explicit is not None:
        return explicit.strip().lower() not in ("0", "false", "no", "off", "")
    if os.environ.get("FEEFIX_DISABLE_DOCS", "").strip().lower() in ("1", "true", "yes", "on"):
        return False
    return True


def _boot_guards() -> dict:
    """Resolve security policy before the app starts serving traffic."""
    from backend.services import passwords
    from backend.services.secrets import enforce_secret_hygiene

    # (1) Password hashing: raises if the deployment demands Argon2id and the
    #     library is missing — a silent downgrade is the one outcome we refuse.
    hashing = passwords.describe()
    if hashing.get("algorithm") == "unavailable":  # pragma: no cover - misconfig
        raise RuntimeError(hashing.get("error", "password hashing unavailable"))
    log.info("[boot] password hashing: %s", hashing)
    if hashing["algorithm"] != "argon2id":
        log.warning(
            "[boot] password hashing is %s — install argon2-cffi (or set"
            " FEEFIX_PASSWORD_ALGO=argon2id) for memory-hard hashing.",
            hashing["algorithm"],
        )

    # (2) Secrets: warn by default, refuse to boot when strict (the default in
    #     production). A deploy still on CHANGE_ME is a deployment error.
    findings = enforce_secret_hygiene()
    for finding in findings:
        log.warning("[secrets] %s", finding)

    # (3) Rate limiting: pick the store and be explicit about scaling reality.
    store = ratelimit.configure()
    warning = ratelimit.warn_if_not_distributed()
    return {"password_hashing": hashing, "rate_limit": store.status(), "rate_limit_warning": warning}


def create_app() -> FastAPI:
    boot = _boot_guards()
    enable_docs = docs_enabled()

    app = FastAPI(
        title="FeeFix India",
        version="1.2.0",
        # Never 500 while *rendering* a response, whatever a client sent.
        default_response_class=SafeJSONResponse,
        description=(
            "Personalized scholarship & fee-waiver matching platform for "
            "Indian students — discover, understand, apply, track."
        ),
        docs_url="/docs" if enable_docs else None,
        redoc_url="/redoc" if enable_docs else None,
        openapi_url="/openapi.json" if enable_docs else None,
    )
    app.state.boot = boot
    app.state.docs_enabled = enable_docs

    if _CORS_ORIGINS:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=_CORS_ORIGINS,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # --- middlewares (last added = outermost) ---------------------------------
    # Order from inside out: CORS → body limits → rate limit → session →
    # security headers. Headers wrap everything, so even a 413/429/500 carries
    # them.
    app.add_middleware(BodyLimitMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(SessionMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)

    # A body that overruns its endpoint policy mid-stream → 413 (not 500).
    app.add_exception_handler(BodyTooLarge, payload_too_large_handler)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        """Validation errors, rendered safely.

        FastAPI's default handler echoes the offending input back; a lone
        surrogate in that input used to make the *error response* itself
        un-encodable (a client-triggered 500). Sanitising the values and using
        the encoding-safe response class keeps the failure a clean 422.
        """
        from fastapi.encoders import jsonable_encoder

        errors = sanitize_for_json(jsonable_encoder(exc.errors()))
        return SafeJSONResponse(status_code=422, content={"detail": errors})

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
