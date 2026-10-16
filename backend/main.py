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
from backend.services.auth import AuthBusy as _AuthBusy
from backend.services.body_limit import BodyLimitMiddleware
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
    """Interactive docs are **on by default**.

    Turning them off never removed a single endpoint: ``/api/...`` answers with
    or without ``/docs``, so the "security" was optical — while breaking
    Swagger/ReDoc, generated clients and QA tooling. The switch is kept only for
    operators who genuinely want a documentation-free surface, and it is honest
    about being cosmetic.

    * ``FEEFIX_ENABLE_DOCS=0`` (or any falsy value) → interactive docs off
    * ``FEEFIX_DISABLE_DOCS=1`` → interactive docs off (alias)
    * anything else, or unset → on

    ``/openapi.json`` is not part of this switch. Hiding the schema breaks
    generated clients and removes no route. See :func:`openapi_enabled`.
    """
    explicit = os.environ.get("FEEFIX_ENABLE_DOCS")
    if explicit is not None:
        return explicit.strip().lower() not in ("0", "false", "no", "off", "")
    if os.environ.get("FEEFIX_DISABLE_DOCS", "").strip().lower() in ("1", "true", "yes", "on"):
        return False
    return True


def openapi_enabled() -> bool:
    """The machine-readable schema is always served.

    Turning ``/openapi.json`` off was grouped with ``/docs`` and sold as
    hardening. It is not: every route still answers, and generated clients,
    contract tests and QA lose the only description of those routes. There is
    no switch. Interactive docs remain optional; the schema does not.
    """
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

    # Branch's policy layer on top: companion half-configs and the operator's
    # explicit FEEFIX_REQUIRED_SECRETS list get the same strictness teeth.
    enforce_secret_policy()

    # (3) Rate limiting: pick the store from the environment (not a stale
    #     earlier choice) and refuse a topology the store cannot actually limit.
    store = ratelimit.configure(force=True)
    warning = ratelimit.warn_if_not_distributed()
    for topo in ratelimit.topology_warnings():
        log.error("[ratelimit] topology: %s", topo)
    if ratelimit.topology_warnings() and strict_mode():
        raise RuntimeError(
            "Refusing to start: rate-limiter topology is unsafe ("
            + "; ".join(ratelimit.topology_warnings())
            + "). Set FEEFIX_REDIS_URL, or FEEFIX_STRICT_SECRETS=0 to run without enforcement."
        )
    from backend.services import auth as _auth

    log.info(
        "[feefix] boot: hashing=%s, rate-limit store=%s (shared=%s), secrets=%s",
        _auth.hash_backend_note(),
        ratelimit.describe()["backend"],
        ratelimit.describe()["shared_across_processes"],
        "strict" if strict_mode() else "advisory",
    )

    # (4) OTP delivery: say out loud which gateway carries sign-in codes, and
    #     whether this deployment is handing them out as a labelled demo. The
    #     one outcome that must never be silent is "codes are not really sent".
    from backend.services import otp as otp_svc

    delivery = otp_svc.delivery_report()
    log.info("[boot] otp delivery: %s", delivery)

    return {
        "password_hashing": hashing,
        "rate_limit": store.status(),
        "rate_limit_warning": warning,
        "otp_delivery": delivery,
    }


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
            "Indian students — discover, understand, apply, track.\n\n"
            "Interactive docs are enabled by default: they are a client/QA "
            "contract, not an attack surface (set `FEEFIX_ENABLE_DOCS=0` to "
            "hide them). Every response is JSON; every request body is capped "
            "per endpoint (`GET /api/health` reports the effective limits)."
        ),
        docs_url="/docs" if enable_docs else None,
        redoc_url="/redoc" if enable_docs else None,
        # Always. Hiding this does not remove an endpoint.
        openapi_url="/openapi.json",
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
    # SessionMiddleware resolves the bearer once per request and hands
    # back `X-Session-Token` (rotation/heal) and `X-Session-Warning`
    # (detected replay) so the UI can prompt a re-login instead of being
    # mysteriously logged out. See services/middleware.py.

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
    app.state.docs_enabled = enable_docs

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

    # The upload gate is not a library sitting unused: if the routes are gone,
    # the process does not start. A test that greps source can be deleted; this
    # cannot be skipped without deleting the boot check.
    from backend.services.uploads import assert_routes_wired

    assert_routes_wired(app.openapi()["paths"])

    if WEB_DIR.exists():
        app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")

    return app


app = create_app()
