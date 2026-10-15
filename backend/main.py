"""FeeFix India — FastAPI application entrypoint.

Serves the REST API under ``/api`` and the web experience (static SPA) at
``/``. Run with::

    uvicorn backend.main:app --host 0.0.0.0 --port 8000

One origin, one port — the web app only ever makes relative API calls, so the
deployment is immune to host/origin mismatches behind any proxy.

MIDDLEWARE ORDER (outermost first)
==================================
Starlette runs middleware in *reverse* registration order, so the last
``add_middleware`` call is the outermost layer. The ordering below is a security
property, not a style choice:

1. :class:`SecurityHeadersMiddleware` — outermost, so a rejection produced by
   any inner layer still carries the CSP, HSTS and nosniff headers. A 429
   without a CSP is a 429 that can be framed or sniffed.
2. :class:`RequestShield` — body-size ceiling, method allow-list, client-IP
   resolution, global rate limit and anti-replay. Everything expensive sits
   *inside* this, so a hostile request is rejected before it costs anything.
3. CORS — innermost of the three, and only present when explicitly configured.
4. Application routes.

ERROR HANDLING
==============
One exception handler, one response shape, no internals. The previous handler
returned ``f"Internal error: {exc.__class__.__name__}"``, which is information
leakage: a class name tells an attacker which subsystem failed
(``OperationalError`` → database, ``SMTPAuthenticationError`` → mail
credentials, ``FileNotFoundError`` → a path the server cares about), and that
is exactly the feedback used to pick the next payload. Clients now receive a
constant sentence; the real cause is written to the audit log, redacted.
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from backend.api.routes import router as api_router
from backend.notifications import (
    ConsoleNotifier,
    NotificationRouter,
    WhatsAppOutboxNotifier,
)
from backend.services import security
from backend.services.dataset import DatasetService
from backend.services.request_shield import RequestShield, log_unexpected, public_error_body
from backend.services.secure_headers import SecurityHeadersMiddleware
from backend.services.sqlite_store import SQLiteStore
from backend.services.tracker import TrackerStore

WEB_DIR = Path(__file__).resolve().parents[1] / "web" / "frontend"

# CORS: the SPA is served same-origin, so cross-origin browser access stays
# CLOSED by default. Deployments that genuinely need it opt in via env var.
_CORS_ORIGINS = security.env_list("FEEFIX_CORS_ORIGINS")
_STORE = security.env_str("FEEFIX_STORE", "sqlite").lower()


def _cors_kwargs() -> dict:
    """CORS settings that cannot be misconfigured into an open policy.

    ``allow_origins=["*"]`` together with ``allow_credentials=True`` is the
    classic CORS footgun — it lets any site make credentialed requests and read
    the responses. Starlette refuses that combination, but only after the fact;
    we refuse it here, loudly, so the mistake is visible at boot rather than
    becoming a silent either/or in production.
    """
    origins = [o for o in _CORS_ORIGINS if o != "*"]
    wildcard = "*" in _CORS_ORIGINS
    if wildcard:
        security.audit_security_event(
            "cors.wildcard_refused",
            "FEEFIX_CORS_ORIGINS contained '*'; ignored. List explicit origins.",
        )
    if not origins:
        return {}
    return {
        "allow_origins": origins,
        # Explicit methods and headers rather than "*": a narrower contract is
        # a smaller attack surface, and "*" invites preflight-dependent bugs.
        "allow_methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": [
            "Authorization", "Content-Type",
            "X-FeeFix-Nonce", "X-FeeFix-Ts",
        ],
        "expose_headers": ["Retry-After"],
        # Credentials are only ever allowed for an explicit origin list. Bearer
        # tokens are not cookies, so this stays False by default.
        "allow_credentials": security.env_bool("FEEFIX_CORS_CREDENTIALS", False) and not wildcard,
        "max_age": 600,
    }


def create_app() -> FastAPI:
    app = FastAPI(
        title="FeeFix India",
        version="1.2.0",
        description=(
            "Personalized scholarship & fee-waiver matching platform for "
            "Indian students — discover, understand, apply, track."
        ),
        # Auto-docs are a complete map of the attack surface. They stay on in
        # development, where they are useful, and disappear in production.
        docs_url=None if security.is_production() else "/docs",
        redoc_url=None,
        openapi_url=None if security.is_production() else "/openapi.json",
    )

    cors = _cors_kwargs()
    if cors:
        app.add_middleware(CORSMiddleware, **cors)

    # --- security middleware (registered inner→outer; see module docstring) ---
    app.add_middleware(RequestShield)
    app.add_middleware(SecurityHeadersMiddleware)

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

    # --- error handling ----------------------------------------------------
    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):  # pragma: no cover
        """Last line of defence: log the truth, tell the client nothing."""
        log_unexpected(request, exc)
        return JSONResponse(status_code=500, content={"detail": public_error_body(exc)})

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        """Field-level 422s, without echoing the rejected values.

        Pydantic's default handler returns the ``input`` that failed. For a
        password field that means the user's password is reflected back in the
        response body — and into any proxy log, browser network tab or error
        reporter on the path. We keep the field name and the reason (both are
        our own strings) and drop the value.
        """
        errors = []
        for err in exc.errors():
            loc = [str(p) for p in err.get("loc", ()) if p not in ("body",)]
            errors.append({
                "field": ".".join(loc) or "body",
                "message": err.get("msg", "Invalid value"),
                "type": err.get("type", "value_error"),
            })
        security.audit_security_event(
            "request.validation_failed",
            f"path={request.url.path[:80]} fields={','.join(e['field'] for e in errors)[:160]}",
        )
        return JSONResponse(
            status_code=422,
            content={"detail": errors[0]["message"] if len(errors) == 1 else errors},
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        """Pass through our own messages; flatten anything unexpected."""
        detail = exc.detail
        if not isinstance(detail, str):
            detail = "Request could not be processed."
        headers = dict(getattr(exc, "headers", None) or {})
        return JSONResponse(status_code=exc.status_code, content={"detail": detail},
                            headers=headers)

    app.include_router(api_router)

    # well-known security contact — RFC 9116. Costs one static response and
    # gives a researcher a documented way to report instead of going public.
    app.get("/.well-known/security.txt", include_in_schema=False)(_security_txt)

    if WEB_DIR.exists():
        # StaticFiles resolves and contains paths itself; mounting at "/" after
        # the router means /api/* always wins over any file of the same name.
        app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")

    return app


_SECURITY_TXT = """Contact: mailto:security@feefix.local
Preferred-Languages: en, hi, bn, ta
Policy: https://github.com/authorsauravkushwaha/feefix-india/blob/main/SECURITY.md
Hiring: false
"""


async def _security_txt():
    """RFC 9116 disclosure endpoint. Plain text, cacheable for a day."""
    from fastapi.responses import PlainTextResponse

    return PlainTextResponse(_SECURITY_TXT, media_type="text/plain",
                             headers={"Cache-Control": "public, max-age=86400"})


app = create_app()
