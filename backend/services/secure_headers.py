"""Security response headers middleware — confidentiality & integrity on the wire.

* ``Strict-Transport-Security`` — force HTTPS where TLS terminates (deploy layer)
* ``Content-Security-Policy`` — same-origin scripts only; defeats XSS injection
  of remote code for the SPA
* ``X-Content-Type-Options: nosniff``, ``X-Frame-Options: DENY``,
  ``Referrer-Policy`` — classic hardening trio
* ``Cache-Control: no-store`` on /api/* — application data never lingers
  in intermediary or browser caches

The interactive docs (``/docs``, ``/redoc``, ``/openapi.json``) are **on by
default** because disabling them removes no endpoint and no attack surface — the
routes answer either way — while breaking generated clients and QA tooling. They
get their own, narrowly-scoped CSP (the CDN assets Swagger/ReDoc need) so the
application's own policy stays ``script-src 'self'``.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# frame-ancestors allows the platform's live-preview embed (*.e2b.app) while
# blocking every other clickjacking embedding origin.
_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "   # JS-set inline styles (cards/badges)
    "img-src 'self' data:; "
    "font-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'self' https://*.e2b.app; "
    "base-uri 'self'; "
    "form-action 'self'"
)

# Swagger UI / ReDoc load their bundle from a CDN. Scoped to the docs paths
# only, and still no 'unsafe-eval' beyond what those pages require.
_DOCS_CSP = (
    "default-src 'self'; "
    "script-src 'self' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "img-src 'self' data: https://fastapi.tiangolo.com; "
    "font-src 'self' data: https://fonts.gstatic.com; "
    "connect-src 'self'; "
    "frame-ancestors 'self' https://*.e2b.app; "
    "base-uri 'self'; "
    "form-action 'self'"
)

_DOCS_PATHS = ("/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        docs_request = request.url.path.startswith(_DOCS_PATHS)
        response.headers.setdefault("Content-Security-Policy", _DOCS_CSP if docs_request else _CSP)
        if request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https":
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response
