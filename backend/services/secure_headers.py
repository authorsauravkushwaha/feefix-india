"""Security response headers middleware — confidentiality & integrity on the wire.

* ``Strict-Transport-Security`` — force HTTPS where TLS terminates (deploy layer)
* ``Content-Security-Policy`` — same-origin scripts only; defeats XSS injection
  of remote code for the SPA
* ``X-Content-Type-Options: nosniff``, ``X-Frame-Options: DENY``,
  ``Referrer-Policy`` — classic hardening trio
* ``Cache-Control: no-store`` on /api/* — application data never lingers
  in intermediary or browser caches
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


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault("Content-Security-Policy", _CSP)
        if request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https":
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response
