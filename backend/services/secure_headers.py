"""Security response headers — confidentiality & integrity on the wire.

These are the cheapest controls in the entire platform: a few bytes on every
response, no runtime cost, and each one closes a class of attack that would
otherwise need application logic to defend.

| Header | Attack it stops |
|---|---|
| ``Content-Security-Policy`` | XSS — ``script-src 'self'`` means injected markup cannot fetch or run code, and there is no ``unsafe-inline``/``unsafe-eval`` escape hatch |
| ``frame-ancestors`` + ``X-Frame-Options`` | Clickjacking — the app cannot be framed by an attacker's page and used as a transparent click target |
| ``X-Content-Type-Options: nosniff`` | MIME confusion — a ``.json`` or uploaded file is never reinterpreted as script |
| ``Cross-Origin-Opener-Policy`` | XS-Leaks / cross-window attacks — severs ``window.opener`` ties to other origins, so a page we open cannot reach back into ours |
| ``Cross-Origin-Resource-Policy`` | Our responses being embedded and read by another origin |
| ``Referrer-Policy`` | Session ids and query parameters leaking to third parties in the Referer header |
| ``Permissions-Policy`` | A compromised script silently enabling camera/mic/geolocation |
| ``X-Permitted-Cross-Domain-Policies`` | Legacy Flash/PDF cross-domain data grants |
| ``Strict-Transport-Security`` | SSL-strip downgrade on the first request after a TLS terminator |
| ``Cache-Control: no-store`` | Authenticated data persisting in a shared/proxy/browser cache |

Deliberate omissions, so they read as decisions rather than oversights:

* **No ``Cross-Origin-Embedder-Policy``.** COEP buys Spectre-style isolation
  that only matters when using ``SharedArrayBuffer``; it would also require
  every third-party subresource to opt in, and this app loads webfonts. The
  cost is real and the benefit here is not.
* **``style-src 'unsafe-inline'`` is retained.** The SPA sets inline ``style``
  attributes on generated cards and badges. Removing it means moving ~40 inline
  styles into classes — worth doing, but it is a refactor, not a header, and
  silently shipping a broken layout is worse than the residual risk. Inline
  *styles* cannot execute script; inline *scripts* can, and those stay banned.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# frame-ancestors allows the platform's live-preview embed (*.e2b.app) while
# blocking every other clickjacking embedding origin. The webfont origins are
# allow-listed because index.html declares preconnect hints for them; without
# these entries the stylesheet request is blocked and the UI silently falls
# back to system fonts.
_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "                      # no inline, no eval, no remote code
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "img-src 'self' data:; "
    "font-src 'self' data: https://fonts.gstatic.com; "
    "connect-src 'self'; "                     # XHR/fetch/WebSocket: same origin only
    "manifest-src 'self'; "
    "worker-src 'self'; "
    "object-src 'none'; "                      # no plugins, no <object>/<embed>
    "frame-ancestors 'self' https://*.e2b.app; "
    "base-uri 'self'; "                        # stops <base> hijacking relative URLs
    "form-action 'self'; "
    "upgrade-insecure-requests"
)

_HSTS = "max-age=31536000; includeSubDomains"

#: Paths whose responses must never be stored anywhere. ``/api/*`` carries
#: account data; the OAuth handoff page carries a live bearer token.
_NO_STORE_PREFIXES = ("/api/",)
_NO_STORE_EXACT = frozenset({"/gh-handoff.js"})


def _is_sensitive(path: str) -> bool:
    return path.startswith(_NO_STORE_PREFIXES) or path in _NO_STORE_EXACT


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        path = request.url.path

        # setdefault, not assignment: a handler that sets a stricter value
        # (e.g. no-store on the OAuth handoff) keeps it.
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=(), usb=(), "
            "magnetometer=(), gyroscope=(), accelerometer=(), fullscreen=(self)",
        )
        response.headers.setdefault("Content-Security-Policy", _CSP)
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        response.headers.setdefault("X-Permitted-Cross-Domain-Policies", "none")
        response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        # Set to 0 on purpose, which reads backwards until you know the
        # history: the legacy XSS auditor *introduced* vulnerabilities (it could
        # be coerced into disabling a page's scripts and into leaking
        # cross-origin content), every modern browser has removed it, and OWASP
        # now recommends explicitly switching it off. The CSP above is the real
        # control; this stops an old auditor from interfering with it.
        response.headers.setdefault("X-XSS-Protection", "0")

        if request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https":
            response.headers.setdefault("Strict-Transport-Security", _HSTS)

        if _is_sensitive(path):
            # Overwrite, not setdefault: an upstream handler must not be able to
            # make an authenticated response cacheable by accident.
            response.headers["Cache-Control"] = "no-store"

        # Never advertise the stack or the framework. Server headers are
        # fingerprinting fuel: they tell an attacker which CVE list to read.
        # Starlette's MutableHeaders has no .pop(), so delete explicitly — the
        # ``in`` test is case-insensitive.
        for name in ("server", "x-powered-by"):
            if name in response.headers:
                del response.headers[name]
        return response


__all__ = ["SecurityHeadersMiddleware"]
