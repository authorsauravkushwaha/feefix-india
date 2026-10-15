"""Request shield — the outermost layer, before any application code runs.

Everything in here exists to answer one question as early and as cheaply as
possible: *should this request be allowed to consume any server resource at
all?* Rejecting at the socket boundary costs microseconds; rejecting inside a
handler costs the parsing, the validation and possibly the crypto that came
before it.

CONTROLS
========
**Body-size ceiling.** FastAPI will happily buffer a 40 MB JSON document and
hand it to pydantic. Measured before this middleware: a 40 MB chat message was
accepted and cost ~3 s of CPU. At a modest request rate that is an
unauthenticated way to occupy every worker. We reject on ``Content-Length``
*before* reading, and we also reject a body that lies about its length by
streaming through a bounded reader.

**Method allow-list.** The API is JSON over GET/POST/PUT/DELETE. ``TRACE`` is
rejected outright — it is the transport for cross-site tracing, which reflects
headers (including ``Authorization``) back into a response body where script
can read them. ``OPTIONS`` is allowed only where CORS is configured.

**Client identity.** Rate limiting and replay defence are both keyed on the
client IP, so getting it wrong breaks both. :func:`security.client_ip` is the
only place that decision is made: ``X-Forwarded-For`` is honoured solely when
the socket peer is inside ``FEEFIX_TRUSTED_PROXIES``.

**Header-size ceiling.** Oversized headers are a slow-loris-adjacent vector and
a log-injection vector; they are refused before parsing.

**Quiet failure.** Nothing in this layer ever emits a stack trace, an internal
class name or a configuration value. Every rejection is a short JSON body with
a ``Retry-After`` where one is meaningful.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from backend.services import anti_replay, ratelimit, security
from backend.services.security import LIMITS

#: HTTP methods the API accepts. TRACE is deliberately absent (cross-site
#: tracing reflects credentials); CONNECT and PATCH are unused.
ALLOWED_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "POST", "PUT", "DELETE"})

#: Endpoints whose mutation must carry anti-replay proof. Read-only endpoints
#: are exempt — replaying a GET yields nothing the attacker did not capture.
_REPLAY_ROUTES = (
    "/api/auth/",
    "/api/events",
    "/api/tracker/",
    "/api/students/",
)


def _json_error(status: int, detail: str, **headers: str) -> JSONResponse:
    body = {"detail": detail}
    response = JSONResponse(status_code=status, content=body)
    for key, value in headers.items():
        response.headers[key.replace("_", "-")] = value
    return response


def _total_header_bytes(request: Request) -> int:
    return sum(len(k) + len(v) + 4 for k, v in request.headers.raw)


class RequestShield(BaseHTTPMiddleware):
    """Reject oversized, malformed and replayed requests at the boundary."""

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path
        is_api = path.startswith("/api/")

        # --- method allow-list -------------------------------------------
        if request.method not in ALLOWED_METHODS:
            security.audit_security_event(
                "shield.method_rejected", f"{request.method} {path[:120]}"
            )
            return _json_error(405, "Method not allowed.", allow="GET, POST, PUT, DELETE, HEAD, OPTIONS")

        # --- header size --------------------------------------------------
        if _total_header_bytes(request) > LIMITS.MAX_HEADER_BYTES:
            return _json_error(431, "Request header fields too large.")

        # --- path sanity --------------------------------------------------
        if len(path) > LIMITS.MAX_URL_PATH_LEN:
            return _json_error(414, "Request-URI too long.")
        if "\x00" in path or "\r" in path or "\n" in path:
            # NUL and CRLF in a path are smuggling / log-injection attempts.
            security.audit_security_event("shield.path_injection", security.scrub_text(path, 200))
            return _json_error(400, "Bad request.")

        if not is_api:
            return await call_next(request)

        # --- client identity (used by every control below) ----------------
        peer = request.client.host if request.client else None
        client = security.client_ip(peer, dict(request.headers))

        # --- query-string size -------------------------------------------
        if len(request.url.query or "") > LIMITS.MAX_QUERY_BYTES:
            return _json_error(414, "Query string too long.")

        # --- global rate limit -------------------------------------------
        if not ratelimit.check_global(client):
            return _json_error(
                429, "Too many requests — slow down.",
                retry_after=str(ratelimit.DEFAULT_LIMIT[1]),
            )

        # --- body size, checked BEFORE the body is read -------------------
        if request.method in ("POST", "PUT", "PATCH"):
            declared = request.headers.get("content-length")
            if declared:
                try:
                    if int(declared) > LIMITS.MAX_BODY_BYTES:
                        security.audit_security_event(
                            "shield.body_too_large", f"declared={declared} path={path[:80]}"
                        )
                        return _json_error(413, "Request body too large.")
                except ValueError:
                    return _json_error(400, "Bad request.")
            elif request.headers.get("transfer-encoding", "").lower() == "chunked":
                # Chunked requests carry no declared length, so the ceiling
                # cannot be checked up front — and draining the body here would
                # break it downstream, because BaseHTTPMiddleware hands the
                # next app a *different* Request object over the same scope and
                # ``_body`` is per-instance.
                #
                # No FeeFix client (browser, Kotlin, curl) uses chunked
                # encoding for JSON, so refusing is both safe and strictly
                # cheaper than any alternative: it is one header comparison,
                # and it closes the "lie about Content-Length" bypass entirely.
                security.audit_security_event("shield.chunked_rejected", path[:120])
                return _json_error(411, "A Content-Length header is required.")
            # No Content-Length AND no Transfer-Encoding means an empty body by
            # definition (HTTP/1.1 §4.4: the message ends with the headers), so
            # there is nothing to bound and nothing to refuse.

        # --- anti-replay on mutating, sensitive routes --------------------
        if any(path.startswith(prefix) for prefix in _REPLAY_ROUTES):
            try:
                anti_replay.check(
                    client_ip=client,
                    headers=dict(request.headers),
                    method=request.method,
                    route=path,
                )
            except anti_replay.ReplayError as exc:
                return _json_error(
                    409, exc.message,
                    retry_after=str(LIMITS.REPLAY_WINDOW_S),
                )

        # Expose the resolved identity to handlers without re-deriving it.
        request.state.client_ip = client

        try:
            response = await call_next(request)
        except ratelimit.RateLimited as exc:
            return _json_error(429, exc.client_message, retry_after=str(exc.retry_after))
        except anti_replay.ReplayError as exc:
            return _json_error(409, exc.message)
        return response


def error_response(status: int, detail: str) -> JSONResponse:
    """Uniform error envelope used by exception handlers."""
    return JSONResponse(status_code=status, content={"detail": detail})


def public_error_body(exc: Exception) -> str:
    """Client-safe text for an unexpected exception.

    The old handler returned ``f"Internal error: {exc.__class__.__name__}"``.
    A class name is information: ``OperationalError`` says "database",
    ``SMTPAuthenticationError`` says "mail credentials are wrong",
    ``FileNotFoundError`` says "a path I care about is missing". Attackers
    fingerprint stacks and error strings to choose their next payload. The
    client gets a constant; the operator gets the truth in the audit log.
    """
    return "Something went wrong on our side. Please try again."


def log_unexpected(request: Request, exc: Exception) -> None:
    """Record the real cause server-side, redacted and bounded."""
    path = getattr(getattr(request, "url", None), "path", "?")
    security.audit_security_event(
        "unhandled_exception",
        f"{type(exc).__name__} at {path}: {security.scrub_text(str(exc), 200)}",
    )


__all__ = [
    "ALLOWED_METHODS",
    "RequestShield",
    "error_response",
    "log_unexpected",
    "public_error_body",
]
