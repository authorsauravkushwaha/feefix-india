"""Request-body gate — enforces the per-endpoint cap *while the body is read*.

The previous version only looked at ``Content-Length``. That is trivially
bypassable: a client that streams with ``Transfer-Encoding: chunked`` (or simply
lies about the length) never produced a header the gate could compare, so the cap
was advisory for exactly the clients that matter. This middleware is a raw ASGI
wrapper that counts the bytes as they arrive and stops the request the moment the
applicable cap is crossed:

* declared ``Content-Length`` over the cap → rejected before the app is called
  (cheapest possible path, zero bytes read);
* everything else → the ``receive`` channel is wrapped with a counter, so a
  chunked/unknown-length body is bounded too;
* the 413 carries ``X-Max-Body-Bytes`` and ``{"limit_bytes": N, "scope": ...}``
  so a legitimate client can adapt (retry smaller, use the upload route)
  instead of guessing what went wrong.

Raw ASGI (not ``BaseHTTPMiddleware``) because only this layer can wrap
``receive``. It is also the outermost middleware, so a rejected body never
reaches auth, rate limiting or the JSON parser.

Why the trip flag instead of just raising: the framework's own body reader
catches *any* exception raised while parsing a request body and turns it into a
400 ("There was an error parsing the body"). Raising there would therefore have
produced a confusing 400 and an app-level parse error instead of a 413 — so on
trip we hand the app ``http.disconnect`` (it stops reading) and simply refuse to
forward whatever response it tries to send, emitting our 413 instead.
"""

from __future__ import annotations

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from backend.services.limits import body_limit_for

# Methods that can carry a body worth gating.
_BODY_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class BodyLimitMiddleware:
    """Per-path request-body cap, enforced during streaming."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("method", "GET").upper() not in _BODY_METHODS:
            await self.app(scope, receive, send)
            return

        limit = body_limit_for(scope.get("path", "/"))
        declared = _content_length(scope)
        if declared is not None and declared > limit.max_bytes:
            await _reject(send, limit)
            return

        received = 0
        tripped = False
        rejected = False

        async def counting_receive() -> Message:
            nonlocal received, tripped
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b"") or b"")
                if received > limit.max_bytes:
                    tripped = True
                    # Stop the flood: the app sees a disconnect and aborts the
                    # read instead of buffering the rest of the payload.
                    return {"type": "http.disconnect"}
            return message

        async def guarded_send(message: Message) -> None:
            nonlocal rejected
            if tripped:
                if not rejected:
                    rejected = True
                    await _reject(send, limit)
                return  # swallow the app's (parse-error) response entirely
            await send(message)

        await self.app(scope, counting_receive, guarded_send)
        if tripped and not rejected:  # app never produced a response at all
            await _reject(send, limit)


def _content_length(scope: Scope) -> int | None:
    for name, value in scope.get("headers", []):
        if name == b"content-length":
            try:
                return int(value.decode("latin-1").strip())
            except (TypeError, ValueError):
                return None
    return None


async def _reject(send: Send, limit) -> None:
    """The 413 itself. Carries its own hardening headers: this middleware sits
    outside the security-header layer (deliberately — a rejected body must not
    pass through anything else), so it cannot rely on it."""
    response = JSONResponse(
        status_code=413,
        content={
            "detail": "Payload too large.",
            "scope": limit.scope,
            "limit_bytes": limit.max_bytes,
        },
    )
    response.headers["X-Max-Body-Bytes"] = str(limit.max_bytes)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    await response(
        {"type": "http", "method": "POST", "path": "/", "headers": []}, None, send
    )
