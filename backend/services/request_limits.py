"""Request-body enforcement — *policy* caps, enforced while the body streams.

``services/limits.py`` decides *how large* a body may be for a given endpoint;
this module is the enforcement point, and it fixes two weaknesses of a naive
``Content-Length`` check:

1. **Header trust.** A request without ``Content-Length`` (chunked transfer
   encoding, HTTP/1.1 ``Transfer-Encoding: chunked``, or a malicious client that
   simply omits the header) previously bypassed the size check entirely. Here
   the bytes are counted *as they arrive*, so a stream cannot exceed the cap
   regardless of what the headers claim.
2. **One-size-fits-all.** The cap is looked up per (method, path) from the
   policy table, so a document upload is not held to a chat turn's limit and a
   chat turn is not allowed to buffer a megabyte.

Design notes
------------
* Implemented as a **pure ASGI middleware** (not ``BaseHTTPMiddleware``) so the
  wrapped ``receive`` is genuinely handed to the inner application — with
  ``BaseHTTPMiddleware`` the downstream app keeps the original ``receive`` and
  the counting would silently do nothing.
* The counter **stops reading** the moment the cap is exceeded and raises
  :class:`BodyTooLarge`, which the app maps to ``413`` (see
  ``backend/main.py``). Nothing beyond one chunk over the cap is ever buffered,
  so the guard cannot itself be used as a memory-amplification vector.
* ``Content-Length`` is still checked first: rejecting a declared 100 MB upload
  before the first byte is cheap, and it lets large rejected bodies be refused
  without consuming bandwidth.
"""

from __future__ import annotations

import logging

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from backend.services.limits import BODY_METHODS, body_limit_bytes, body_limit_for

log = logging.getLogger("feefix")


class BodyTooLarge(Exception):
    """Raised mid-stream when a request body exceeds its endpoint policy."""

    def __init__(self, *, limit: int, received: int, method: str, path: str, policy: str):
        super().__init__(f"request body exceeded {limit} bytes")
        self.limit = limit
        self.received = received
        self.method = method
        self.path = path
        self.policy = policy

    def as_json(self) -> dict:
        return {
            "detail": "Payload too large.",
            "limit_bytes": self.limit,
            "policy": self.policy,
            "hint": (
                "This endpoint accepts at most "
                f"{self.limit} bytes; see GET /api/meta for the full limit table."
            ),
        }


def _header(scope: Scope, name: bytes) -> bytes | None:
    for key, value in scope.get("headers", []):
        if key == name:
            return value
    return None


def _declared_length(scope: Scope) -> int | None:
    raw = _header(scope, b"content-length")
    if not raw:
        return None
    try:
        value = int(raw.strip())
    except (TypeError, ValueError):
        return None
    return value if value >= 0 else None


class BodyLimitMiddleware:
    """Per-endpoint body caps, enforced against the real byte stream."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http" or scope.get("method") not in BODY_METHODS:
            await self.app(scope, receive, send)
            return

        method = scope["method"]
        path = scope.get("path", "")
        policy = body_limit_for(method, path)
        limit = policy.max_bytes

        declared = _declared_length(scope)
        if declared is not None and declared > limit:
            await self._reject(scope, receive, send, policy.name, limit, declared)
            return

        received = 0
        too_large = False
        response_started = False

        async def counting_receive() -> Message:
            nonlocal received, too_large
            message = await receive()
            if message.get("type") == "http.request":
                chunk = message.get("body", b"") or b""
                received += len(chunk)
                if received > limit:
                    too_large = True
                    # Stop feeding the application any further bytes: signal
                    # end-of-body so its parse fails fast, then throw away that
                    # failure and answer 413 below. (Raising from `receive`
                    # instead would be reported by the framework as a generic
                    # "error parsing the body" 400 — the wrong status and the
                    # wrong story for the client.)
                    return {"type": "http.request", "body": b"", "more_body": False}
            return message

        async def counting_send(message: Message) -> None:
            nonlocal response_started
            if too_large and not response_started:
                # Discard whatever the application produced for a body we aborted.
                return
            if message.get("type") == "http.response.start":
                response_started = True
            await send(message)

        await self.app(scope, counting_receive, counting_send)

        if too_large and not response_started:
            log.warning(
                "[limits] aborted %s %s after %d bytes (limit %d, %s policy)",
                method, path, received, limit, policy.name,
            )
            response = JSONResponse(
                status_code=413,
                content=BodyTooLarge(
                    limit=limit,
                    received=received,
                    method=method,
                    path=path,
                    policy=policy.name,
                ).as_json(),
            )
            await response(scope, receive, send)

    async def _reject(
        self, scope: Scope, receive: Receive, send: Send, policy: str, limit: int, declared: int
    ) -> None:
        log.warning(
            "[limits] rejected %s %s: declared %d bytes > %d (%s policy)",
            scope.get("method"),
            scope.get("path"),
            declared,
            limit,
            policy,
        )
        response = JSONResponse(
            status_code=413,
            content=BodyTooLarge(
                limit=limit,
                received=declared,
                method=scope.get("method", ""),
                path=scope.get("path", ""),
                policy=policy,
            ).as_json(),
        )
        await response(scope, receive, send)


async def payload_too_large_handler(request, exc: BodyTooLarge):  # noqa: ANN001 - Starlette signature
    """Map :class:`BodyTooLarge` to a helpful ``413`` (registered in main.py)."""
    from fastapi.responses import JSONResponse

    log.warning(
        "[limits] aborted %s %s after %d bytes (limit %d, %s policy)",
        exc.method,
        exc.path,
        exc.received,
        exc.limit,
        exc.policy,
    )
    return JSONResponse(status_code=413, content=exc.as_json())


__all__ = [
    "BODY_METHODS",
    "BodyLimitMiddleware",
    "BodyTooLarge",
    "body_limit_bytes",
    "payload_too_large_handler",
]
