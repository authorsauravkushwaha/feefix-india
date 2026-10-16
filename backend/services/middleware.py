"""ASGI middlewares — session resolution and rate limiting.

Written as **pure ASGI** middlewares on purpose:

* ``BaseHTTPMiddleware`` re-wraps ``receive``/``send`` and makes body handling
  opaque — fine for header work, wrong for anything that must observe or bound
  the byte stream (see ``request_limits.py``).
* Blocking work (SQLite session lookups, a Redis round-trip for the limiter) is
  pushed to a worker thread with ``run_in_threadpool`` so a slow store cannot
  stall the event loop for every other connection.
"""

from __future__ import annotations

import logging

from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from backend.services import auth as auth_svc
from backend.services import ratelimit

log = logging.getLogger("feefix")


def _bearer(scope: Scope) -> str | None:
    for key, value in scope.get("headers", []):
        if key == b"authorization":
            text = value.decode("latin-1")
            if text.lower().startswith("bearer "):
                return text[7:].strip()
            return None
    return None


class SessionMiddleware:
    """Resolve the bearer session once per request; rotate aged tokens.

    The resolved user is cached on ``scope["state"]["user"]`` (surfaced as
    ``request.state.user``) so the whole request shares one lookup and one
    rotation decision. When a token was rotated — or a late client was healed —
    the fresh token is returned in ``X-Session-Token``.
    """

    def __init__(self, app: ASGIApp, prefix: str = "/api/") -> None:
        self.app = app
        self.prefix = prefix

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http" or not str(scope.get("path", "")).startswith(self.prefix):
            await self.app(scope, receive, send)
            return

        token = _bearer(scope)
        request = Request(scope, receive)
        fingerprint = auth_svc.client_fingerprint(request)
        user, new_token = await run_in_threadpool(
            auth_svc.resolve_and_rotate, token, fingerprint
        )
        scope.setdefault("state", {})["user"] = user

        if not new_token:
            await self.app(scope, receive, send)
            return

        async def send_with_token(message: Message) -> None:
            if message.get("type") == "http.response.start":
                headers = list(message.get("headers", []))
                headers.append((b"x-session-token", new_token.encode("latin-1")))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_token)


class RateLimitMiddleware:
    """Per-IP sliding-window admission control with endpoint tiers.

    Denials are cheap (``429`` + ``Retry-After``, no handler work). The store is
    pluggable — in-process or Redis — so the limits hold across workers and
    instances (see ``services/ratelimit.py``).
    """

    def __init__(self, app: ASGIApp, prefix: str = "/api/") -> None:
        self.app = app
        self.prefix = prefix

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http" or not str(scope.get("path", "")).startswith(self.prefix):
            await self.app(scope, receive, send)
            return

        path = str(scope.get("path", ""))
        bucket = ratelimit.bucket_for_path(path)
        client = ratelimit.client_ip(Request(scope, receive))
        allowed, retry = await run_in_threadpool(ratelimit.enforce, client, bucket)
        if allowed:
            await self.app(scope, receive, send)
            return
        response = JSONResponse(
            status_code=429,
            content={
                "detail": "Too many requests — slow down.",
                "retry_after": retry,
                "scope": bucket,
            },
            headers={"Retry-After": str(retry)},
        )
        await response(scope, receive, send)
