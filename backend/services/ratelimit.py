"""Rate limiting — pluggable backends, correct under horizontal scaling.

The original implementation was a per-process dict: with ``--workers 4`` or two
Render instances the effective limit is silently multiplied by the number of
processes, and an attacker simply spreads requests across them. A rate limiter
that only works in a single process is not a rate limiter in production.

This module therefore separates the *policy* (which bucket, what limit) from the
*store* (where the counters live):

* :class:`MemoryBackend` — the original in-process sliding window, still the
  default for local development and single-process deployments. Memory-bounded
  (its own DoS vector) and lock-guarded for threads.
* :class:`RedisBackend` — **atomic sliding window in Redis** (a ``MULTI``/``EXEC``
  pipeline of ``ZREMRANGEBYSCORE``/``ZADD``/``ZCARD``/``PEXPIRE``), so every
  worker and every instance shares one counter set. Selected automatically when
  ``FEEFIX_REDIS_URL``/``REDIS_URL`` is present (``FEEFIX_RATELIMIT_BACKEND`` can
  force ``memory`` or ``redis``).

Two further production realities are handled explicitly:

* **Fail-open vs fail-closed.** If Redis is unreachable, availability and
  security pull in opposite directions. The default is *fail-closed for auth
  buckets* (a brute-force attempt must never get a free pass when the limiter is
  down) and *fail-open for the rest* (an outage must not take the product down).
  ``FEEFIX_RATELIMIT_FAIL_MODE`` overrides this globally.
* **Topology awareness.** :func:`warn_if_not_distributed` shouts at boot if the
  deployment looks scaled-out (``WEB_CONCURRENCY``/``UVICORN_WORKERS`` > 1) while
  running the in-memory backend, so the previous silent failure mode becomes a
  loud, actionable log line. ``GET /api/health`` exposes the same state.

Proxy awareness is unchanged: ``X-Forwarded-For`` is honoured only behind a
trusted proxy (``FEEFIX_TRUST_PROXY``), otherwise it is ignored so it cannot be
spoofed to evade limits.
"""

from __future__ import annotations

import logging
import os
import threading
import time
import uuid
from typing import Protocol

log = logging.getLogger("feefix.ratelimit")


def _env_int(name: str, default: int, *, minimum: int = 1) -> int:
    raw = os.environ.get(name)
    if raw is None or not str(raw).strip():
        return default
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return default
    return value if value >= minimum else default


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


# -- policy -------------------------------------------------------------------- #
DEFAULT_LIMIT = (
    _env_int("FEEFIX_RL_GLOBAL_LIMIT", 1000),
    _env_int("FEEFIX_RL_GLOBAL_WINDOW", 60),
)
AUTH_LIMIT = (
    _env_int("FEEFIX_RL_AUTH_LIMIT", 10),
    _env_int("FEEFIX_RL_AUTH_WINDOW", 300),
)
EXPENSIVE_LIMIT = (
    _env_int("FEEFIX_RL_EXPENSIVE_LIMIT", 30),
    _env_int("FEEFIX_RL_EXPENSIVE_WINDOW", 60),
)

# Endpoints whose work is CPU-heavy (embeddings / matching) and get the tighter
# EXPENSIVE_LIMIT instead of the global one.
EXPENSIVE_PATHS = tuple(
    p.strip()
    for p in os.environ.get(
        "FEEFIX_RL_EXPENSIVE_PATHS",
    "/api/ask,/api/search/semantic,/api/chat,/api/events,/api/uploads"
    ).split(",")
    if p.strip()
)

# Backstop: never track more than this many distinct keys at once (memory store).
_MAX_KEYS = _env_int("FEEFIX_RL_MAX_KEYS", 50_000)

REDIS_KEY_PREFIX = os.environ.get("FEEFIX_RL_REDIS_PREFIX", "feefix:rl")
# Bucket prefixes that stay *closed* when the store is unreachable.
FAIL_CLOSED_BUCKETS = tuple(
    b.strip()
    for b in os.environ.get("FEEFIX_RATELIMIT_FAIL_MODE", "auth").split(",")
    if b.strip()
)
# Global override: "open" | "closed" | "" (empty = per-bucket policy above)
FAIL_MODE = (os.environ.get("FEEFIX_RATELIMIT_FAIL_MODE_GLOBAL", "") or "").strip().lower()


def _trust_proxy() -> bool:
    return _env_bool("FEEFIX_TRUST_PROXY", False)


def client_ip(request) -> str:
    """Real client IP — honour X-Forwarded-For only behind a trusted proxy.

    **Rightmost** entry, deliberately. Proxies *append* to ``X-Forwarded-For``,
    so the leftmost value is whatever the client chose to send: reading it let
    anyone rotate a header and get a fresh bucket per request, i.e. an unlimited
    rate-limit bypass (found by the fuzz suite). The rightmost value is the one
    our own trusted hop observed and cannot be spoofed through it.

    With no trusted proxy configured the header is ignored entirely — otherwise
    the same trick works directly.
    """
    if _trust_proxy():
        xff = request.headers.get("x-forwarded-for", "")
        if xff:
            hops = [part.strip() for part in xff.split(",") if part.strip()]
            if hops:
                return hops[-1]
    return request.client.host if request.client else "unknown"


# -- buckets -------------------------------------------------------------------- #
def _spec(bucket: str) -> tuple[int, int]:
    if bucket.startswith("auth"):
        return AUTH_LIMIT
    if bucket.startswith("exp"):
        return EXPENSIVE_LIMIT
    return DEFAULT_LIMIT


def bucket_for_path(path: str) -> str:
    """Bucket label for an ``/api`` path (``global`` or ``exp:<endpoint>``)."""
    if path.startswith(EXPENSIVE_PATHS):
        return f"exp:{path}"
    return "global"


def _retry_after_for(bucket: str, oldest_age_s: float) -> int:
    limit_window = _spec(bucket)[1]
    return max(1, int(limit_window - oldest_age_s) + 1)


# -- store contract -------------------------------------------------------------- #
class RateLimitStore(Protocol):
    name: str
    distributed: bool

    def allow(self, bucket: str, ident: str, limit: int, window_s: int) -> tuple[bool, float]:
        """Record a hit. Returns ``(allowed, retry_after_seconds)``."""

    def retry_after(self, bucket: str, ident: str) -> int:
        """Seconds until the oldest hit leaves the window (best effort)."""

    def reset(self) -> None: ...

    def status(self) -> dict: ...


class MemoryBackend:
    """Per-process sliding window with a hard cap on tracked keys."""

    name = "memory"
    distributed = False

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.hits: dict[tuple[str, str], list[float]] = {}

    # Back-compat alias (older code/tests referenced ``_hits``).
    @property
    def _hits(self) -> dict:
        return self.hits

    def _sweep(self, now: float) -> None:
        if len(self.hits) < _MAX_KEYS:
            stale = [k for k, buf in self.hits.items() if not buf or buf[-1] < now - 3600]
            for k in stale:
                self.hits.pop(k, None)
            return
        # Emergency: keep only the most recently active keys.
        for k in sorted(self.hits, key=lambda k: self.hits[k][-1] if self.hits[k] else 0)[
            : _MAX_KEYS // 2
        ]:
            self.hits.pop(k, None)

    def allow(self, bucket: str, ident: str, limit: int, window_s: int) -> tuple[bool, float]:
        now = time.monotonic()
        key = (ident, bucket)
        with self._lock:
            buf = self.hits.setdefault(key, [])
            cutoff = now - window_s
            while buf and buf[0] < cutoff:
                buf.pop(0)
            if len(buf) >= limit:
                return False, max(0.0, buf[0] + window_s - now)
            buf.append(now)
            if len(self.hits) > _MAX_KEYS:
                self._sweep(now)
            return True, 0.0

    def retry_after(self, bucket: str, ident: str) -> int:
        now = time.monotonic()
        with self._lock:
            buf = self.hits.get((ident, bucket), [])
            if not buf:
                return 1
            return max(1, int(buf[0] + _spec(bucket)[1] - now) + 1)

    def reset(self) -> None:
        with self._lock:
            self.hits.clear()

    def status(self) -> dict:
        return {"backend": self.name, "distributed": False, "tracked_keys": len(self.hits)}


class RedisBackend:
    """Shared sliding window in Redis — one counter set for all workers/instances.

    Every check is a single atomic pipeline: drop expired members, add this hit,
    count the window, refresh the TTL. Unique members mean concurrent workers can
    never overwrite each other's hits.
    """

    name = "redis"

    def __init__(self, client, url: str | None = None) -> None:
        self._client = client
        self.url = url
        self._lock = threading.Lock()

    @property
    def distributed(self) -> bool:  # a live shared store is what makes us correct
        return True

    def available(self) -> bool:
        try:
            self._client.ping()
            return True
        except Exception:  # pragma: no cover - depends on the deployment
            return False

    def _fail_closed(self, bucket: str) -> bool:
        if FAIL_MODE == "closed":
            return True
        if FAIL_MODE == "open":
            return False
        return any(bucket.startswith(b) for b in FAIL_CLOSED_BUCKETS)

    def _key(self, bucket: str, ident: str) -> str:
        return f"{REDIS_KEY_PREFIX}:{bucket}:{ident}"

    def allow(self, bucket: str, ident: str, limit: int, window_s: int) -> tuple[bool, float]:
        now_ms = int(time.time() * 1000)
        window_ms = window_s * 1000
        key = self._key(bucket, ident)
        member = f"{now_ms}-{uuid.uuid4().hex[:8]}"
        try:
            pipe = self._client.pipeline(transaction=True)
            pipe.zremrangebyscore(key, 0, now_ms - window_ms)
            pipe.zadd(key, {member: now_ms})
            pipe.zcard(key)
            pipe.pexpire(key, window_ms + 1000)
            results = pipe.execute()
            count = int(results[2])
            if count <= limit:
                return True, 0.0
            # Over the limit: take our probe hit back out so denied attempts do
            # not artificially extend the window for everyone else.
            self._client.zrem(key, member)
            return False, self._oldest_age(key, now_ms, window_ms)
        except Exception as exc:  # noqa: BLE001 - any store failure is handled the same way
            return self._on_store_failure(bucket, exc)

    def _oldest_age(self, key: str, now_ms: int, window_ms: int) -> float:
        try:
            oldest = self._client.zrange(key, 0, 0, withscores=True)
        except Exception:  # noqa: BLE001
            return float(window_ms) / 1000
        if not oldest:
            return float(window_ms) / 1000
        try:
            oldest_ms = float(oldest[0][1])
        except (TypeError, ValueError, IndexError):
            return float(window_ms) / 1000
        return max(0.0, (now_ms - oldest_ms) / 1000.0)

    def _on_store_failure(self, bucket: str, exc: Exception) -> tuple[bool, float]:
        closed = self._fail_closed(bucket)
        log.error(
            "[ratelimit] redis unavailable (%s: %s) — failing %s for bucket %r",
            type(exc).__name__,
            exc,
            "CLOSED" if closed else "OPEN",
            bucket,
        )
        return (not closed), (60.0 if closed else 0.0)

    def retry_after(self, bucket: str, ident: str) -> int:
        try:
            key = self._key(bucket, ident)
            oldest = self._client.zrange(key, 0, 0, withscores=True)
        except Exception:  # noqa: BLE001
            return _retry_after_for(bucket, 0.0)
        if not oldest:
            return 1
        now_ms = int(time.time() * 1000)
        age_s = max(0.0, (now_ms - float(oldest[0][1])) / 1000.0)
        return _retry_after_for(bucket, age_s)

    def reset(self) -> None:
        try:
            keys = list(self._client.scan_iter(match=f"{REDIS_KEY_PREFIX}:*"))
            if keys:
                self._client.delete(*keys)
        except Exception as exc:  # noqa: BLE001
            log.warning("[ratelimit] reset failed: %s", exc)

    def status(self) -> dict:
        return {"backend": self.name, "distributed": True, "url": _redact(self.url)}


def _redact(url: str | None) -> str | None:
    """Never log a Redis URL verbatim — it may carry a password."""
    if not url:
        return None
    if "@" in url:
        scheme, _, host = url.partition("://")
        return f"{scheme or 'redis'}://***@{host.split('@', 1)[1]}"
    return url


# -- backend selection ------------------------------------------------------------ #
_BACKEND: RateLimitStore | None = None
_BACKEND_LOCK = threading.Lock()
_MEMORY = MemoryBackend()

# Back-compat alias used by the historical test suite.
_hits = _MEMORY.hits


def _redis_url() -> str | None:
    return (
        os.environ.get("FEEFIX_REDIS_URL")
        or os.environ.get("REDIS_URL")
        or os.environ.get("FEEFIX_RATELIMIT_URL")
    )


def _make_redis_client(url: str):  # pragma: no cover - import path is environment specific
    try:
        import redis  # type: ignore import-not-found
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "FEEFIX_REDIS_URL is set but the 'redis' package is not installed."
            " Install it (pip install 'redis>=5') or unset FEEFIX_REDIS_URL."
        ) from exc
    kwargs: dict = {
        "decode_responses": False,
        "socket_timeout": float(os.environ.get("FEEFIX_REDIS_TIMEOUT", "1.0")),
        "socket_connect_timeout": float(os.environ.get("FEEFIX_REDIS_TIMEOUT", "1.0")),
        "health_check_interval": 30,
    }
    if url.startswith("rediss://"):
        kwargs["ssl"] = True
    return redis.Redis.from_url(url, **kwargs)


def configure(backend: RateLimitStore | None = None, *, force: bool = False) -> RateLimitStore:
    """Select the store once per process (idempotent unless ``force``)."""
    global _BACKEND
    with _BACKEND_LOCK:
        if backend is not None:
            _BACKEND = backend
            log.info("[ratelimit] backend=%s", backend.name)
            return _BACKEND
        if _BACKEND is not None and not force:
            return _BACKEND

        requested = (os.environ.get("FEEFIX_RATELIMIT_BACKEND", "auto") or "auto").strip().lower()
        url = _redis_url()

        if requested == "memory":
            _BACKEND = _MEMORY
        elif requested == "redis":
            if not url:
                raise RuntimeError("FEEFIX_RATELIMIT_BACKEND=redis requires FEEFIX_REDIS_URL.")
            _BACKEND = RedisBackend(_make_redis_client(url), url)
        elif url:
            try:
                client = _make_redis_client(url)
                _BACKEND = RedisBackend(client, url)
            except RuntimeError as exc:
                log.error("[ratelimit] %s — falling back to the in-process store.", exc)
                _BACKEND = _MEMORY
        else:
            _BACKEND = _MEMORY
        log.info("[ratelimit] backend=%s distributed=%s", _BACKEND.name, _BACKEND.distributed)
        return _BACKEND


def backend() -> RateLimitStore:
    return configure()


def memory_backend() -> MemoryBackend:
    return _MEMORY


def _hit(bucket: str, ident: str) -> tuple[bool, float]:
    limit, window = _spec(bucket)
    return backend().allow(bucket, ident, limit, window)


def check_global(client_ip_: str) -> bool:
    return _hit("global", client_ip_)[0]


def check_auth(client_ip_: str, identifier: str) -> bool:
    return _hit("auth", f"{client_ip_}:{identifier}")[0]


def check_expensive(client_ip_: str, bucket: str) -> bool:
    return _hit("exp", f"{client_ip_}:{bucket}")[0]


def retry_after(client_ip_: str, bucket: str) -> int:
    """Seconds until a bucket frees up (for the ``Retry-After`` header).

    ``bucket`` takes the same label the caller used to check: ``"global"``,
    ``"auth:<identifier>"`` or ``"exp:<endpoint>"``.
    """
    if bucket.startswith("auth:"):
        return backend().retry_after("auth", f"{client_ip_}:{bucket[5:]}")
    if bucket.startswith("exp"):
        return backend().retry_after("exp", f"{client_ip_}:{bucket}")
    return backend().retry_after("global", client_ip_)


def enforce(client_ip_: str, bucket_label: str = "global") -> tuple[bool, int]:
    """One call for middleware: ``(allowed, retry_after_seconds)``."""
    bucket = "global" if bucket_label == "global" else bucket_label.split(":", 1)[0]
    ident = client_ip_ if bucket == "global" else f"{client_ip_}:{bucket_label}"
    allowed, retry = _hit(bucket, ident)
    if allowed:
        return True, 0
    return False, max(1, int(retry) if retry else 1)


def status() -> dict:
    store = backend()
    info = store.status()
    workers = _worker_hint()
    info["workers"] = workers
    info["recommendation"] = (
        None
        if store.distributed or workers <= 1
        else "Multiple workers/instances share no counter state — set FEEFIX_REDIS_URL."
    )
    return info


def _worker_hint() -> int:
    for name in ("WEB_CONCURRENCY", "UVICORN_WORKERS", "GUNICORN_WORKERS", "FEEFIX_INSTANCES"):
        raw = os.environ.get(name)
        if raw and str(raw).strip().isdigit():
            return max(1, int(str(raw).strip()))
    return 1


def warn_if_not_distributed() -> str | None:
    """Boot-time reality check for scaled-out deployments (returns the warning)."""
    store = backend()
    if store.distributed:
        return None
    workers = _worker_hint()
    if workers <= 1:
        return None
    warning = (
        f"Rate limiting is running on the in-process store with {workers} workers/instances: "
        "each process keeps its own counters, so effective limits are multiplied by "
        f"{workers} and an attacker can spread requests across them. Set FEEFIX_REDIS_URL "
        "(or FEEFIX_RATELIMIT_BACKEND=redis) so all workers share one counter set."
    )
    log.error("[ratelimit] %s", warning)
    return warning


def reset() -> None:
    """Clear all counters (tests, or an operator-triggered flush)."""
    _MEMORY.reset()
    store = backend()
    if store is not _MEMORY:
        store.reset()
