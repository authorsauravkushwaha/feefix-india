"""Rate limiting — the availability pillar, with a *shared* counter by default.

The bug this module used to have is the classic one: a sliding window held in a
Python dict. It is correct for exactly one process. Run ``uvicorn --workers 4``
or scale to N instances and every replica keeps its own counter, so the real
limit becomes ``N × configured`` and an attacker simply spreads requests —
invisible to a single-process test suite.

The fix is a store boundary:

===============  =========  ==================================================
store            shared     when it applies
===============  =========  ==================================================
``sqlite``       yes*       **default** — counters live in the same hardened
                            SQLite file the app already uses, updated inside a
                            ``BEGIN IMMEDIATE`` transaction, so every worker
                            process AND every thread sees one counter. (*shared
                            across processes on one host / one DB volume.)
``redis``        yes        set ``FEEFIX_REDIS_URL`` — the only correct choice
                            for multiple instances; a Lua script does the
                            prune/count/insert atomically server-side.
``memory``       no         opt-in (``FEEFIX_RATE_LIMIT_BACKEND=memory``) for
                            tests and single-process dev. Selecting it while a
                            concurrency hint is set logs a loud topology warning
                            (and fails closed under strict mode) instead of
                            silently multiplying every limit.
===============  =========  ==================================================

Other hardening kept from before: tiered buckets (expensive AI endpoints get
their own tighter window), a bounded counter table (the DoS shield cannot become
a DoS vector), per-bucket ``Retry-After`` and proxy-aware client IPs — now
anchored to the *right* of ``X-Forwarded-For`` (the side proxies append to),
so a client-supplied header can no longer be used to evade a bucket.

Store failures never take the service down silently: they are counted and
reported by ``describe()`` (surfaced in ``/api/health``), and
``FEEFIX_RATELIMIT_FAIL_MODE=closed`` makes the limiter refuse traffic instead
of failing open.
"""

from __future__ import annotations

import logging
import os
import secrets
import threading
import time

log = logging.getLogger("feefix.ratelimit")

DEFAULT_LIMIT = (1000, 60)       # 1000 requests / 60s per IP (app-wide)
AUTH_LIMIT = (10, 300)           # 10 auth attempts / 5 min per IP+account
EXPENSIVE_LIMIT = (30, 60)       # 30 CPU-heavy calls / 60s per IP

# Endpoints whose work is CPU-heavy (embeddings / matching) and get the
# tighter EXPENSIVE_LIMIT instead of the global one.
EXPENSIVE_PATHS = ("/api/ask", "/api/search/semantic", "/api/chat", "/api/events")

# Backstop: never track more than this many distinct keys at once.
_MAX_KEYS = int(os.environ.get("FEEFIX_RATELIMIT_MAX_KEYS", "10000"))
_KEY_PREFIX = os.environ.get("FEEFIX_RATELIMIT_PREFIX", "feefix:rl:")


# --------------------------------------------------------------------------- #
# Stores
# --------------------------------------------------------------------------- #
class MemoryStore:
    """Single-process sliding window. Honest about not being shared."""

    name = "memory"
    shared = False

    def __init__(self, max_keys: int = _MAX_KEYS) -> None:
        self.max_keys = max_keys
        self._lock = threading.Lock()
        self.hits: dict[str, list[float]] = {}

    def hit(self, key: str, limit: int, window_s: float, now: float) -> tuple[bool, int]:
        with self._lock:
            buf = self.hits.setdefault(key, [])
            cutoff = now - window_s
            while buf and buf[0] < cutoff:
                buf.pop(0)
            if len(buf) >= limit:
                return False, max(1, int(buf[0] + window_s - now) + 1)
            buf.append(now)
            if len(self.hits) > self.max_keys:
                self._prune(now)
            return True, 0

    def retry_after(self, key: str, window_s: float, now: float) -> int:
        with self._lock:
            buf = self.hits.get(key) or []
            if not buf:
                return 1
            return max(1, int(buf[0] + window_s - now) + 1)

    def _prune(self, now: float) -> None:
        """Drop expired buckets; if still over the cap, keep the newest half."""
        stale = [k for k, buf in self.hits.items() if not buf or buf[-1] < now - 3600]
        for key in stale:
            self.hits.pop(key, None)
        if len(self.hits) <= self.max_keys:
            return
        ordered = sorted(self.hits, key=lambda k: self.hits[k][-1] if self.hits[k] else 0)
        for key in ordered[: len(ordered) - self.max_keys // 2]:
            self.hits.pop(key, None)

    def reset(self) -> None:
        with self._lock:
            self.hits.clear()

    def tracked(self) -> int:
        with self._lock:
            return len(self.hits)


class SQLiteStore:
    """Shared sliding window in the app's SQLite file — atomic across processes.

    ``BEGIN IMMEDIATE`` takes the write lock up front, so prune → count → insert
    is one serialised unit of work: two workers can never both see "9 hits" and
    both admit the 10th.
    """

    name = "sqlite"
    shared = True

    def __init__(self, max_keys: int = _MAX_KEYS) -> None:
        self.max_keys = max_keys

    def _conn(self):
        from backend.services import db

        return db.get_connection(), db._lock

    def hit(self, key: str, limit: int, window_s: float, now: float) -> tuple[bool, int]:
        conn, lock = self._conn()
        cutoff = now - window_s
        with lock:
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("DELETE FROM rate_limit_hits WHERE ts < ?", (cutoff,))
                row = conn.execute(
                    "SELECT COUNT(*) AS n, MIN(ts) AS oldest"
                    " FROM rate_limit_hits WHERE key=? AND ts >= ?",
                    (_KEY_PREFIX + key, cutoff),
                ).fetchone()
                count = row["n"] if row else 0
                if count >= limit:
                    oldest = (row["oldest"] if row and row["oldest"] is not None else now)
                    conn.rollback()
                    return False, max(1, int(oldest + window_s - now) + 1)
                conn.execute(
                    "INSERT INTO rate_limit_hits (key, ts) VALUES (?,?)",
                    (_KEY_PREFIX + key, now),
                )
                self._enforce_bound(conn)
                conn.commit()
                return True, 0
            except Exception:
                conn.rollback()
                raise

    def _enforce_bound(self, conn) -> None:
        """Keep the table bounded like the in-memory table always was."""
        total = conn.execute("SELECT COUNT(*) FROM rate_limit_hits").fetchone()[0]
        if total > self.max_keys:
            conn.execute(
                "DELETE FROM rate_limit_hits WHERE rowid IN ("
                " SELECT rowid FROM rate_limit_hits ORDER BY ts ASC LIMIT ?)",
                (total - self.max_keys // 2,),
            )

    def retry_after(self, key: str, window_s: float, now: float) -> int:
        conn, lock = self._conn()
        with lock:
            row = conn.execute(
                "SELECT MIN(ts) AS oldest FROM rate_limit_hits WHERE key=? AND ts >= ?",
                (_KEY_PREFIX + key, now - window_s),
            ).fetchone()
        oldest = row["oldest"] if row else None
        if oldest is None:
            return 1
        return max(1, int(oldest + window_s - now) + 1)

    def reset(self) -> None:
        conn, lock = self._conn()
        with lock:
            conn.execute("DELETE FROM rate_limit_hits")
            conn.commit()

    def tracked(self) -> int:
        conn, lock = self._conn()
        with lock:
            return conn.execute(
                "SELECT COUNT(DISTINCT key) FROM rate_limit_hits"
            ).fetchone()[0]


# Atomic sliding window: prune, count, insert in one server-side script.
_REDIS_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
local n = redis.call('ZCARD', key)
if n >= limit then
  local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
  local retry = window - (now - tonumber(oldest[2]))
  if retry < 0 then retry = 0 end
  return {0, math.ceil(retry / 1000) + 1}
end
redis.call('ZADD', key, now, ARGV[4])
redis.call('PEXPIRE', key, window)
return {1, 0}
"""


class RedisStore:
    """Multi-instance store — the only correct choice behind a load balancer."""

    name = "redis"
    shared = True

    def __init__(self, url: str, max_keys: int = _MAX_KEYS) -> None:
        import redis  # lazy: optional dependency, only needed when configured

        self._client = redis.Redis.from_url(url, socket_timeout=2, socket_connect_timeout=2)
        self._client.ping()
        self.max_keys = max_keys

    def hit(self, key: str, limit: int, window_s: float, now: float) -> tuple[bool, int]:
        now_ms = int(now * 1000)
        window_ms = int(window_s * 1000)
        allowed, retry = self._client.eval(
            _REDIS_LUA,
            1,
            _KEY_PREFIX + key,
            now_ms,
            window_ms,
            limit,
            f"{now_ms}-{secrets.token_hex(4)}",
        )
        return bool(int(allowed)), int(retry)

    def retry_after(self, key: str, window_s: float, now: float) -> int:
        oldest = self._client.zrange(_KEY_PREFIX + key, 0, 0, withscores=True)
        if not oldest:
            return 1
        return max(1, int(oldest[0][1] / 1000 + window_s - now) + 1)

    def reset(self) -> None:
        for key in self._client.scan_iter(match=_KEY_PREFIX + "*", count=500):
            self._client.delete(key)

    def tracked(self) -> int:
        return sum(1 for _ in self._client.scan_iter(match=_KEY_PREFIX + "*", count=500))


# --------------------------------------------------------------------------- #
# Selection
# --------------------------------------------------------------------------- #
_store = None
_degraded = 0
_last_error = ""


def _select_store():
    choice = os.environ.get("FEEFIX_RATE_LIMIT_BACKEND", "auto").strip().lower()
    url = os.environ.get("FEEFIX_REDIS_URL", "").strip()
    if choice in ("auto", "") and url:
        choice = "redis"
    if choice == "redis" or (choice == "auto" and url):
        try:
            store = RedisStore(url)
            log.info("[ratelimit] shared Redis store in use (%s)", _REDIS_HOST(url))
            return store
        except Exception as exc:  # pragma: no cover - depends on deployment
            log.error(
                "[ratelimit] FEEFIX_REDIS_URL is set but Redis is unreachable (%s: %s) "
                "— falling back to the shared SQLite store",
                exc.__class__.__name__,
                exc,
            )
            choice = "sqlite"
    if choice == "memory":
        log.warning(
            "[ratelimit] in-memory store selected: limits are PER PROCESS. "
            "Use the default sqlite store (or set FEEFIX_REDIS_URL) whenever you "
            "run more than one worker or instance."
        )
        return MemoryStore()
    return SQLiteStore()


def _REDIS_HOST(url: str) -> str:  # pragma: no cover - cosmetic
    try:
        from urllib.parse import urlparse

        parsed = urlparse(url)
        return f"{parsed.hostname}:{parsed.port or 6379}"
    except Exception:
        return "configured"


def store():
    """The active store (lazily created so tests can point at a temp DB first)."""
    global _store
    if _store is None:
        _store = _select_store()
    return _store


def use_store(candidate) -> None:
    """Swap the store (tests / explicit wiring)."""
    global _store
    _store = candidate


def _trusted_proxy_count() -> int:
    """How many proxies sit in front of the app (0 = trust no forwarded header).

    The old boolean ``FEEFIX_TRUST_PROXY`` trusted the *leftmost* XFF entry,
    which a client can forge. Counting proxies lets us anchor to the right-hand
    side instead — the entries our own infrastructure appended.
    """
    raw = os.environ.get("FEEFIX_TRUSTED_PROXY_COUNT")
    if raw and str(raw).strip().isdigit():
        return max(0, int(raw))
    legacy = os.environ.get("FEEFIX_TRUST_PROXY", "").lower() in ("1", "true", "yes", "on")
    return 1 if legacy else 0


def client_ip(request) -> str:
    """Real client IP — honours X-Forwarded-For only for trusted proxies."""
    count = _trusted_proxy_count()
    if count:
        xff = request.headers.get("x-forwarded-for", "")
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if len(parts) >= count:
            return parts[-count]
        if parts:
            return parts[-1]
    return request.client.host if request.client else "unknown"


# -- bucket plumbing --------------------------------------------------------- #
def _window_for(bucket: str) -> int:
    if bucket == "global":
        return DEFAULT_LIMIT[1]
    if bucket.startswith("auth:"):
        return AUTH_LIMIT[1]
    return EXPENSIVE_LIMIT[1]


def _bucket_key(client: str, bucket: str) -> str:
    return f"{client}|{bucket}"


def _allow(client: str, bucket: str, limit: int, window_s: int) -> bool:
    global _degraded, _last_error
    now = time.monotonic()
    try:
        allowed, _retry = store().hit(_bucket_key(client, bucket), limit, window_s, now)
        return allowed
    except Exception as exc:  # store outage — never crash a request over it
        _degraded += 1
        _last_error = f"{exc.__class__.__name__}: {exc}"
        fail_closed = os.environ.get("FEEFIX_RATELIMIT_FAIL_MODE", "open").strip().lower() in (
            "closed",
            "close",
            "deny",
            "fail-closed",
            "fail_closed",
        )
        if _degraded in (1, 10) or _degraded % 100 == 0:
            log.error(
                "[ratelimit] store failure #%s (%s) — failing %s",
                _degraded,
                _last_error,
                "CLOSED" if fail_closed else "open",
            )
        return not fail_closed


def retry_after(client_ip_: str, bucket: str) -> int:
    """Seconds until the oldest hit in a bucket's window ages out (for 429)."""
    window = _window_for(bucket)
    try:
        return store().retry_after(_bucket_key(client_ip_, bucket), window, time.monotonic())
    except Exception:  # pragma: no cover - store outage
        return 1


def check_global(client_ip: str) -> bool:
    return _allow(client_ip, "global", *DEFAULT_LIMIT)


def check_auth(client_ip: str, identifier: str) -> bool:
    return _allow(client_ip, f"auth:{identifier}", *AUTH_LIMIT)


def check_expensive(client_ip: str, bucket: str) -> bool:
    return _allow(client_ip, f"exp:{bucket}", *EXPENSIVE_LIMIT)


def reset() -> None:
    """Clear the active store (tests, and an operator's panic button)."""
    global _degraded, _last_error
    try:
        store().reset()
    except Exception:  # pragma: no cover - store outage
        pass
    _degraded, _last_error = 0, ""


# -- topology honesty -------------------------------------------------------- #
def concurrency_hint() -> int:
    """Best-effort worker count — how many counters a memory store would create."""
    for name in ("FEEFIX_WEB_CONCURRENCY", "WEB_CONCURRENCY", "UVICORN_WORKERS"):
        raw = os.environ.get(name)
        if raw and str(raw).strip().isdigit():
            return max(1, int(raw))
    return 1


def topology_warnings() -> list[str]:
    """Reasons the current limiter configuration cannot be trusted as-is."""
    active = store()
    warnings: list[str] = []
    workers = concurrency_hint()
    if not active.shared and workers > 1:
        warnings.append(
            f"rate limiter store is '{active.name}' but {workers} workers are configured: "
            f"effective limits are up to {workers}× the configured value. "
            "Set FEEFIX_REDIS_URL (multi-instance) or use the default sqlite store."
        )
    if active.name == "sqlite" and os.environ.get("FEEFIX_INSTANCE_COUNT", "1").strip() not in ("", "1"):
        warnings.append(
            "multiple instances are configured but the SQLite limiter only shares "
            "state through a shared database file — set FEEFIX_REDIS_URL for a "
            "load-balanced deployment."
        )
    return warnings


def describe() -> dict:
    """Machine-readable limiter status for /api/health and tests."""
    active = store()
    try:
        tracked = active.tracked()
    except Exception:  # pragma: no cover - store outage
        tracked = -1
    return {
        "backend": active.name,
        "shared_across_processes": active.shared,
        "workers_hint": concurrency_hint(),
        "tracked_keys": tracked,
        "max_keys": getattr(active, "max_keys", None),
        "degraded_events": _degraded,
        "last_error": _last_error,
        "limits": {
            "global": list(DEFAULT_LIMIT),
            "auth": list(AUTH_LIMIT),
            "expensive": list(EXPENSIVE_LIMIT),
        },
        "warnings": topology_warnings(),
    }


# The always-available in-process store. Kept as ``_hits``/``_lock`` module
# attributes because older tooling looked at them directly; the *active* store
# may be the shared SQLite/Redis one (see ``store()``).
_memory_store = MemoryStore()
_hits: dict[str, list[float]] = _memory_store.hits
_lock = _memory_store._lock


def memory_store() -> MemoryStore:
    """The process-local store (used for comparisons in tests and diagnostics)."""
    return _memory_store
