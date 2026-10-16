"""Rate limiting — shared counters by default, pluggable backends underneath.

Two historical bugs frame this module:

1. **Per-process counters.** A sliding window in a Python dict is correct for
   exactly one process. ``uvicorn --workers 4`` or N instances behind a load
   balancer silently multiplies every limit by N — an attacker just spreads
   requests. Every store here is either *shared* (SQLite file, Redis) or honest
   about not being shared (memory), and the topology is checked at boot.
2. **Spoofable client identity.** Reading the *left* of ``X-Forwarded-For``
   trusted a header the client chose, so a request could rotate its bucket
   forever. The client IP is now anchored to the *right* of the header (the side
   our own proxies append to), and only when a trusted proxy count is configured.

===============  ==========  ====================================================
store            shared      when it applies
===============  ==========  ====================================================
``sqlite``       yes*        **default** — counters live in the same hardened
                            SQLite file the app already uses, updated inside a
                            ``BEGIN IMMEDIATE`` transaction, so every worker
                            process AND every thread sees one counter. (*shared
                            across processes on one host / one DB volume.)
``redis``        yes         set ``FEEFIX_REDIS_URL`` — the only correct choice
                            for multiple instances; a Lua script does the
                            prune/count/insert atomically server-side.
``memory``       no         opt-in (``FEEFIX_RATELIMIT_BACKEND=memory``) for
                            tests and single-process dev. Selecting it while a
                            concurrency hint is set logs a loud topology warning
                            (and fails closed under strict mode) instead of
                            silently multiplying every limit.
===============  ==========  ====================================================

Both selection styles are supported: the store API (:func:`use_store`,
:func:`describe`) that the route-level checks use, and the backend API
(:func:`configure`, :func:`status`, :func:`enforce`) that the ASGI middleware
uses. Tiered buckets (expensive AI endpoints get their own tighter window), a
bounded counter table (the DoS shield cannot become a DoS vector), per-bucket
``Retry-After`` and env-tunable limits are all kept.

Store failures never take the service down silently: they are counted and
reported by ``describe()``/``status()`` (surfaced in ``/api/health``), and
``FEEFIX_RATELIMIT_FAIL_MODE=closed`` makes the limiter refuse traffic instead
of failing open. """ 

from __future__ import annotations

import logging
import os
import secrets
import threading
import time
import uuid
from typing import Protocol

#: Optional dependency, only imported when a Redis store is actually configured
#: (see ``RedisStore``). Bound at module level so tests can substitute a fake.
redis = None
try:  # pragma: no cover - trivial import guard
    import redis as _redis_module

    redis = _redis_module
except Exception:  # pragma: no cover - redis is optional
    redis = None

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
        # ``redis`` is the module-level symbol, so tests can substitute a fake
        # client; in a deployment without Redis configured this class is never
        # constructed and the package is never required.
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
        if redis is None:  # pragma: no cover - depends on installation
            log.error(
                "[ratelimit] FEEFIX_REDIS_URL is set but the 'redis' package is not "
                "installed — falling back to the shared SQLite store. Install redis "
                "to use it (requirements-redis.txt)."
            )
            return SQLiteStore()
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

    @property
    def multi_instance(self) -> bool:
        return False

    def status(self) -> dict:
        return {
            "backend": self.name,
            "distributed": False,
            "scope": "process",
            "multi_instance": False,
            "tracked_keys": len(self.hits),
        }


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
            # Remaining time until the oldest hit leaves the window — not the
            # age of that hit. Returning the age told clients to retry in a
            # second when they actually had to wait out the rest of the window.
            age_s = self._oldest_age(key, now_ms, window_ms)
            return False, max(0.0, window_s - age_s)
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

    @property
    def multi_instance(self) -> bool:
        return True

    def status(self) -> dict:
        return {
            "backend": self.name,
            "distributed": True,
            "scope": "cluster",
            "multi_instance": True,
            "url": _redact(self.url),
        }


def _trusted_proxy_count() -> int:
    """How many proxies sit in front of the app (0 = trust no forwarded header).

    Both spellings are honoured: ``FEEFIX_TRUSTED_PROXY_COUNT`` (N hops) and the
    legacy boolean ``FEEFIX_TRUST_PROXY`` (exactly one hop). Counting lets us
    anchor to the right-hand side — the entries our own infrastructure appended —
    so a client-forged leftmost value can never become the bucket key.
    """
    raw = os.environ.get("FEEFIX_TRUSTED_PROXY_COUNT")
    if raw and str(raw).strip().isdigit():
        return max(0, int(raw))
    legacy = os.environ.get("FEEFIX_TRUST_PROXY", "").lower() in ("1", "true", "yes", "on")
    return 1 if legacy else 0


def _trust_proxy() -> bool:
    return _trusted_proxy_count() > 0


def client_ip(request) -> str:
    """Real client IP — honours X-Forwarded-For only for trusted proxies.

    **Rightmost** entry, deliberately. Proxies *append* to ``X-Forwarded-For``,
    so the leftmost value is whatever the client chose to send: reading it let
    anyone rotate a header and get a fresh bucket per request, i.e. an unlimited
    rate-limit bypass (found by the fuzz suite). The rightmost value is the one
    our own trusted hop observed and cannot be spoofed through it.

    With ``FEEFIX_TRUSTED_PROXY_COUNT=N`` the Nth entry from the right is used
    (the hop N proxies away); with no trusted proxy configured the header is
    ignored entirely — otherwise the same trick works directly.
    """
    count = _trusted_proxy_count()
    if count:
        xff = request.headers.get("x-forwarded-for", "")
        hops = [part.strip() for part in xff.split(",") if part.strip()]
        if hops:
            return hops[-count] if len(hops) >= count else hops[-1]
    return request.client.host if request.client else "unknown"


def _redact(url: str | None) -> str | None:
    """Never log a Redis URL verbatim — it may carry a password."""
    if not url:
        return None
    if "@" in url:
        scheme, _, host = url.partition("://")
        return f"{scheme or 'redis'}://***@{host.split('@', 1)[1]}"
    return url


class SqliteBackend:
    """Sliding window in a SQLite file every worker on this host can open.

    Render/gunicorn ``--workers N`` share a filesystem. A per-process dict does
    not: each worker hands out a full quota and the effective limit is ``N ×``.
    This store is the shared counter for that topology. It is **not** shared
    across machines — multi-instance deployments still need Redis
    (``multi_instance`` is false here on purpose, so boot can refuse to pretend
    otherwise).
    """

    name = "sqlite"
    distributed = True
    multi_instance = False

    #: Lock wait for the journal-mode upgrade only (real statements get 30 s).
    _WAL_BUSY_S = 1.0
    _WAL_ATTEMPTS = 3

    def __init__(self, path: str | os.PathLike[str]) -> None:
        import sqlite3

        self.path = str(path)
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._sqlite3 = sqlite3
        self._local = threading.local()
        self._wal = False
        self._init()

    def _conn(self):
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._sqlite3.connect(self.path, timeout=self._WAL_BUSY_S, isolation_level=None)
            # Order matters twice over: the busy handler is installed *before*
            # the first statement can contend for a lock, and the WAL upgrade
            # below is attempted with a short wait, so a contended file does not
            # stall a boot. 30 s afterwards for every real statement.
            conn.execute(f"PRAGMA busy_timeout={int(self._WAL_BUSY_S * 1000)}")
            self._wal = self._switch_to_wal(conn)
            conn.execute("PRAGMA busy_timeout=30000")
            conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn = conn
        return conn

    def _switch_to_wal(self, conn) -> bool:
        """Move the file to WAL, waiting out a concurrent opener — never fatal.

        Two workers on one host start together and both try to switch the same
        **fresh** file to WAL. The loser gets ``sqlite3.OperationalError:
        database is locked`` from a journal-mode change, and the busy handler is
        not consulted for that particular race (the in-process version, eight
        concurrent openers, is what CI's flake-watch gate caught in
        ``backend/services/db.py``; this store had the same bug and CI caught it
        a second time). A worker that dies at boot because a sibling won a
        journal-mode race takes the whole deployment down to protect a
        performance setting, so losing is a degraded mode: retry, then carry on
        in the default journal mode, where ``BEGIN IMMEDIATE`` plus the busy
        timeout still enforce exactly one quota.
        """
        last_error: Exception | None = None
        for attempt in range(self._WAL_ATTEMPTS):
            try:
                mode = str(conn.execute("PRAGMA journal_mode=WAL").fetchone()[0]).lower()
            except self._sqlite3.OperationalError as exc:
                last_error = exc
                if "locked" not in str(exc).lower() and "busy" not in str(exc).lower():
                    raise
            else:
                if mode == "wal":
                    return True
                last_error = self._sqlite3.OperationalError(f"journal_mode is {mode!r}, not 'wal'")
            if attempt < self._WAL_ATTEMPTS - 1:
                time.sleep(0.05 * (attempt + 1))
        # Network mounts cannot do WAL at all. Serve anyway (correct, slower) and
        # say so — a silent downgrade is how the original per-process limiter
        # shipped in the first place.
        log.warning(
            "[ratelimit] %s is not in WAL mode: %s (using the default journal "
            "mode; the shared quota is still enforced)", self.path, last_error,
        )
        return False

    def _init(self) -> None:
        conn = self._conn()
        conn.execute(
            "CREATE TABLE IF NOT EXISTS hits ("
            " bucket TEXT NOT NULL, ident TEXT NOT NULL, at_ms INTEGER NOT NULL)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hits_lookup ON hits(bucket, ident, at_ms)"
        )

    def allow(self, bucket: str, ident: str, limit: int, window_s: int) -> tuple[bool, float]:
        now_ms = int(time.time() * 1000)
        window_ms = window_s * 1000
        cutoff = now_ms - window_ms
        try:
            conn = self._conn()
            conn.execute("BEGIN IMMEDIATE")
        except Exception as exc:  # noqa: BLE001
            return _on_store_failure(bucket, exc)
        try:
            conn.execute(
                "DELETE FROM hits WHERE bucket=? AND ident=? AND at_ms < ?",
                (bucket, ident, cutoff),
            )
            # Bound the table so the limiter cannot become the DoS vector.
            conn.execute("DELETE FROM hits WHERE at_ms < ?", (now_ms - 3_600_000,))
            row = conn.execute(
                "SELECT COUNT(*), MIN(at_ms) FROM hits WHERE bucket=? AND ident=?",
                (bucket, ident),
            ).fetchone()
            count = int(row[0] or 0)
            oldest = row[1]
            if count >= limit:
                conn.execute("COMMIT")
                if oldest is None:
                    return False, float(window_s)
                remaining = max(0.0, (int(oldest) + window_ms - now_ms) / 1000.0)
                return False, remaining
            conn.execute(
                "INSERT INTO hits (bucket, ident, at_ms) VALUES (?,?,?)",
                (bucket, ident, now_ms),
            )
            conn.execute("COMMIT")
            return True, 0.0
        except Exception as exc:  # noqa: BLE001
            try:
                conn.execute("ROLLBACK")
            except Exception:  # noqa: BLE001
                self._local.conn = None
            return _on_store_failure(bucket, exc)

    def retry_after(self, bucket: str, ident: str) -> int:
        try:
            conn = self._conn()
            oldest = conn.execute(
                "SELECT MIN(at_ms) FROM hits WHERE bucket=? AND ident=?",
                (bucket, ident),
            ).fetchone()[0]
        except Exception:  # noqa: BLE001
            return _retry_after_for(bucket, 0.0)
        if oldest is None:
            return 1
        age_s = max(0.0, (int(time.time() * 1000) - int(oldest)) / 1000.0)
        return _retry_after_for(bucket, age_s)

    def reset(self) -> None:
        try:
            conn = self._conn()
            conn.execute("DELETE FROM hits")
        except Exception as exc:  # noqa: BLE001
            log.warning("[ratelimit] sqlite reset failed: %s", exc)

    def status(self) -> dict:
        return {
            "backend": self.name,
            "distributed": True,
            "scope": "host",
            "multi_instance": False,
            "path": "configured",
            # WAL is a performance/robustness setting, not the correctness
            # mechanism (that is BEGIN IMMEDIATE + the busy timeout) — so a
            # database that refused WAL still enforces one shared quota, and the
            # degraded mode is visible here instead of only in a log line.
            "journal_mode": "wal" if self._wal else "default",
        }


def _on_store_failure(bucket: str, exc: Exception) -> tuple[bool, float]:
    closed = _fail_closed_for(bucket)
    log.error(
        "[ratelimit] shared store unavailable (%s: %s) — failing %s for bucket %r",
        type(exc).__name__,
        exc,
        "CLOSED" if closed else "OPEN",
        bucket,
    )
    return (not closed), (60.0 if closed else 0.0)


def _fail_closed_for(bucket: str) -> bool:
    if FAIL_MODE == "closed":
        return True
    if FAIL_MODE == "open":
        return False
    return any(bucket.startswith(b) for b in FAIL_CLOSED_BUCKETS)


def _is_production() -> bool:
    return (os.environ.get("FEEFIX_ENV") or "").strip().lower() in ("prod", "production")


def _sqlite_path():
    from pathlib import Path

    explicit = os.environ.get("FEEFIX_RATELIMIT_DB")
    if explicit and explicit.strip():
        return Path(explicit.strip())
    db_path = os.environ.get("FEEFIX_DB")
    if db_path and db_path.strip():
        base = Path(db_path.strip())
        return base.with_name(base.stem + ".ratelimit.db")
    return Path(__file__).resolve().parents[2] / "runtime" / "ratelimit.db"


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
            if _is_production() or _worker_hint() > 1 or _instance_hint() > 1:
                raise RuntimeError(
                    "Refusing the in-process rate limiter: it multiplies the limit by the "
                    "number of workers/instances. Set FEEFIX_REDIS_URL for more than one "
                    "machine, or FEEFIX_RATELIMIT_BACKEND=sqlite to share a file on one host. "
                    "FEEFIX_RATELIMIT_BACKEND=memory is only valid for a single local process."
                )
            _BACKEND = _MEMORY
        elif requested == "redis":
            if not url:
                raise RuntimeError("FEEFIX_RATELIMIT_BACKEND=redis requires FEEFIX_REDIS_URL.")
            client = _make_redis_client(url)
            store = RedisBackend(client, url)
            if _is_production() and not store.available():
                raise RuntimeError(
                    "FEEFIX_REDIS_URL is set but Redis did not answer. Refusing to serve "
                    "production on per-process counters."
                )
            _BACKEND = store
        elif requested == "sqlite":
            _BACKEND = SqliteBackend(_sqlite_path())
        elif url:
            try:
                client = _make_redis_client(url)
                store = RedisBackend(client, url)
                if not store.available() and _is_production():
                    raise RuntimeError(
                        "FEEFIX_REDIS_URL is set but Redis did not answer. Refusing to serve "
                        "production on per-process counters."
                    )
                _BACKEND = store
            except RuntimeError as exc:
                if _is_production():
                    raise
                log.error("[ratelimit] %s — falling back to the host-shared store.", exc)
                _BACKEND = SqliteBackend(_sqlite_path())
        elif _is_production() or _worker_hint() > 1:
            # One host, many workers: a shared file is a real counter, not a warning.
            _BACKEND = SqliteBackend(_sqlite_path())
        else:
            _BACKEND = _MEMORY
        log.info(
            "[ratelimit] backend=%s distributed=%s multi_instance=%s",
            _BACKEND.name,
            _BACKEND.distributed,
            getattr(_BACKEND, "multi_instance", False),
        )
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
    instances = _instance_hint()
    info["workers"] = workers
    info["instances"] = instances
    if not store.distributed and (workers > 1 or instances > 1):
        info["recommendation"] = (
            "Multiple workers/instances share no counter state — set FEEFIX_REDIS_URL."
        )
    elif store.name == "sqlite":
        info["recommendation"] = (
            "Counters are shared on this host only. Set FEEFIX_REDIS_URL before "
            "raising FEEFIX_INSTANCES above 1."
        )
    else:
        info["recommendation"] = None
    return info


def _worker_hint() -> int:
    for name in ("WEB_CONCURRENCY", "UVICORN_WORKERS", "GUNICORN_WORKERS"):
        raw = os.environ.get(name)
        if raw and str(raw).strip().isdigit():
            return max(1, int(str(raw).strip()))
    return 1


def _instance_hint() -> int:
    """How many machines this deploy claims to be.

    ``WEB_CONCURRENCY`` is workers on *one* host and must not be read as an
    instance count — that confusion used to demand Redis for a single box that
    a shared file already covers, and to ignore a real second instance.
    """
    raw = os.environ.get("FEEFIX_INSTANCES")
    if raw and str(raw).strip().isdigit():
        return max(1, int(str(raw).strip()))
    return 1


def warn_if_not_distributed() -> str | None:
    """Boot-time topology check. Raises when the configured store cannot hold.

    A log line is not a rate limit. Scaled-out memory counters used to warn and
    keep serving, which is the bypass (limit × N). This refuses that boot.
    """
    store = backend()
    workers = _worker_hint()
    instances = _instance_hint()
    multi = bool(getattr(store, "multi_instance", False))
    if store.name == "memory" and (workers > 1 or instances > 1 or _is_production()):
        raise RuntimeError(
            "Refusing to serve with per-process rate limits "
            f"(backend=memory, workers={workers}, instances={instances}). "
            "Set FEEFIX_REDIS_URL for more than one machine, or leave the backend on "
            "auto/sqlite so workers on one host share a file."
        )
    if instances > 1 and not multi:
        raise RuntimeError(
            f"FEEFIX_INSTANCES={instances} but the rate-limit backend is {store.name!r}, "
            "which cannot share counters across hosts. Set FEEFIX_REDIS_URL. "
            "A warning here used to keep serving; that multiplied the limit by N."
        )
    if store.name == "sqlite":
        return (
            "Rate limits are shared by every worker on this host (SQLite). "
            "They are not shared across machines — set FEEFIX_REDIS_URL before "
            "raising FEEFIX_INSTANCES above 1."
        )
    return None


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

def reset() -> None:
    """Clear every active counter (tests, and an operator's panic button)."""
    global _degraded, _last_error
    for target in ({store(), backend(), _MEMORY} if not isinstance(store(), MemoryBackend) else {store(), backend()}):
        try:
            target.reset()
        except Exception:  # pragma: no cover - store outage
            pass
    _degraded, _last_error = 0, ""

