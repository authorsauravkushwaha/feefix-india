"""Rate limiting — the availability pillar.

Sliding-window counters in memory, keyed per (client_ip, bucket). Generous
defaults so interactive use never notices; strict buckets on auth endpoints to
blunt credential brute-forcing. Zero dependencies (stdlib only).

Hardening beyond a naive counter:

* **Tiered buckets** — expensive endpoints (AI Q&A, semantic search, chat,
  event ingest) get their own tighter limits so one client can't monopolise
  CPU-heavy embedding work.
* **Bounded memory** — the hit table is capped and periodically swept, so a
  flood from many source IPs can't grow the process without limit (its own
  DoS vector).
* **Proxy-aware** — behind a trusted reverse proxy the real client IP is taken
  from ``X-Forwarded-For`` (opt-in via ``FEEFIX_TRUST_PROXY``); otherwise the
  header is ignored so it can't be spoofed to evade limits.
"""

from __future__ import annotations

import os
import threading
import time

_lock = threading.Lock()
_hits: dict[tuple[str, str], list[float]] = {}

DEFAULT_LIMIT = (1000, 60)       # 1000 requests / 60s per IP (app-wide)
AUTH_LIMIT = (10, 300)           # 10 auth attempts / 5 min per IP+account
EXPENSIVE_LIMIT = (30, 60)       # 30 CPU-heavy calls / 60s per IP

# Endpoints whose work is CPU-heavy (embeddings / matching) and get the
# tighter EXPENSIVE_LIMIT instead of the global one.
EXPENSIVE_PATHS = ("/api/ask", "/api/search/semantic", "/api/chat", "/api/events")

# Backstop: never track more than this many distinct keys at once.
_MAX_KEYS = 50_000


def _trust_proxy() -> bool:
    return os.environ.get("FEEFIX_TRUST_PROXY", "").lower() in ("1", "true", "yes", "on")


def client_ip(request) -> str:
    """Real client IP — honour X-Forwarded-For only behind a trusted proxy."""
    if _trust_proxy():
        xff = request.headers.get("x-forwarded-for", "")
        if xff:
            return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _sweep(now: float) -> None:
    """Drop empty / fully-expired buckets; hard-cap the table if still too big."""
    if len(_hits) < _MAX_KEYS:
        # cheap pass: remove buckets whose newest hit is older than any window
        stale = [k for k, buf in _hits.items() if not buf or buf[-1] < now - 3600]
        for k in stale:
            _hits.pop(k, None)
        return
    # Emergency: keep only the most recently active keys.
    for k in sorted(_hits, key=lambda k: _hits[k][-1] if _hits[k] else 0)[: _MAX_KEYS // 2]:
        _hits.pop(k, None)


def _allow(key: tuple[str, str], limit: int, window_s: int) -> bool:
    now = time.monotonic()
    with _lock:
        buf = _hits.setdefault(key, [])
        cutoff = now - window_s
        while buf and buf[0] < cutoff:
            buf.pop(0)
        if len(buf) >= limit:
            return False
        buf.append(now)
        if len(_hits) > _MAX_KEYS:
            _sweep(now)
        return True


def retry_after(client_ip_: str, bucket: str) -> int:
    """Seconds until the oldest hit in a bucket's window ages out (for 429)."""
    now = time.monotonic()
    with _lock:
        buf = _hits.get((client_ip_, bucket), [])
        if not buf:
            return 1
        return max(1, int(buf[0] + _window_for(bucket) - now) + 1)


def _window_for(bucket: str) -> int:
    if bucket.startswith("auth:") or bucket == "global":
        return AUTH_LIMIT[1] if bucket.startswith("auth:") else DEFAULT_LIMIT[1]
    return EXPENSIVE_LIMIT[1]


def check_global(client_ip: str) -> bool:
    return _allow((client_ip, "global"), *DEFAULT_LIMIT)


def check_auth(client_ip: str, identifier: str) -> bool:
    return _allow((client_ip, f"auth:{identifier}"), *AUTH_LIMIT)


def check_expensive(client_ip: str, bucket: str) -> bool:
    return _allow((client_ip, f"exp:{bucket}"), *EXPENSIVE_LIMIT)


def reset() -> None:  # tests
    with _lock:
        _hits.clear()
