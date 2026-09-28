"""Rate limiting — the availability pillar.

Sliding-window counters in memory, keyed per (client_ip, bucket). Generous
defaults so interactive use never notices; strict buckets on auth endpoints
to blunt credential brute-forcing. Zero dependencies (stdlib only).
"""

from __future__ import annotations

import threading
import time

_lock = threading.Lock()
_hits: dict[tuple[str, str], list[float]] = {}

DEFAULT_LIMIT = (1000, 60)       # 1000 requests / 60s per IP (app-wide)
AUTH_LIMIT = (10, 300)           # 10 auth attempts / 5 min per IP+account


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
        return True


def check_global(client_ip: str) -> bool:
    return _allow((client_ip, "global"), *DEFAULT_LIMIT)


def check_auth(client_ip: str, identifier: str) -> bool:
    return _allow((client_ip, f"auth:{identifier}"), *AUTH_LIMIT)


def reset() -> None:  # tests
    with _lock:
        _hits.clear()
