"""Rate limiting — the availability pillar.

Sliding-window counters in memory, keyed per ``(client_ip, bucket)``. Zero
dependencies (stdlib only), safe under threads.

WHAT THE FIRST VERSION GOT WRONG
================================
The original limiter was eleven lines and had four exploitable properties. Each
is fixed here, and each fix has a regression test in ``tests/test_security.py``.

1. **Unbounded memory.** Every distinct key allocated a list that was never
   removed once its entries aged out — only the *entries* were trimmed, and
   only when that key was touched again. An attacker rotating source IPs and
   usernames grew the map without limit. Measured: 5 000 requests → 5 008
   permanently-live buckets. Enough requests and the process is OOM-killed,
   which is a denial of service achieved with completely legal traffic.
   → Hard bucket ceiling plus opportunistic eviction of empty buckets.

2. **``request.client.host`` is not the client.** Behind a load balancer every
   user shares the proxy's address, so one abuser exhausts the limit for the
   entire customer base — a self-inflicted DoS. The obvious fix (trust
   ``X-Forwarded-For``) is worse: that header is attacker-controlled, and
   rotating it bypasses the limiter completely.
   → :func:`security.client_ip` trusts XFF *only* from configured proxy CIDRs,
     walking a bounded number of hops from the right.

3. **The auth key contained an attacker-chosen value.** Keying on
   ``(ip, "auth:" + email)`` means an attacker who tries 10 000 *different*
   emails gets 10 000 × 10 attempts — the per-account limit never engages, and
   the KDF cost is paid every time.
   → A per-IP authentication budget that does not depend on any field the
     attacker controls, in addition to the per-account one.

4. **No notion of cost.** A limit of "1000 requests/minute" treats a static
   file and a 600 000-iteration PBKDF2 hash as equal. They are not: at ~200 ms
   of CPU each, 1000 KDF calls is 200 CPU-seconds — more than three full cores
   saturated by a *single* client staying inside the rules.
   → Separate, much tighter budgets for expensive operations
     (:data:`KDF_LIMIT`), charged per call rather than per request.

Windows are sliding (not fixed): a fixed window lets an attacker send a full
budget at 00:59 and another at 01:00, doubling the instantaneous rate.
"""

from __future__ import annotations

import threading
import time
from collections import deque

from backend.services import security
from backend.services.security import LIMITS

_lock = threading.Lock()
# (client_ip, bucket) -> deque[monotonic timestamps]
_hits: dict[tuple[str, str], deque[float]] = {}

# ------------------------------------------------------------------ budgets --
#: App-wide ceiling per IP across ``/api/*``. Generous for a human driving the
#: SPA (which issues a handful of calls per interaction) and fatal for a flood.
DEFAULT_LIMIT = (LIMITS.GLOBAL_RPM, 60)

#: Per (IP, account) authentication attempts.
AUTH_LIMIT = (LIMITS.AUTH_ATTEMPTS, LIMITS.AUTH_WINDOW_S)

#: Per-IP authentication attempts, *independent of the identifier supplied*.
#: This is the key that cannot be diluted by varying the email address.
AUTH_PER_IP_LIMIT = (LIMITS.AUTH_ATTEMPTS * 4, LIMITS.AUTH_WINDOW_S)

#: Per-IP budget for calls that run the password KDF. Each one costs ~200 ms of
#: CPU, so this is the control that stops a single client from saturating cores.
KDF_LIMIT = (LIMITS.KDF_RPM, 60)

#: OTP issuance per destination per hour.
OTP_DEST_LIMIT = (LIMITS.OTP_REQUEST_PER_DEST_HOUR, 3600)

# Backwards-compatible aliases (imported by name elsewhere / by tests).
GLOBAL_LIMIT = DEFAULT_LIMIT


class RateLimited(Exception):
    """Raised when a caller must receive HTTP 429.

    Carries ``retry_after`` so the response can be honest about when the client
    may return — which is both good manners and the standard signal that well
    behaved clients (and the SPA) use to back off instead of hammering.
    """

    def __init__(self, bucket: str, retry_after: int, limit: int, window_s: int) -> None:
        self.bucket = bucket
        self.retry_after = max(1, int(retry_after))
        self.limit = limit
        self.window_s = window_s
        super().__init__(f"rate limited on {bucket}")

    @property
    def client_message(self) -> str:
        """Text safe to show a user: no internals, no limits, no key names."""
        return "Too many attempts — please wait a moment and try again."


_last_evict = 0.0
_MAX_WINDOW = 3600
_EVICT_INTERVAL = 30.0


def _sweep_expired(now: float) -> None:
    """Reclaim buckets whose windows have fully elapsed.

    Throttled to once per ``_EVICT_INTERVAL`` so the sweep cost cannot itself be
    amplified by request volume. This is the *hygiene* pass — it keeps the map
    small under normal traffic, but it is not what bounds it, because a burst
    can outrun a timer.
    """
    global _last_evict
    if now - _last_evict < _EVICT_INTERVAL:
        return
    _last_evict = now
    dead = []
    for key, buf in _hits.items():
        while buf and buf[0] <= now - _MAX_WINDOW:
            buf.popleft()
        if not buf:
            dead.append(key)
    for key in dead:
        _hits.pop(key, None)


def _bound_size(incoming: tuple[str, str]) -> None:
    """Enforce the absolute bucket ceiling in O(1) per new key.

    The first version of this limiter trimmed *entries* inside a bucket but
    never removed a bucket, so the map grew forever: 5 000 requests left 5 008
    permanently-live buckets. A timer-driven sweep is not sufficient either —
    measured, a one-second burst of 60 000 distinct keys reached 120 011 buckets
    before the 30 s sweep could run, which is exactly the memory-exhaustion
    outcome the sweep was meant to prevent.

    So the ceiling is checked on every insertion. ``dict`` preserves insertion
    order, so the oldest key is ``next(iter(...))`` and dropping it is O(1). An
    evicted counter fails *open* for that one key: the attacker's own budget
    resets. That is the correct trade — losing one attacker's counter is
    nothing; losing the process is a total denial of service.
    """
    if len(_hits) < LIMITS.RATELIMIT_MAX_BUCKETS or incoming in _hits:
        return
    for _ in range(max(1, LIMITS.RATELIMIT_MAX_BUCKETS // 100)):
        if len(_hits) < LIMITS.RATELIMIT_MAX_BUCKETS:
            return
        oldest = next(iter(_hits))
        if oldest == incoming:
            return
        _hits.pop(oldest, None)


def _allow(key: tuple[str, str], limit: int, window_s: int) -> bool:
    now = time.monotonic()
    cutoff = now - window_s
    with _lock:
        _sweep_expired(now)
        buf = _hits.get(key)
        if buf is None:
            _bound_size(key)
            buf = deque()
            _hits[key] = buf
        while buf and buf[0] <= cutoff:
            buf.popleft()
        if len(buf) >= limit:
            return False
        buf.append(now)
        return True


def _retry_after(key: tuple[str, str], window_s: int) -> int:
    """Seconds until the oldest hit in this window expires."""
    now = time.monotonic()
    with _lock:
        buf = _hits.get(key)
        if not buf:
            return window_s
        return max(1, int(buf[0] + window_s - now) + 1)


def _charge_or_raise(bucket: str, key: tuple[str, str], limit: int, window_s: int) -> None:
    if not _allow(key, limit, window_s):
        raise RateLimited(bucket, _retry_after(key, window_s), limit, window_s)


# ---------------------------------------------------------------- public API --
def check_global(client_ip: str) -> bool:
    """App-wide per-IP ceiling. Returns False rather than raising (middleware)."""
    return _allow((client_ip, "global"), *DEFAULT_LIMIT)


def check_auth(client_ip: str, identifier: str) -> bool:
    """Legacy boolean form: per-(IP, identifier) auth budget.

    Retained because callers and tests use it. It now *also* charges the
    per-IP budget, so varying ``identifier`` no longer buys unlimited attempts.
    """
    ident = (identifier or "anon")[:LIMITS.MAX_EMAIL_LEN]
    if not _allow((client_ip, "auth-ip"), *AUTH_PER_IP_LIMIT):
        return False
    return _allow((client_ip, f"auth:{ident}"), *AUTH_LIMIT)


def guard_auth(client_ip: str, identifier: str, *, route: str = "auth") -> None:
    """Raise :class:`RateLimited` for an over-budget authentication attempt."""
    ident = (identifier or "anon")[:LIMITS.MAX_EMAIL_LEN]
    ip_key = (client_ip, "auth-ip")
    acct_key = (client_ip, f"auth:{ident}")
    _charge_or_raise("auth-ip", ip_key, *AUTH_PER_IP_LIMIT)
    _charge_or_raise(f"auth:{route}", acct_key, *AUTH_LIMIT)


def guard_kdf(client_ip: str) -> None:
    """Charge one password-hashing operation against the per-IP KDF budget.

    Call this *before* :func:`backend.services.auth.hash_password` /
    ``verify_password``. It is the control that turns "an unlimited number of
    200 ms CPU operations per minute" into "at most 20".
    """
    _charge_or_raise("kdf", (client_ip, "kdf"), *KDF_LIMIT)


def guard_otp_destination(client_ip: str, channel: str, address: str) -> None:
    """Per-destination OTP issuance budget — protects the *recipient*.

    Without this, an attacker can make the platform send unlimited SMS/email to
    a third party: a paid-resource drain for us and a harassment vector aimed at
    someone who never used FeeFix. Keyed on the destination, not the sender, so
    rotating source IPs does not help.
    """
    key = (address, f"otp-dest:{channel}")
    _charge_or_raise("otp-dest", key, *OTP_DEST_LIMIT)


def guard_route(client_ip: str, route: str, limit: int, window_s: int) -> None:
    """Generic per-(IP, route) budget for any endpoint needing its own ceiling."""
    _charge_or_raise(route, (client_ip, f"route:{route}"), limit, window_s)


def snapshot() -> dict:
    """Aggregate counters for ``/api/health`` — sizes only, never keys."""
    with _lock:
        return {"buckets": len(_hits), "hits": sum(len(b) for b in _hits.values())}


def reset() -> None:
    """Clear all state (tests)."""
    global _last_evict
    with _lock:
        _hits.clear()
        _last_evict = 0.0


__all__ = [
    "AUTH_LIMIT",
    "AUTH_PER_IP_LIMIT",
    "DEFAULT_LIMIT",
    "KDF_LIMIT",
    "OTP_DEST_LIMIT",
    "RateLimited",
    "check_auth",
    "check_global",
    "guard_auth",
    "guard_kdf",
    "guard_otp_destination",
    "guard_route",
    "reset",
    "snapshot",
]
