"""Anti-replay defence — making a captured request worth exactly one use.

WHAT A REPLAY ATTACK IS HERE
============================
FeeFix authenticates with a bearer token and signs users in with one-time
codes. An attacker who can *observe* a request — a hostile Wi-Fi access point,
a compromised CDN log, a browser extension with network permissions, a TLS
terminator whose logs leak — can send the exact same bytes again. Without a
replay defence the server has no way to tell the copy from the original:

* replay ``POST /api/auth/otp/verify`` with a captured code → sign in as the
  victim *if* the code has not yet been consumed
* replay ``POST /api/auth/link-session`` with a captured bearer token → bind
  the attacker's session id to the victim's account
* replay ``DELETE /api/auth/account`` → destroy the victim's data
* replay an SMS/email delivery callback → forge a sign-in

TLS stops the *casual* observer. It does not stop a compromised intermediary,
and it does nothing at all about a request that was logged and later replayed
from inside the trust boundary. Replay defence is the control that assumes TLS
has already failed somewhere.

THE MECHANISM
=============
Two client-supplied headers on every state-changing auth request:

    X-FeeFix-Ts:     <unix seconds when the client built the request>
    X-FeeFix-Nonce:  <128+ bits of fresh randomness, never reused>

The server rejects a request when

1. the timestamp is outside :data:`security.LIMITS.REPLAY_WINDOW_S` of the
   server clock — an old capture cannot be replayed later, and a forged
   far-future timestamp cannot be pre-mined to survive the window; and
2. the ``(client_ip, nonce)`` pair has been seen before inside that window —
   the exact-same-bytes replay is caught even within the allowed skew.

Nonce keys are stored **per client IP**. That matters for availability: a
global nonce table is itself a DoS target, because an attacker who can insert
200 000 junk nonces would evict the legitimate ones and lock out every real
user. Keyed per IP, an attacker can only ever fill their own bucket — and that
bucket is already rate-limited, so filling it costs them their own access.

CLOCK SKEW
==========
The window is symmetric (±300 s) because client clocks are routinely wrong.
A one-sided window would reject honest users whose laptop clock is slow. The
nonce store is retained for slightly longer than the window
(:data:`REPLAY_NONCE_TTL_S`) so a nonce cannot expire from the cache while its
timestamp is still acceptable — that gap would be a replay hole.

MODES
=====
``off``      — defence disabled (never in production; :func:`mode` overrides)
``optional`` — validate when the client participates, tolerate when it does not
``enforce``  — the headers are mandatory

Production resolves to ``enforce`` unless an operator deliberately overrides
it, because a defence that silently degrades to nothing is not a defence.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict

from backend.services import security
from backend.services.input_guard import valid_nonce
from backend.services.security import LIMITS

OFF = "off"
OPTIONAL = "optional"
ENFORCE = "enforce"

_NONCE_HEADER = "x-feefix-nonce"
_TS_HEADER = "x-feefix-ts"

#: Public names so clients (and the Kotlin/JS references) agree on one spelling.
HEADER_NONCE = "X-FeeFix-Nonce"
HEADER_TIMESTAMP = "X-FeeFix-Ts"

_lock = threading.Lock()
# client_ip -> OrderedDict[nonce -> expires_at_monotonic]
_seen: dict[str, OrderedDict[str, float]] = {}

# Counters are exported for the health endpoint so an operator can watch the
# rollout ("how many clients still don't send nonces?") and see attacks.
_stats = {"accepted": 0, "replayed": 0, "stale": 0, "missing": 0, "malformed": 0}


class ReplayError(Exception):
    """A request failed the replay check.

    Carries a client-safe message only — the reason a replay was rejected must
    not tell the attacker *which* half of the defence caught them, because that
    is exactly the feedback needed to iterate toward a working forgery.
    """

    def __init__(self, message: str = "Request rejected — refresh and try again.") -> None:
        super().__init__(message)
        self.message = message


def mode() -> str:
    """Effective anti-replay mode for the current environment."""
    configured = (security.env_str("FEEFIX_ANTI_REPLAY") or "").strip().lower()
    if configured in (OFF, OPTIONAL, ENFORCE):
        # An explicit OFF in production is almost certainly a mistake; honour it
        # only when the operator also acknowledges the risk.
        if configured == OFF and security.is_production():
            if not security.env_bool("FEEFIX_I_ACCEPT_REPLAY_RISK", False):
                security.audit_security_event(
                    "anti_replay.off_refused",
                    "FEEFIX_ANTI_REPLAY=off ignored in production",
                )
                return ENFORCE
        return configured
    return ENFORCE if security.is_production() else OPTIONAL


def _sweep(bucket: OrderedDict[str, float], now: float) -> None:
    """Drop expired nonces from the front of an insertion-ordered map. O(evicted)."""
    while bucket:
        nonce, expires = next(iter(bucket.items()))
        if expires > now:
            return
        bucket.pop(nonce, None)


def _record(client_ip: str, nonce: str, now: float) -> bool:
    """Insert a nonce. Returns False when it was already present (a replay)."""
    ttl = float(LIMITS.REPLAY_NONCE_TTL_S)
    with _lock:
        bucket = _seen.get(client_ip)
        if bucket is None:
            bucket = OrderedDict()
            _seen[client_ip] = bucket
        _sweep(bucket, now)
        if nonce in bucket:
            # Touch it so a replayed nonce cannot be aged out early.
            bucket.move_to_end(nonce)
            return False
        bucket[nonce] = now + ttl
        bucket.move_to_end(nonce)
        # Hard per-IP ceiling: beyond this, the oldest entries go. An attacker
        # can only ever evict their own nonces — which helps nobody but us.
        while len(bucket) > LIMITS.REPLAY_MAX_NONCES:
            bucket.popitem(last=False)
        # Global ceiling on the number of tracked IPs — the map itself must be
        # bounded or it becomes the memory-exhaustion vector we are defending.
        if len(_seen) > LIMITS.RATELIMIT_MAX_BUCKETS:
            _evict_oldest_ips(now)
        return True


def _evict_oldest_ips(now: float) -> None:
    """Reclaim IP buckets whose newest nonce has already expired."""
    dead = [
        ip for ip, bucket in _seen.items()
        if not bucket or bucket[next(reversed(bucket))] <= now
    ]
    for ip in dead[: max(1, len(_seen) // 4)]:
        _seen.pop(ip, None)


def _parse_ts(raw: str | None) -> float | None:
    if not raw:
        return None
    raw = raw.strip()
    if not raw or len(raw) > 20:
        return None
    try:
        ts = float(raw)
    except ValueError:
        return None
    # Reject nonsense magnitudes early (nanoseconds, negative, year 3000).
    if not (1_000_000_000.0 <= ts <= 4_000_000_000.0):
        return None
    return ts


def check(
    *,
    client_ip: str,
    headers: dict | None,
    method: str = "POST",
    route: str = "",
) -> None:
    """Validate one request against the replay policy.

    Raises :class:`ReplayError` when the request must be refused. Idempotent
    read-only methods are exempt: replaying a ``GET`` gains an attacker nothing
    they do not already have by looking at the response they captured.
    """
    if method.upper() in ("GET", "HEAD", "OPTIONS"):
        return

    active = mode()
    if active == OFF:
        return

    headers = headers or {}
    raw_nonce = headers.get(_NONCE_HEADER) or headers.get(HEADER_NONCE)
    raw_ts = headers.get(_TS_HEADER) or headers.get(HEADER_TIMESTAMP)

    if not raw_nonce and not raw_ts:
        _bump("missing")
        if active == ENFORCE:
            raise ReplayError()
        return

    ts = _parse_ts(raw_ts)
    nonce = valid_nonce(raw_nonce)
    if ts is None or nonce is None:
        _bump("malformed")
        security.audit_security_event(
            "anti_replay.malformed", f"route={route} ip={client_ip}", None
        )
        if active == ENFORCE:
            raise ReplayError()
        return

    now = time.time()
    if abs(now - ts) > LIMITS.REPLAY_WINDOW_S:
        _bump("stale")
        security.audit_security_event(
            "anti_replay.stale", f"route={route} skew={int(now - ts)}s", None
        )
        raise ReplayError()

    if not _record(client_ip, nonce, time.monotonic()):
        _bump("replayed")
        # This is the interesting event: a genuine replay attempt, or a buggy
        # client reusing a nonce. Either way an operator wants to see it.
        security.audit_security_event(
            "anti_replay.rejected", f"route={route} ip={client_ip}", None
        )
        raise ReplayError()

    _bump("accepted")


def new_nonce() -> tuple[str, str]:
    """Mint a ``(nonce, timestamp)`` pair — used by server-side self-tests and
    by any first-party client that imports this module."""
    import secrets as _secrets

    return _secrets.token_urlsafe(24), str(int(time.time()))


def _bump(key: str) -> None:
    with _lock:
        _stats[key] = _stats.get(key, 0) + 1


def stats() -> dict:
    """Snapshot for ``/api/health`` — counts only, never nonces or IPs."""
    with _lock:
        return {
            "mode": mode(),
            "tracked_ips": len(_seen),
            "tracked_nonces": sum(len(b) for b in _seen.values()),
            **dict(_stats),
        }


def reset() -> None:
    """Clear all state (tests)."""
    with _lock:
        _seen.clear()
        for key in _stats:
            _stats[key] = 0


__all__ = [
    "ENFORCE",
    "HEADER_NONCE",
    "HEADER_TIMESTAMP",
    "OFF",
    "OPTIONAL",
    "ReplayError",
    "check",
    "mode",
    "new_nonce",
    "reset",
    "stats",
]
