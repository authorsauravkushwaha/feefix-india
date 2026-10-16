"""FeeFix authentication — accounts, memory-hard password hashing, sessions.

Password hashing (the point of the module)
------------------------------------------
**Argon2id is the default and the only scheme used for new passwords.** It is
memory-hard, so unlike PBKDF2-HMAC-SHA256 (600k iterations — OWASP-acceptable
but trivially parallelised on GPUs/ASICs) an attacker cannot buy throughput with
silicon: every guess costs ~48 MiB of RAM they must actually own.

* parameters — Argon2id, ``t=3``, ``m=48 MiB``, ``p=1``, 16-byte salt, 32-byte
  tag (OWASP's recommended range; all four knobs are env-tunable for constrained
  hosts via ``FEEFIX_ARGON2_{TIME_COST,MEMORY_KIB,PARALLELISM}``).
* ``scrypt$`` — if ``argon2-cffi`` is not installed the service degrades to
  ``hashlib.scrypt`` (n=2^15, r=8, p=1 ≈ 32 MiB, still memory-hard) and says so
  loudly at boot. It never silently falls back to PBKDF2 for new hashes.
* ``pbkdf2$`` — legacy rows keep verifying and are **transparently re-hashed to
  Argon2id on the next successful login** (see :func:`login`), so the weak
  scheme drains out of the database without a migration or a password reset.

Denial-of-service side of memory-hard hashing: 48 MiB per concurrent hash is a
lever an attacker could pull. Two bounds apply — the per-IP auth rate limit, and
a KDF concurrency semaphore (``FEEFIX_KDF_CONCURRENCY``, default 4 ⇒ at most
~192 MiB of transient hashing memory) which refuses rather than exhausts RAM.
Passwords are still length-capped and pre-hashed, so KDF cost is constant in the
input's size.

Sessions
--------
Opaque 256-bit bearer tokens (``secrets``); only the SHA-256 hash is stored, so
a database leak yields nothing replayable. 30-day rolling expiry; logout and
account deletion revoke.

Replay handling — detection *without* the self-DoS
--------------------------------------------------
Tokens rotate after ``ROTATE_AFTER_S``. The previous behaviour revoked the entire
session family the moment a superseded token was replayed, which turns one stale
tab / an offline mobile client into "you are logged out everywhere". Now:

* the **replayed (superseded) token is always killed instantly** — replay gains
  the attacker nothing;
* the **live token keeps working** (policy ``quarantine``, default), a security
  event is recorded, and the user can see it at ``GET /api/auth/security-events``
  and revoke everything deliberately with ``POST /api/auth/logout-all``;
* sustained replay is what escalates: ``FEEFIX_SESSION_REUSE_ESCALATE`` (default
  3) distinct replays inside ``REUSE_WINDOW_S`` revoke the family, because at
  that point it is no longer a benign race;
* an operator who prefers the old aggressive trade-off sets
  ``FEEFIX_SESSION_REUSE_POLICY=revoke_family``; ``observe`` records without
  killing anything.

Design choices (deliberately boring, because boring is secure):

* **Passwords** — Argon2id (memory-hard, parameters in
  ``services/passwords.py``) with transparent upgrade of legacy PBKDF2 rows on
  the next successful sign-in. A production deployment configured for Argon2id
  refuses to start without ``argon2-cffi`` rather than silently downgrading.
* **Sessions** — opaque 256-bit random bearer tokens (``secrets`` module).
  Only the **SHA-256 hash** of a token is stored, so a database leak yields
  nothing usable. 30-day rolling expiry; logout and account deletion revoke.
* **Timing safety** — verification always runs the KDF, and unknown-account
  logins burn an equivalent dummy verification; digests are compared with
  ``hmac.compare_digest``; unknown-email errors are identical to
  wrong-password errors (no user-enumeration).

Token rotation & replay detection (availability ≠ collateral damage)
--------------------------------------------------------------------
Tokens are silently rotated after ``FEEFIX_ROTATE_AFTER_S`` (24 h) and the fresh
token is returned in ``X-Session-Token``. A *superseded* token presented later is
a replay signal — but "replayed token" and "stale device/tab that has not caught
up" look identical from the server, and revoking the whole session family for a
benign race logs the user out everywhere. So:

* within ``FEEFIX_TOKEN_OVERLAP_S`` (15 min) a superseded token still
  authenticates, and if it comes from the **same client fingerprint** the server
  mints a fresh sibling token for that device — the stale client *self-heals*
  instead of hard-failing;
* beyond the overlap the stale token is refused (never the live one);
* the family is **not** revoked because a rotated token was replayed. A mobile
  client holding the previous token, or a tab that missed the rotation header,
  must not be able to log the user out of every other device. Strikes are
  recorded for operators; they do not kill the live session.
  ``FEEFIX_REPLAY_POLICY=strict`` is the explicit opt-in that restores
  revoke-the-family. ``lenient`` only logs.

The trade-off is explicit and configurable rather than accidental — see
``docs/security/SECURITY.md``.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import secrets
import threading
import uuid
from datetime import datetime, timedelta, timezone

from backend.services import db, passwords
from backend.services.limits import MAX_EMAIL_LEN, MAX_PASSWORD_LEN, MIN_PASSWORD_LEN

log = logging.getLogger("feefix.auth")

def _env_int(name: str, default: int, *, minimum: int = 1) -> int:
    raw = os.environ.get(name)
    if raw is None or not str(raw).strip():
        return default
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return default
    return value if value >= minimum else default


PBKDF2_ITERATIONS = 600_000          # legacy scheme only (verify + rehash)
SESSION_DAYS = _env_int("FEEFIX_SESSION_DAYS", 30)
# A token in continuous use longer than this is silently rotated.
ROTATE_AFTER_S = _env_int("FEEFIX_ROTATE_AFTER_S", 24 * 3600)
# How long a superseded token keeps being *useful*: inside this window a stale
# token from the same device is healed (fresh sibling) or tolerated; beyond it
# the stale token is refused. This is the knob that trades replay strictness for
# availability.
OVERLAP_S = _env_int("FEEFIX_TOKEN_OVERLAP_S", 15 * 60)
# Legacy name for the short in-flight window (kept for policy summaries).
REUSE_GRACE_S = _env_int("FEEFIX_REUSE_GRACE_S", 60)
# Window for counting replay escalations.
REUSE_WINDOW_S = 3600
# balanced (default) | strict | lenient — main's knob. The legacy branch knob
# FEEFIX_SESSION_REUSE_POLICY (quarantine | revoke_family | observe) is read at
# call time by _reuse_policy() and wins when explicitly set.
REPLAY_POLICY = (os.environ.get("FEEFIX_REPLAY_POLICY") or "balanced").strip().lower()
REPLAY_STRIKES = _env_int("FEEFIX_REPLAY_STRIKES", 5)
if REPLAY_POLICY not in ("balanced", "strict", "lenient", "quarantine"):  # pragma: no cover - config typo
    log.warning("[auth] unknown FEEFIX_REPLAY_POLICY=%r — using 'balanced'", REPLAY_POLICY)
    REPLAY_POLICY = "balanced"

_TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-]{32,128}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# -- Argon2id parameters (OWASP range; env-tunable for small hosts) ----------- #
ARGON2_TIME_COST = int(os.environ.get("FEEFIX_ARGON2_TIME_COST", "3"))
ARGON2_MEMORY_KIB = int(os.environ.get("FEEFIX_ARGON2_MEMORY_KIB", str(48 * 1024)))
ARGON2_PARALLELISM = int(os.environ.get("FEEFIX_ARGON2_PARALLELISM", "1"))
# scrypt fallback parameters (stdlib, still memory-hard: ~32 MiB per hash).
# ``maxmem`` must be given explicitly — OpenSSL's 32 MiB default is *below*
# 128·N·r, so the call would fail with "memory limit exceeded".
SCRYPT_N, SCRYPT_R, SCRYPT_P = 1 << 15, 8, 1
SCRYPT_MAXMEM = 128 * SCRYPT_N * SCRYPT_R * 2

#: Bound on concurrent KDF work — memory-hard hashing must not be able to
#: exhaust the host. Waiters time out and get a retryable error instead.
KDF_CONCURRENCY = max(1, int(os.environ.get("FEEFIX_KDF_CONCURRENCY", "4")))
KDF_WAIT_S = float(os.environ.get("FEEFIX_KDF_WAIT_S", "5"))
_KDF_SLOTS = threading.BoundedSemaphore(KDF_CONCURRENCY)

_argon2 = None
_argon2_checked = False
_backend_note = ""


class AuthError(ValueError):
    """Uniform, non-informative auth failure."""


class AuthBusy(AuthError):
    """KDF capacity is saturated — retry shortly (surfaced as 503)."""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


# -- password hashing ---------------------------------------------------------- #
def _argon2_available():
    """Import argon2 lazily once; cache the outcome (import errors are sticky)."""
    global _argon2, _argon2_checked
    if not _argon2_checked:
        _argon2_checked = True
        try:
            import argon2  # noqa: F401

            _argon2 = argon2
        except Exception as exc:  # pragma: no cover - depends on environment
            log.error(
                "[auth] argon2-cffi is unavailable (%s: %s) — new passwords use the "
                "memory-hard scrypt fallback. Install argon2-cffi for Argon2id.",
                exc.__class__.__name__,
                exc,
            )
            _argon2 = None
    return _argon2 is not None


def hash_backend() -> str:
    """Which scheme new passwords get on this host: ``argon2id`` or ``scrypt``."""
    return "argon2id" if _argon2_available() else "scrypt"


def hash_backend_note() -> str:
    """Human-readable state for /api/health (never a secret, never a hash)."""
    if hash_backend() == "argon2id":
        return (
            f"argon2id (t={ARGON2_TIME_COST}, m={ARGON2_MEMORY_KIB} KiB, "
            f"p={ARGON2_PARALLELISM})"
        )
    return f"scrypt (n=2^{SCRYPT_N.bit_length() - 1}, r={SCRYPT_R}, p={SCRYPT_P}) — install argon2-cffi"


def _prehash(password: str) -> bytes:
    """Fixed-size pre-image so KDF cost is independent of password length.

    A 100 MB "password" would otherwise force the KDF to hash megabytes — a
    trivial CPU/memory-exhaustion DoS. Hashing to 32 bytes first makes the work
    constant regardless of input size (the *long-password DoS* defence);
    ``MAX_PASSWORD_LEN`` is a second, earlier cap.
    """
    return hashlib.sha256(password.encode("utf-8")).digest()


def _kdf_slot():
    """Context manager-ish guard: acquire one KDF slot or raise AuthBusy."""
    if not _KDF_SLOTS.acquire(timeout=KDF_WAIT_S):
        raise AuthBusy("Sign-in is busy — please retry in a moment.")


def _kdf_release() -> None:
    try:
        _KDF_SLOTS.release()
    except ValueError:  # pragma: no cover - defensive
        pass


def hash_password(password: str, *, iterations: int = PBKDF2_ITERATIONS) -> str:
    """Hash a password with the best available memory-hard scheme.

    Returns the Argon2id PHC string (``$argon2id$v=19$m=49152,t=3,p=1$…``) when
    ``argon2-cffi`` is installed, otherwise ``scrypt$<n>$<r>$<p>$<salt>$<tag>``.
    PBKDF2 is **never** produced here — only :func:`legacy_pbkdf2_hash` can, and
    that exists purely for the upgrade tests. ``iterations`` is accepted for
    signature compatibility with the old API and ignored by the new schemes.
    """
    preimage = _prehash(password)
    _kdf_slot()
    try:
        if _argon2_available():
            from argon2 import PasswordHasher

            # PHC string: salt and parameters travel with the hash, so future
            # parameter raises stay verifiable for existing users.
            hasher = PasswordHasher(
                time_cost=ARGON2_TIME_COST,
                memory_cost=ARGON2_MEMORY_KIB,
                parallelism=ARGON2_PARALLELISM,
                hash_len=32,
                salt_len=16,
            )
            return hasher.hash(preimage)
        salt = secrets.token_bytes(16)
        tag = hashlib.scrypt(
            preimage, salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32,
            maxmem=SCRYPT_MAXMEM,
        )
        return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${tag.hex()}"
    finally:
        _kdf_release()


def legacy_pbkdf2_hash(password: str, *, iterations: int = PBKDF2_ITERATIONS) -> str:
    """Produce the pre-1.2 PBKDF2 format (fixtures + hash-upgrade tests only)."""
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", _prehash(password), salt, iterations)
    return f"pbkdf2${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Verify against any supported scheme: Argon2id, scrypt, legacy PBKDF2.

    Every branch runs inside a KDF slot and is constant-time on the comparison,
    and unknown-scheme rows fail closed (no scheme confusion).
    """
    if not stored:
        return False
    try:
        if stored.startswith("argon2id$"):
            # Main's storage format: ARGON2_PREFIX + PHC-without-leading-$.
            stored = "$" + stored[len("argon2id$"):]
        if stored.startswith("$argon2"):
            if not _argon2_available():
                return False
            from argon2 import PasswordHasher
            from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

            hasher = PasswordHasher()
            _kdf_slot()
            try:
                return bool(hasher.verify(stored, _prehash(password)))
            except (VerifyMismatchError, VerificationError, InvalidHashError):
                return False
            finally:
                _kdf_release()
        if stored.startswith("scrypt$"):
            scheme, n, r, p, salt_hex, tag_hex = stored.split("$")
            salt_bytes = bytes.fromhex(salt_hex)
            tag_len = len(bytes.fromhex(tag_hex))
            _kdf_slot()
            try:
                tag = hashlib.scrypt(
                    _prehash(password),
                    salt=salt_bytes,
                    n=int(n),
                    r=int(r),
                    p=int(p),
                    dklen=tag_len,
                    # Derive from the stored parameters, not a constant: a hash
                    # written with stronger parameters must stay verifiable.
                    maxmem=max(SCRYPT_MAXMEM, 128 * int(n) * int(r) * 2),
                )
            finally:
                _kdf_release()
            return hmac.compare_digest(tag, bytes.fromhex(tag_hex))
        if stored.startswith("pbkdf2$"):
            _, iterations, salt_hex, digest_hex = stored.split("$")
            salt = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(digest_hex)
            iters = int(iterations)
            _kdf_slot()
            try:
                actual = hashlib.pbkdf2_hmac("sha256", _prehash(password), salt, iters)
                # … and the legacy pre-v1 scheme that hashed the raw password.
                legacy = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters)
            finally:
                _kdf_release()
            return hmac.compare_digest(actual, expected) or hmac.compare_digest(legacy, expected)
        return False
    except AuthBusy:
        # Capacity back-pressure is NOT a wrong password. Swallowing it here made
        # a saturated KDF look like bad credentials (401), which would have
        # clients treating a load spike as an account problem.
        raise
    except Exception:
        return False


def needs_rehash(stored: str) -> bool:
    """True when a stored hash uses a weaker scheme or weaker parameters."""
    if not stored:
        return True
    if stored.startswith("$argon2"):
        try:
            from argon2 import PasswordHasher

            hasher = PasswordHasher(
                time_cost=ARGON2_TIME_COST,
                memory_cost=ARGON2_MEMORY_KIB,
                parallelism=ARGON2_PARALLELISM,
                hash_len=32,
            )
            _kdf_slot()
            try:
                return bool(hasher.check_needs_rehash(stored))
            finally:
                _kdf_release()
        except Exception:
            return False
    if stored.startswith("argon2id$"):
        # Main's storage format ("argon2id$<phc>"): only rewrite when its
        # parameters no longer match the configured policy.
        from backend.services import passwords as _passwords

        return _passwords.needs_rehash(stored)
    # scrypt (fallback) and pbkdf2 (legacy) rows: upgrade as soon as we can.
    return True


def validate_credentials(email: str, password: str) -> None:
    email = (email or "").strip()
    if not EMAIL_RE.match(email) or len(email) > MAX_EMAIL_LEN:
        raise AuthError("Enter a valid email address.")
    if len(password or "") < MIN_PASSWORD_LEN:
        raise AuthError(f"Password must be at least {MIN_PASSWORD_LEN} characters.")
    if len(password) > MAX_PASSWORD_LEN:
        raise AuthError(f"Password must be at most {MAX_PASSWORD_LEN} characters.")


# -- users ----------------------------------------------------------------------
def register(email: str, password: str, name: str | None = None) -> dict:
    validate_credentials(email, password)
    email = email.strip().lower()
    conn = db.get_connection()
    password_hash = hash_password(password)
    with db._lock:
        exists = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if exists:
            raise AuthError("An account with this email already exists.")
        user_id = uuid.uuid4().hex[:12]
        now = _iso(_utcnow())
        conn.execute(
            "INSERT INTO users (id, email, password_hash, name, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?)",
            (user_id, email, password_hash, (name or "").strip() or None, now, now),
        )
        conn.commit()
    db.audit(user_id, "auth.register", None)
    return {"id": user_id, "email": email, "name": name}


def login(email: str, password: str) -> dict:
    email = (email or "").strip().lower()
    conn = db.get_connection()
    row = conn.execute(
        "SELECT id, email, name, password_hash FROM users WHERE email=?", (email,)
    ).fetchone()
    # Always run the KDF so unknown-email and wrong-password take similar time.
    # (A saturated pool raises AuthBusy for both cases — uniformly — and the
    # caller maps it to a retryable 503.)
    stored = row["password_hash"] if row else hash_password("dummy-password")
    if not row or not verify_password(password, stored):
        raise AuthError("Invalid email or password.")
    _upgrade_hash_if_needed(row["id"], password, stored)
    db.audit(row["id"], "auth.login", None)
    return {"id": row["id"], "email": row["email"], "name": row["name"]}


def _upgrade_hash_if_needed(user_id: str, password: str, stored: str) -> None:
    """Re-hash a legacy/weak row to Argon2id after a successful sign-in.

    This is what drains PBKDF2 out of a live database: no forced reset, no
    migration window where users are locked out, and a failure here can never
    break the login that already succeeded.
    """
    if not needs_rehash(stored):
        return
    try:
        fresh = passwords.hash_password(password)
        conn = db.get_connection()
        with db._lock:
            conn.execute(
                "UPDATE users SET password_hash=?, updated_at=? WHERE id=?",
                (fresh, _iso(_utcnow()), user_id),
            )
            conn.commit()
        db.audit(user_id, "auth.password_hash_upgraded", f"to {fresh.split('$')[1] or 'argon2id'}")
    except Exception as exc:  # pragma: no cover - never break a good login
        log.warning("[auth] password hash upgrade failed: %s", exc)


# -- sessions ---------------------------------------------------------------------
def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _reuse_policy() -> str:
    policy = os.environ.get("FEEFIX_SESSION_REUSE_POLICY", "quarantine").strip().lower()
    return policy if policy in ("quarantine", "revoke_family", "observe") else "quarantine"


def _reuse_escalation_threshold() -> int:
    try:
        return max(1, int(os.environ.get("FEEFIX_SESSION_REUSE_ESCALATE", "3")))
    except ValueError:
        return 3


def _effective_replay_policy() -> str:
    """Resolve the two policy knobs into one behaviour family.

    * ``FEEFIX_SESSION_REUSE_POLICY`` (the branch knob: quarantine | revoke_family
      | observe) wins whenever it is explicitly set — including invalid values,
      which fall back to quarantine (:func:`_reuse_policy`).
    * Otherwise main's ``REPLAY_POLICY`` attr (monkeypatched by its tests, or
      ``FEEFIX_REPLAY_POLICY`` at import) maps onto the same three behaviours:
      balanced → quarantine (refuse + strikes + escalate), strict →
      revoke_family (one strike kills the family), lenient → observe (record,
      never kill).
    """
    env = os.environ.get("FEEFIX_SESSION_REUSE_POLICY")
    if env is not None and env.strip():
        return _reuse_policy()
    policy = REPLAY_POLICY
    if policy == "strict":
        return "revoke_family"
    if policy == "lenient":
        return "observe"
    if policy == "balanced":
        # Main's default spelling for "the careful middle": refusal + strikes,
        # escalate only when one fingerprint hammers past the threshold.
        return "quarantine"
    return policy  # pragma: no cover - quarantine spelling accepted directly


def _maybe_escalate(user: dict, family: str, presenter: str | None, policy: str) -> bool:
    """Family revocation for sustained same-client replay. True = revoked.

    Counted per fingerprint and scoped to the window: three replays from *one*
    client are no longer a benign race, while three devices each trying once are
    not a reason to log everybody out everywhere (the availability fix).
    """
    if policy not in ("quarantine", "balanced"):
        return False
    if _recent_replay_count(family, presenter) < _reuse_escalation_threshold():
        return False
    _revoke_family(family)
    record_security_event(
        user["id"], family, "session_family_revoked",
        f"{_recent_replay_count(family, presenter)} replays within {REUSE_WINDOW_S}s "
        "from one client — all tokens for this sign-in revoked; sign in again",
        presenter,
    )
    db.audit(user["id"], "auth.session_family_revoked", f"policy={policy}")
    return True


def prune_expired_sessions() -> int:
    """Drop sessions past their expiry (tombstones included).

    Cheap and opportunistic — called whenever a new session is minted, so the
    table cannot grow without bound even on a deployment with no cleanup job.
    """
    conn = db.get_connection()
    with db._lock:
        cur = conn.execute(
            "DELETE FROM auth_sessions WHERE expires_at < ?", (_iso(_utcnow()),)
        )
        conn.commit()
    return cur.rowcount

def client_fingerprint(request) -> str | None:
    """Stable-ish client identity: hash of User-Agent (+ language/proto hints).

    Not a security boundary on its own (a thief controls the header) — it is a
    *corroborating* signal used to distinguish "same device catching up" from
    "somebody replaying a stolen token", and it is never stored in the clear.
    """
    if request is None:
        return None
    parts = [
        request.headers.get("user-agent", ""),
        request.headers.get("accept-language", ""),
        request.headers.get("sec-ch-ua-platform", ""),
    ]
    material = "|".join(parts).strip()
    if not material or material == "||":
        return None
    return hashlib.sha256(material.encode("utf-8", "ignore")).hexdigest()[:16]


def create_session(
    user_id: str, client: str | None = None, *, session_key: str | None = None
) -> tuple[str, datetime]:
    token = secrets.token_urlsafe(32)
    now = _utcnow()
    expires = now + timedelta(days=SESSION_DAYS)
    conn = db.get_connection()
    with db._lock:
        conn.execute(
            "INSERT INTO auth_sessions"
            " (token_hash, user_id, created_at, expires_at, last_seen, client,"
            "  session_key, replaced_by, replaced_at, replay_strikes, fingerprint)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                _token_hash(token), user_id, _iso(now), _iso(expires), _iso(now), client,
                session_key or uuid.uuid4().hex, None, None, 0, client,
            ),
        )
        conn.commit()
    return token, expires


def record_security_event(
    user_id: str | None, session_key: str | None, kind: str, detail: str, client: str | None = None
) -> None:
    """Persist a session-security signal (visible to the user, auditable)."""
    try:
        conn = db.get_connection()
        with db._lock:
            conn.execute(
                "INSERT INTO auth_security_events"
                " (user_id, session_key, kind, detail, client, occurred_at)"
                " VALUES (?,?,?,?,?,?)",
                (user_id, session_key, kind, detail, client, _iso(_utcnow())),
            )
            conn.commit()
    except Exception as exc:  # pragma: no cover - never break auth over audit
        log.warning("[auth] could not record security event %s: %s", kind, exc)


def security_events(user_id: str, limit: int = 50) -> list[dict]:
    conn = db.get_connection()
    rows = conn.execute(
        "SELECT kind, detail, client, occurred_at FROM auth_security_events"
        " WHERE user_id=? ORDER BY id DESC LIMIT ?",
        (user_id, max(1, min(limit, 200))),
    ).fetchall()
    return [dict(r) for r in rows]


def _recent_replay_count(session_key: str, client: str | None = None) -> int:
    """Replay presentations for this family — optionally scoped to one client.

    Escalation counts *per fingerprint*: the same device presenting a rotated
    token three times inside the window is no longer a benign race, while three
    different devices each trying once must not trigger a family-wide logout
    (the availability fix this whole policy exists for).
    """
    conn = db.get_connection()
    since = _iso(_utcnow() - timedelta(seconds=REUSE_WINDOW_S))
    query = (
        "SELECT COUNT(*) AS n FROM auth_security_events"
        " WHERE session_key=? AND kind='token_replay' AND occurred_at >= ?"
    )
    params: list = [session_key, since]
    if client:
        query += " AND client=?"
        params.append(client)
    row = conn.execute(query, params).fetchone()
    return int(row["n"] if row else 0)


def _delete_row(token_hash: str) -> None:
    """Drop exactly one session row — never a family (see availability notes)."""
    conn = db.get_connection()
    with db._lock:
        conn.execute("DELETE FROM auth_sessions WHERE token_hash=?", (token_hash,))
        conn.commit()


def _strike_family(session_key: str, token_hash: str) -> int:
    """Count *one* replay observation against a session family; return the total.

    The strike lands on the replayed row and the total is the family maximum, so
    repeating a replay of the same stale token advances the counter by exactly
    one observation (incrementing every row would inflate the count by the
    family size and trip the threshold far too early).
    """
    conn = db.get_connection()
    with db._lock:
        conn.execute(
            "UPDATE auth_sessions SET replay_strikes = replay_strikes + 1"
            " WHERE session_key=? AND token_hash=?",
            (session_key, token_hash),
        )
        row = conn.execute(
            "SELECT COALESCE(MAX(replay_strikes), 0) AS n FROM auth_sessions WHERE session_key=?",
            (session_key,),
        ).fetchone()
        conn.commit()
    return int(row["n"]) if row else 0


def _user_of(row) -> dict:
    return {"id": row["uid"], "email": row["email"], "name": row["name"]}


def _fingerprint_matches(row, client: str | None) -> bool:
    """Same device, proven — not merely uncontradicted.

    A missing fingerprint used to count as a match. That let anyone holding a
    just-rotated token omit ``User-Agent`` and receive a freshly minted
    long-lived sibling (the heal path). Unknown is not same-device. The caller
    still must not revoke the family; it only withholds the mint.
    """
    recorded = row["fingerprint"] if "fingerprint" in row.keys() else None
    if not recorded or not client:
        return False
    return hmac.compare_digest(str(recorded), str(client))


def _handle_superseded(row, client: str | None) -> tuple[dict | None, str | None]:
    """Decide what a *superseded* (already rotated) token may do.

    Returns ``(user, new_token)``. ``user`` is ``None`` when the token is
    refused. The live token of the family is never harmed by this path unless
    the replay pattern escalates under an explicit policy.
    """
    user = _user_of(row)
    replaced_at = (
        datetime.fromisoformat(row["replaced_at"]) if row["replaced_at"] else _utcnow()
    )
    age_s = max(0.0, (_utcnow() - replaced_at).total_seconds())
    same_device = _fingerprint_matches(row, client)
    family = row["session_key"] or row["token_hash"]

    if age_s <= OVERLAP_S:
        if same_device and _claim_heal(row["token_hash"]):
            # Same device, late request: heal it *once* by minting a fresh
            # sibling so it stops using the superseded one. A retry loop must
            # not mint a new live token on every request.
            db.audit(user["id"], "auth.token_overlap_healed", f"age={int(age_s)}s")
            return user, _mint_sibling(row, client)
        if same_device:
            db.audit(user["id"], "auth.token_overlap_reused", f"age={int(age_s)}s")
            return user, None
        # Different or unproven client inside the overlap window: allow the
        # in-flight request but do not mint a long-lived token, and do not
        # touch the live session.
        db.audit(user["id"], "auth.token_overlap_foreign_client", f"age={int(age_s)}s")
        return user, None

    # Beyond the overlap: the stale token is refused. The live session is kept
    # unless the operator explicitly opted into family revocation.
    if REPLAY_POLICY == "strict":
        _revoke_family(family)
        db.audit(user["id"], "auth.token_reuse_revoked", f"age={int(age_s)}s policy=strict")
        return None, None

    strikes = _strike_family(family, row["token_hash"])
    action = (
        "auth.token_replay_observed" if REPLAY_POLICY == "lenient" else "auth.token_replay_rejected"
    )
    db.audit(
        user["id"],
        action,
        f"strikes={strikes} age={int(age_s)}s live_session_kept=true policy={REPLAY_POLICY}",
    )
    return None, None


def _claim_heal(token_hash: str) -> bool:
    """Reserve the one heal this superseded token is allowed to mint.

    Returns True only for the first caller. A stale tab that retries the old
    token therefore cannot fill ``auth_sessions`` with sibling tokens.
    """
    conn = db.get_connection()
    with db._lock:
        cur = conn.execute(
            "UPDATE auth_sessions SET heal_count = heal_count + 1"
            " WHERE token_hash=? AND heal_count < 1",
            (token_hash,),
        )
        conn.commit()
    return cur.rowcount == 1


def _mint_sibling(row, client: str | None) -> str:
    """Mint a fresh token in the same family (client self-heal path).

    The fingerprint is inherited when the caller does not know it, so a rotation
    never *loses* the device identity that replay detection relies on.
    """
    if not client:
        try:
            client = row["fingerprint"]
        except (KeyError, IndexError):  # pragma: no cover - row shim
            client = None
    new_token = secrets.token_urlsafe(32)
    now = _utcnow()
    new_hash = _token_hash(new_token)
    conn = db.get_connection()
    with db._lock:
        conn.execute(
            "INSERT INTO auth_sessions"
            " (token_hash, user_id, created_at, expires_at, last_seen, client,"
            "  session_key, replaced_by, replaced_at, replay_strikes, fingerprint)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                new_hash, row["user_id"], _iso(now), _iso(now + timedelta(days=SESSION_DAYS)),
                _iso(now), client, row["session_key"], None, None, 0, client,
            ),
        )
        conn.execute(
            "UPDATE auth_sessions SET replaced_by=?, replaced_at=? WHERE token_hash=?",
            (new_hash, _iso(now), row["token_hash"]),
        )
        conn.commit()
    return new_token


def _lookup(
    token: str, client: str | None = None, fingerprint: str | None = None
) -> tuple[dict | None, object | None, str | None]:
    """Return ``(user, row)`` for a live token, or ``(None, None)``.

    Row is returned only for tokens that are current (not superseded), so callers
    can safely touch/rotate them.
    """
    if not token or not _TOKEN_RE.match(token):
        return None, None, None
    conn = db.get_connection()
    row = conn.execute(
        "SELECT s.token_hash, s.expires_at, s.session_key, s.replaced_by, s.replaced_at,"
        " s.replayed_at, s.replay_strikes, s.fingerprint, s.heal_count, s.user_id,"
        " u.id AS uid, u.email, u.name"
        " FROM auth_sessions s JOIN users u ON u.id = s.user_id"
        " WHERE s.token_hash=?",
        (_token_hash(token),),
    ).fetchone()
    if not row:
        return None, None, None
    if datetime.fromisoformat(row["expires_at"]) < _utcnow():
        # Expiry kills exactly this token — never its family.
        _delete_row(row["token_hash"])
        return None, None, None
    if not row["replaced_by"]:
        # Live, current token: normal path (rotation/touch handled by callers).
        return _user_of(row), row, None
    user = _user_of(row)
    replaced_at = (
        datetime.fromisoformat(row["replaced_at"])
        if row["replaced_at"]
        else _utcnow()
    )
    age_s = max(0.0, (_utcnow() - replaced_at).total_seconds())
    same_device = _fingerprint_matches(row, fingerprint)
    presenter = fingerprint or client
    family = row["session_key"] or row["token_hash"]

    if age_s <= OVERLAP_S:
        # Inside the overlap window the stale token is *useful*, not hostile:
        # heal the same device once, tolerate everyone else without minting.
        record_security_event(
            user["id"], family, "token_replay",
            (
                f"stale token presented {int(age_s)}s after rotation"
                + (" — healed for the same device" if same_device else " (foreign client, tolerated)")
            ),
            presenter,
        )
        policy = _effective_replay_policy()
        if _maybe_escalate(user, family, presenter, policy):
            return None, None, "stale-token-replayed"
        if same_device and _claim_heal(row["token_hash"]):
            db.audit(user["id"], "auth.token_overlap_healed", f"age={int(age_s)}s")
            return user, _SupersededRow(row, _mint_sibling(row, fingerprint or client)), None
        if same_device:
            db.audit(user["id"], "auth.token_overlap_reused", f"age={int(age_s)}s")
        else:
            db.audit(user["id"], "auth.token_overlap_foreign_client", f"age={int(age_s)}s")
        return user, _SupersededRow(row, None), None

    # Beyond the overlap: the stale token is refused. The live session is kept
    # unless the operator's policy says otherwise or the pattern escalates.
    record_security_event(
        user["id"], family, "token_replay",
        f"stale token replayed {int(age_s)}s after rotation (outside the overlap window)",
        presenter,
    )
    policy = _effective_replay_policy()
    if policy == "revoke_family":
        _revoke_family(family)
        db.audit(user["id"], "auth.token_reuse_revoked", f"age={int(age_s)}s policy=revoke_family")
        return None, None, "stale-token-replayed"
    if policy == "observe":
        db.audit(user["id"], "auth.token_replay_observed", f"age={int(age_s)}s policy=observe")
        return None, None, "stale-token-replayed"
    # quarantine (and main's balanced spelling of it): strikes are recorded and
    # the family is revoked only when ONE fingerprint hammers past the threshold
    # inside the window — different devices each trying once never escalate.
    db.audit(user["id"], "auth.token_replay_rejected", f"age={int(age_s)}s policy={policy}")
    _maybe_escalate(user, family, presenter, policy)
    return None, None, "stale-token-replayed"


class _SupersededRow:
    """Marks a superseded-but-tolerated token so callers don't rotate it again."""

    __slots__ = ("_row", "healed_token")

    def __init__(self, row, healed_token: str | None) -> None:
        self._row = row
        self.healed_token = healed_token

    def __getitem__(self, key):  # pragma: no cover - row passthrough
        return self._row[key]

    def keys(self):  # pragma: no cover
        return self._row.keys()

    def get(self, key, default=None):  # pragma: no cover - row passthrough
        try:
            return self._row[key]
        except (KeyError, IndexError):
            return default

    superseded = True



def _touch(row) -> None:
    """Sliding 30-day expiry on activity (rolling window)."""
    conn = db.get_connection()
    now = _utcnow()
    with db._lock:
        conn.execute(
            "UPDATE auth_sessions SET last_seen=?, expires_at=? WHERE token_hash=?",
            (_iso(now), _iso(now + timedelta(days=SESSION_DAYS)), row["token_hash"]),
        )
        conn.commit()


def resolve_token(token: str | None, client: str | None = None, fingerprint: str | None = None) -> dict | None:
    """Bearer token → user dict (rolling refresh) or None. No rotation here."""
    user, row, warning = _lookup(token, client, fingerprint)
    if user is None or row is None:
        return None
    if isinstance(row, _SupersededRow):  # tolerated stale token; already refreshed
        return user
    if not row["replaced_by"]:
        _touch(row)
    return user

    return user


def resolve_and_rotate(
    token: str | None, client: str | None = None, fingerprint: str | None = None
) -> tuple[dict | None, str | None, str | None]:
    """Resolve a bearer token, rotating it if it has aged past ``ROTATE_AFTER_S``.

    Returns ``(user, new_token, warning)``: ``new_token`` is set when a rotation
    (or a self-heal for a late client) handed the caller a fresher token;
    ``warning`` carries a client-visible signal such as ``stale-token-replayed``
    so the UI can prompt a re-login after a *detected* replay instead of being
    silently logged out.
    """
    user, row, warning = _lookup(token, client, fingerprint)
    if user is None:
        return None, None, warning
    if isinstance(row, _SupersededRow):
        return user, row.healed_token, None

    conn = db.get_connection()
    created_row = conn.execute(
        "SELECT created_at FROM auth_sessions WHERE token_hash=?", (row["token_hash"],)
    ).fetchone()
    created = datetime.fromisoformat(created_row["created_at"])
    if (_utcnow() - created).total_seconds() < ROTATE_AFTER_S:
        _touch(row)
        return user, None, None
    # Rotate: mint a new token in the same family, mark the old one superseded.
    new_token = _mint_sibling(row, fingerprint or client)
    db.audit(user["id"], "auth.token_rotated", None)
    return user, new_token, None


def _revoke_family(session_key: str) -> None:
    conn = db.get_connection()
    with db._lock:
        conn.execute("DELETE FROM auth_sessions WHERE session_key=?", (session_key,))
        conn.commit()


def revoke_token(token: str) -> bool:
    """Logout: revoke the whole rotation family this token belongs to."""
    if not token or not _TOKEN_RE.match(token):
        return False
    conn = db.get_connection()
    with db._lock:
        row = conn.execute(
            "SELECT session_key FROM auth_sessions WHERE token_hash=?", (_token_hash(token),)
        ).fetchone()
        if not row:
            return False
        key = row["session_key"] or _token_hash(token)
        cur = conn.execute("DELETE FROM auth_sessions WHERE session_key=?", (key,))
        conn.commit()
    return cur.rowcount > 0


def revoke_all_user_tokens(user_id: str) -> None:
    conn = db.get_connection()
    with db._lock:
        conn.execute("DELETE FROM auth_sessions WHERE user_id=?", (user_id,))
        conn.commit()


def delete_account(user_id: str) -> None:
    """Right-to-erasure: user → tokens → owned profiles/tracker rows → documents.

    Uploaded document bytes are removed from disk too — deleting an account must
    not leave the student's certificates behind.
    """
    conn = db.get_connection()
    with db._lock:
        owned = [
            r["session_id"]
            for r in conn.execute(
                "SELECT session_id FROM profiles WHERE user_id=?", (user_id,)
            ).fetchall()
        ]
        documents = [
            r["stored_name"]
            for r in conn.execute(
                "SELECT stored_name FROM documents WHERE user_id=?", (user_id,)
            ).fetchall()
        ]
        for sid in owned:
            conn.execute("DELETE FROM tracker WHERE session_id=?", (sid,))
        conn.execute("DELETE FROM profiles WHERE user_id=?", (user_id,))
        conn.execute("DELETE FROM documents WHERE user_id=?", (user_id,))
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.commit()
    if documents:
        from backend.services.documents import remove_stored_files

        remove_stored_files(documents)
    db.audit(user_id, "auth.delete_account", f"owned_sessions={len(owned)} documents={len(documents)}")


    db.audit(user_id, "auth.delete_account", f"owned_sessions={len(owned)}")


def policy_summary() -> dict:
    """Non-secret summary of rotation/replay policy (docs, `/api/meta`)."""
    return {
        "rotate_after_s": ROTATE_AFTER_S,
        "token_overlap_s": OVERLAP_S,
        "replay_policy": REPLAY_POLICY,
        "replay_strikes": REPLAY_STRIKES,
        "reuse_grace_s": REUSE_GRACE_S,
        "session_days": SESSION_DAYS,
    }

