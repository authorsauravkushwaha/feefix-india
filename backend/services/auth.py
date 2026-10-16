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

from backend.services import db
from backend.services.limits import MAX_EMAIL_LEN, MAX_PASSWORD_LEN, MIN_PASSWORD_LEN

log = logging.getLogger("feefix.auth")

PBKDF2_ITERATIONS = 600_000          # legacy scheme only (verify + rehash)
SESSION_DAYS = 30
ROTATE_AFTER_S = 24 * 3600           # rotate a token that has lived a full day
REUSE_GRACE_S = 60                   # in-flight tolerance before "reuse" = theft
REUSE_WINDOW_S = 3600                # window for counting replays / escalation
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
        fresh = hash_password(password)
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


def create_session(user_id: str, client: str | None = None) -> tuple[str, datetime]:
    prune_expired_sessions()
    token = secrets.token_urlsafe(32)
    now = _utcnow()
    expires = now + timedelta(days=SESSION_DAYS)
    conn = db.get_connection()
    with db._lock:
        conn.execute(
            "INSERT INTO auth_sessions"
            " (token_hash, user_id, created_at, expires_at, last_seen, client,"
            "  session_key, replaced_by, replaced_at)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (
                _token_hash(token), user_id, _iso(now), _iso(expires), _iso(now), client,
                uuid.uuid4().hex, None, None,
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


def _recent_replay_count(session_key: str) -> int:
    conn = db.get_connection()
    since = _iso(_utcnow() - timedelta(seconds=REUSE_WINDOW_S))
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM auth_security_events"
        " WHERE session_key=? AND kind='token_replay' AND occurred_at >= ?",
        (session_key, since),
    ).fetchone()
    return int(row["n"] if row else 0)


def _lookup(token: str, client: str | None = None) -> tuple[dict | None, object | None, str | None]:
    """Resolve a token → ``(user, row, warning)``.

    Anti-replay with an availability floor: a replayed superseded token is
    *tombstoned* (deleted would hide repeat attempts) and recorded; the live
    token in the same family keeps working unless the replay pattern escalates
    or the operator opted into whole-family revocation.
    """
    if not token or not _TOKEN_RE.match(token):
        return None, None, None
    conn = db.get_connection()
    row = conn.execute(
        "SELECT s.token_hash, s.expires_at, s.session_key, s.replaced_by, s.replaced_at,"
        " s.replayed_at, u.id AS uid, u.email, u.name"
        " FROM auth_sessions s JOIN users u ON u.id = s.user_id"
        " WHERE s.token_hash=?",
        (_token_hash(token),),
    ).fetchone()
    if not row:
        return None, None, None
    if datetime.fromisoformat(row["expires_at"]) < _utcnow():
        revoke_token(token)
        return None, None, None
    user = {"id": row["uid"], "email": row["email"], "name": row["name"]}
    if row["replaced_by"] or row["replayed_at"]:
        replaced_at = (
            datetime.fromisoformat(row["replaced_at"] or row["replayed_at"])
            if (row["replaced_at"] or row["replayed_at"])
            else _utcnow()
        )
        if not row["replayed_at"] and (_utcnow() - replaced_at).total_seconds() <= REUSE_GRACE_S:
            # Within the grace window: a concurrent in-flight request that
            # started just before rotation — same user, still honoured.
            return user, row, None
        return _handle_replay(row, user, client)
    return user, row, None


def _handle_replay(row, user: dict, client: str | None):
    """Neutralise the replayed token; escalate only when the pattern says 'not a race'.

    The row is *tombstoned* rather than deleted: the token is dead either way
    (we never authenticate it again), but keeping it means a repeat attempt is
    still attributable — which is what makes escalation possible at all — and it
    costs an attacker nothing to try again, so we must be able to count it.
    """
    conn = db.get_connection()
    session_key = row["session_key"] or row["token_hash"]
    repeat = bool(row["replayed_at"])
    with db._lock:
        # Tombstone only — the *live* token of this family is deliberately left
        # alone (that is the availability fix); escalation below decides whether
        # the family should go too.
        conn.execute(
            "UPDATE auth_sessions SET replayed_at=? WHERE token_hash=?",
            (_iso(_utcnow()), row["token_hash"]),
        )
        conn.commit()
    record_security_event(
        user["id"], session_key, "token_replay",
        "superseded session token replayed outside the grace window"
        + (" (repeat attempt)" if repeat else ""),
        client,
    )
    db.audit(user["id"], "auth.token_replay_detected", f"policy={_reuse_policy()} repeat={repeat}")

    policy = _reuse_policy()
    replays = _recent_replay_count(session_key)
    escalate = policy == "revoke_family" or (
        policy == "quarantine" and replays >= _reuse_escalation_threshold()
    )
    if escalate and policy != "observe":
        _revoke_family(session_key)
        record_security_event(
            user["id"], session_key, "session_family_revoked",
            f"{replays} replays within {REUSE_WINDOW_S}s — all tokens for this "
            "sign-in revoked; sign in again",
            client,
        )
        db.audit(user["id"], "auth.session_family_revoked", f"replays={replays}")
    return None, None, "stale-token-replayed"


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


def resolve_token(token: str | None) -> dict | None:
    """Bearer token → user dict (rolling refresh) or None. No rotation here."""
    user, row, _warning = _lookup(token)
    if user is None:
        return None
    if not row["replaced_by"] and not row["replayed_at"]:
        _touch(row)
    return user


def resolve_and_rotate(
    token: str | None, client: str | None = None
) -> tuple[dict | None, str | None, str | None]:
    """Resolve a bearer token, rotating it if it has aged past ``ROTATE_AFTER_S``.

    Returns ``(user, new_token, warning)``: ``new_token`` is set only when a
    rotation happened, and ``warning`` carries a client-visible signal such as
    ``stale-token-replayed`` so the UI can prompt a re-login after a *detected*
    replay instead of being silently logged out.
    """
    user, row, warning = _lookup(token, client)
    if user is None or row["replaced_by"] or row["replayed_at"]:
        return user, None, warning
    conn = db.get_connection()
    created = datetime.fromisoformat(
        conn.execute(
            "SELECT created_at FROM auth_sessions WHERE token_hash=?", (row["token_hash"],)
        ).fetchone()["created_at"]
    )
    if (_utcnow() - created).total_seconds() < ROTATE_AFTER_S:
        _touch(row)
        return user, None, None
    # Rotate: mint a new token in the same family, mark the old one superseded.
    new_token = secrets.token_urlsafe(32)
    now = _utcnow()
    new_hash = _token_hash(new_token)
    with db._lock:
        conn.execute(
            "INSERT INTO auth_sessions"
            " (token_hash, user_id, created_at, expires_at, last_seen, client,"
            "  session_key, replaced_by, replaced_at)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (
                new_hash, row["uid"], _iso(now),
                _iso(now + timedelta(days=SESSION_DAYS)), _iso(now), client,
                row["session_key"], None, None,
            ),
        )
        conn.execute(
            "UPDATE auth_sessions SET replaced_by=?, replaced_at=? WHERE token_hash=?",
            (new_hash, _iso(now), row["token_hash"]),
        )
        conn.commit()
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
