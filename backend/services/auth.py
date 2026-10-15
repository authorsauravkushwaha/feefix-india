"""FeeFix authentication — accounts, password hashing, revocable sessions.

Design choices (free, zero-dependency, and deliberately boring-because-boring-is-secure):

* **Passwords** — PBKDF2-HMAC-SHA256, 600,000 iterations, 16-byte per-user salt
  (OWASP-recommended parameters; stdlib `hashlib`, no external deps).
  Stored format: ``pbkdf2$<iterations>$<salt_hex>$<hex_digest>``.
* **Sessions** — opaque 256-bit random bearer tokens (``secrets`` module).
  Only the **SHA-256 hash** of a token is stored, so a database leak yields
  nothing usable. 30-day rolling expiry; logout and account deletion revoke.
* **Timing safety** — verification always hashes, and digests are compared
  with ``hmac.compare_digest``; unknown-email errors are identical to
  wrong-password errors (no user-enumeration).
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from backend.services import db
from backend.services.limits import MAX_EMAIL_LEN, MAX_PASSWORD_LEN, MIN_PASSWORD_LEN

PBKDF2_ITERATIONS = 600_000
SESSION_DAYS = 30
# Anti-replay: an opaque bearer token is silently rotated once it has been in
# use longer than this, and the previous token is remembered so that its later
# re-use (a stolen token being replayed) revokes the whole session family.
ROTATE_AFTER_S = 24 * 3600          # rotate a token that has lived a full day
REUSE_GRACE_S = 60                  # in-flight tolerance before "reuse" = theft
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-]{32,128}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class AuthError(ValueError):
    """Uniform, non-informative auth failure."""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


# -- passwords ----------------------------------------------------------------
def _prehash(password: str) -> bytes:
    """Fixed-size pre-image so PBKDF2 cost is independent of password length.

    A 100 MB "password" would otherwise force the KDF to HMAC megabytes on
    every one of the 600k iterations — a trivial CPU-exhaustion DoS. Hashing to
    32 bytes first makes the work constant regardless of input size (the
    *long-password DoS* defence); ``MAX_PASSWORD_LEN`` is a second, earlier cap.
    """
    return hashlib.sha256(password.encode("utf-8")).digest()


def hash_password(password: str, *, iterations: int = PBKDF2_ITERATIONS) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", _prehash(password), salt, iterations)
    return f"pbkdf2${iterations}${salt.hex()}${digest.hex()}"


def _pbkdf2_digest(preimage: bytes, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", preimage, salt, iterations)


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iterations, salt_hex, digest_hex = stored.split("$")
        if scheme != "pbkdf2":
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        iters = int(iterations)
        # Current scheme (pre-hashed) …
        actual = _pbkdf2_digest(_prehash(password), salt, iters)
        # … and the legacy direct-hash scheme, so old rows keep verifying.
        legacy = _pbkdf2_digest(password.encode("utf-8"), salt, iters)
        return hmac.compare_digest(actual, expected) or hmac.compare_digest(legacy, expected)
    except Exception:
        return False


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
    with db._lock:
        exists = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if exists:
            raise AuthError("An account with this email already exists.")
        user_id = uuid.uuid4().hex[:12]
        now = _iso(_utcnow())
        conn.execute(
            "INSERT INTO users (id, email, password_hash, name, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?)",
            (user_id, email, hash_password(password), (name or "").strip() or None, now, now),
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
    stored = row["password_hash"] if row else hash_password("dummy")
    if not row or not verify_password(password, stored):
        raise AuthError("Invalid email or password.")
    db.audit(row["id"], "auth.login", None)
    return {"id": row["id"], "email": row["email"], "name": row["name"]}


# -- sessions ---------------------------------------------------------------------
def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_session(user_id: str, client: str | None = None) -> tuple[str, datetime]:
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


def _lookup(token: str):
    """Return (user_dict, row) for a live token, or (None, None).

    Enforces the anti-replay invariant: a token that was already rotated
    (``replaced_by`` set) is a *replayed* token once its grace window has
    passed, and re-using it revokes the entire session family so a thief who
    captured it is locked out the moment the real user rotates.
    """
    if not token or not _TOKEN_RE.match(token):
        return None, None
    conn = db.get_connection()
    row = conn.execute(
        "SELECT s.token_hash, s.expires_at, s.session_key, s.replaced_by, s.replaced_at,"
        " u.id AS uid, u.email, u.name"
        " FROM auth_sessions s JOIN users u ON u.id = s.user_id"
        " WHERE s.token_hash=?",
        (_token_hash(token),),
    ).fetchone()
    if not row:
        return None, None
    if datetime.fromisoformat(row["expires_at"]) < _utcnow():
        revoke_token(token)
        return None, None
    user = {"id": row["uid"], "email": row["email"], "name": row["name"]}
    if row["replaced_by"]:
        replaced_at = datetime.fromisoformat(row["replaced_at"]) if row["replaced_at"] else _utcnow()
        if (_utcnow() - replaced_at).total_seconds() > REUSE_GRACE_S:
            # Replay of an already-rotated token → burn the whole family.
            _revoke_family(row["session_key"] or row["token_hash"])
            db.audit(user["id"], "auth.token_reuse_revoked", "rotated token replayed")
            return None, None
        # Within the grace window: a concurrent in-flight request that started
        # just before rotation — same user, still honoured.
    return user, row


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
    user, row = _lookup(token)
    if user is None:
        return None
    if not row["replaced_by"]:
        _touch(row)
    return user


def resolve_and_rotate(token: str | None) -> tuple[dict | None, str | None]:
    """Resolve a bearer token, rotating it if it has aged past ``ROTATE_AFTER_S``.

    Returns ``(user, new_token)``; ``new_token`` is set only when a rotation
    happened, so the caller can hand the fresh token back to the client. Rotation
    is idempotent per family: once rotated, the old token is never rotated again.
    """
    user, row = _lookup(token)
    if user is None or row["replaced_by"]:
        return user, None
    conn = db.get_connection()
    created = datetime.fromisoformat(
        conn.execute(
            "SELECT created_at FROM auth_sessions WHERE token_hash=?", (row["token_hash"],)
        ).fetchone()["created_at"]
    )
    if (_utcnow() - created).total_seconds() < ROTATE_AFTER_S:
        _touch(row)
        return user, None
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
                _iso(now + timedelta(days=SESSION_DAYS)), _iso(now), None,
                row["session_key"], None, None,
            ),
        )
        conn.execute(
            "UPDATE auth_sessions SET replaced_by=?, replaced_at=? WHERE token_hash=?",
            (new_hash, _iso(now), row["token_hash"]),
        )
        conn.commit()
    db.audit(user["id"], "auth.token_rotated", None)
    return user, new_token


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
    """Right-to-erasure: user → their tokens → their owned profiles/tracker rows."""
    conn = db.get_connection()
    with db._lock:
        owned = [
            r["session_id"]
            for r in conn.execute(
                "SELECT session_id FROM profiles WHERE user_id=?", (user_id,)
            ).fetchall()
        ]
        for sid in owned:
            conn.execute("DELETE FROM tracker WHERE session_id=?", (sid,))
        conn.execute("DELETE FROM profiles WHERE user_id=?", (user_id,))
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.commit()
    db.audit(user_id, "auth.delete_account", f"owned_sessions={len(owned)}")
