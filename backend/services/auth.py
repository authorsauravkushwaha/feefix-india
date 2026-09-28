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

PBKDF2_ITERATIONS = 600_000
SESSION_DAYS = 30
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-]{32,128}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MIN_PASSWORD_LEN = 8


class AuthError(ValueError):
    """Uniform, non-informative auth failure."""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


# -- passwords ----------------------------------------------------------------
def hash_password(password: str, *, iterations: int = PBKDF2_ITERATIONS) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iterations, salt_hex, digest_hex = stored.split("$")
        if scheme != "pbkdf2":
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(iterations))
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def validate_credentials(email: str, password: str) -> None:
    if not EMAIL_RE.match((email or "").strip()):
        raise AuthError("Enter a valid email address.")
    if len(password or "") < MIN_PASSWORD_LEN:
        raise AuthError(f"Password must be at least {MIN_PASSWORD_LEN} characters.")


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
            "INSERT INTO auth_sessions (token_hash, user_id, created_at, expires_at, last_seen, client)"
            " VALUES (?,?,?,?,?,?)",
            (_token_hash(token), user_id, _iso(now), _iso(expires), _iso(now), client),
        )
        conn.commit()
    return token, expires


def resolve_token(token: str | None) -> dict | None:
    """Bearer token → user dict (rolling refresh) or None."""
    if not token or not _TOKEN_RE.match(token):
        return None
    conn = db.get_connection()
    row = conn.execute(
        "SELECT s.token_hash, s.expires_at, u.id AS uid, u.email, u.name"
        " FROM auth_sessions s JOIN users u ON u.id = s.user_id"
        " WHERE s.token_hash=?",
        (_token_hash(token),),
    ).fetchone()
    if not row:
        return None
    if datetime.fromisoformat(row["expires_at"]) < _utcnow():
        revoke_token(token)
        return None
    with db._lock:
        # Rolling window: sliding 30-day expiry on activity.
        conn.execute(
            "UPDATE auth_sessions SET last_seen=?, expires_at=? WHERE token_hash=?",
            (_iso(_utcnow()), _iso(_utcnow() + timedelta(days=SESSION_DAYS)), row["token_hash"]),
        )
        conn.commit()
    return {"id": row["uid"], "email": row["email"], "name": row["name"]}


def revoke_token(token: str) -> bool:
    conn = db.get_connection()
    with db._lock:
        cur = conn.execute("DELETE FROM auth_sessions WHERE token_hash=?", (_token_hash(token),))
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
