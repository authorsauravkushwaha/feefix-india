"""FeeFix authentication — accounts, password hashing, revocable sessions.

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


PBKDF2_ITERATIONS = passwords.PBKDF2_ITERATIONS  # kept for backwards compatibility
SESSION_DAYS = _env_int("FEEFIX_SESSION_DAYS", 30)
# A token in continuous use longer than this is silently rotated.
ROTATE_AFTER_S = _env_int("FEEFIX_ROTATE_AFTER_S", 24 * 3600)
# How long a superseded token keeps working while clients catch up (in-flight
# tolerance + slow/background tabs). This is the knob that trades replay
# strictness for availability.
OVERLAP_S = _env_int("FEEFIX_TOKEN_OVERLAP_S", 15 * 60)
# Legacy name for the short in-flight window used by the ``strict`` policy.
REUSE_GRACE_S = _env_int("FEEFIX_REUSE_GRACE_S", 60)
# balanced (default) | strict | lenient
REPLAY_POLICY = (os.environ.get("FEEFIX_REPLAY_POLICY") or "balanced").strip().lower()
REPLAY_STRIKES = _env_int("FEEFIX_REPLAY_STRIKES", 5)
if REPLAY_POLICY not in ("balanced", "strict", "lenient"):  # pragma: no cover - config typo
    log.warning("[auth] unknown FEEFIX_REPLAY_POLICY=%r — using 'balanced'", REPLAY_POLICY)
    REPLAY_POLICY = "balanced"

_TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-]{32,128}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class AuthError(ValueError):
    """Uniform, non-informative auth failure."""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


# -- passwords ------------------------------------------------------------------ #
def hash_password(password: str, *, iterations: int | None = None) -> str:
    """Hash a password with the active algorithm (Argon2id where available).

    ``iterations`` is accepted for backwards compatibility with older callers
    that pinned PBKDF2 rounds; new code should not pass it.
    """
    if iterations and iterations != passwords.PBKDF2_ITERATIONS:
        # Explicit legacy request (importers/tests) — honour the PBKDF2 path.
        preimage = hashlib.sha256(password.encode("utf-8")).digest()
        salt = secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac("sha256", preimage, salt, iterations)
        return f"pbkdf2${iterations}${salt.hex()}${digest.hex()}"
    return passwords.hash_password(password)


def verify_password(password: str, stored: str) -> bool:
    """Boolean compatibility wrapper around :func:`passwords.verify`."""
    return passwords.verify(password, stored)[0]


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
    if not row:
        # Unknown account: burn an equivalent verification so response timing
        # cannot be used to enumerate registered emails.
        passwords.dummy_verify(password)
        raise AuthError("Invalid email or password.")
    ok, needs_rehash = passwords.verify(password, row["password_hash"])
    if not ok:
        raise AuthError("Invalid email or password.")
    if needs_rehash:
        # Transparent upgrade: a legacy PBKDF2 row (or outdated Argon2id
        # parameters) becomes a current-scheme hash the moment it is proven.
        try:
            with db._lock:
                conn.execute(
                    "UPDATE users SET password_hash=?, updated_at=? WHERE id=?",
                    (hash_password(password), _iso(_utcnow()), row["id"]),
                )
                conn.commit()
            db.audit(row["id"], "auth.password_rehashed", passwords.active_algorithm())
        except Exception as exc:  # noqa: BLE001 - never block a valid sign-in
            log.warning("[auth] password rehash skipped: %s", exc)
    db.audit(row["id"], "auth.login", None)
    return {"id": row["id"], "email": row["email"], "name": row["name"]}


# -- sessions ---------------------------------------------------------------------
def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


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


def _fetch_row(token: str):
    if not token or not _TOKEN_RE.match(token):
        return None
    conn = db.get_connection()
    return conn.execute(
        "SELECT s.token_hash, s.expires_at, s.session_key, s.replaced_by, s.replaced_at,"
        " s.replay_strikes, s.fingerprint, s.heal_count, s.user_id,"
        " u.id AS uid, u.email, u.name"
        " FROM auth_sessions s JOIN users u ON u.id = s.user_id"
        " WHERE s.token_hash=?",
        (_token_hash(token),),
    ).fetchone()


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


def _lookup(token: str, client: str | None = None) -> tuple[dict | None, object | None]:
    """Return ``(user, row)`` for a live token, or ``(None, None)``.

    Row is returned only for tokens that are current (not superseded), so callers
    can safely touch/rotate them.
    """
    row = _fetch_row(token)
    if not row:
        return None, None
    if datetime.fromisoformat(row["expires_at"]) < _utcnow():
        # Expiry kills exactly this token — never its family.
        _delete_row(row["token_hash"])
        return None, None
    if row["replaced_by"]:
        user, new_token = _handle_superseded(row, client)
        if user is None:
            return None, None
        # Surface the healed token to the caller via the row shim.
        return user, _SupersededRow(row, new_token)
    return _user_of(row), row


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


def resolve_token(token: str | None, client: str | None = None) -> dict | None:
    """Bearer token → user dict (rolling refresh) or None. No rotation here."""
    user, row = _lookup(token, client)
    if user is None or row is None:
        return None
    if isinstance(row, _SupersededRow):  # tolerated stale token; already refreshed
        return user
    _touch(row)
    return user


def resolve_and_rotate(
    token: str | None, client: str | None = None
) -> tuple[dict | None, str | None]:
    """Resolve a bearer token, rotating it if it has aged past ``ROTATE_AFTER_S``.

    Returns ``(user, new_token)``; ``new_token`` is set when a rotation (or a
    self-heal for a late client) handed the caller a fresher token.
    """
    user, row = _lookup(token, client)
    if user is None or row is None:
        return None, None
    if isinstance(row, _SupersededRow):
        return user, row.healed_token
    conn = db.get_connection()
    created_row = conn.execute(
        "SELECT created_at FROM auth_sessions WHERE token_hash=?", (row["token_hash"],)
    ).fetchone()
    created = datetime.fromisoformat(created_row["created_at"])
    if (_utcnow() - created).total_seconds() < ROTATE_AFTER_S:
        _touch(row)
        return user, None
    # Rotate: mint a new token in the same family, mark the old one superseded.
    new_token = _mint_sibling(row, client)
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
