"""FeeFix authentication — accounts, password hashing, revocable sessions.

Design choices (free, zero-dependency, and deliberately
boring-because-boring-is-secure):

* **Passwords** — PBKDF2-HMAC-SHA256, 600,000 iterations, 16-byte per-user salt
  (OWASP-recommended parameters; stdlib ``hashlib``, no external deps).
  Stored format: ``pbkdf2$<iterations>$<salt_hex>$<hex_digest>``.
* **Sessions** — opaque 256-bit random bearer tokens (``secrets`` module).
  Only the **SHA-256 hash** of a token is stored, so a database leak yields
  nothing usable.
* **Timing safety** — verification always hashes, and digests are compared with
  ``hmac.compare_digest``; unknown-email errors are identical to wrong-password
  errors (no user-enumeration).

WHAT THIS REVISION ADDS
=======================
**Long-password DoS ceiling.** ``validate_credentials`` now rejects anything
over :data:`security.LIMITS.MAX_PASSWORD_LEN` *before* the KDF runs, and the
email check no longer uses a backtracking regex. Previously a 10 MB password
field was encoded, hashed and stored; a 20 KB email address took 718 ms to
validate (see :mod:`backend.services.input_guard`).

**Client binding.** A session records a non-reversible fingerprint of the user
agent that created it. A token replayed from a different client is revoked
rather than honoured. This is defence in depth for token theft: it does not
replace TLS, it raises the cost of using a token that leaked through it. The
fingerprint is a SHA-256 digest — the raw user agent is PII and is never
stored. Binding is on by default in production and can be relaxed with
``FEEFIX_BIND_CLIENT=0`` for deployments behind user-agent-rewriting proxies.

**Absolute session lifetime.** The rolling 30-day window is now capped by a
90-day absolute expiry. Without it, a stolen token used once a month never
expires — rolling renewal is an availability feature that quietly becomes a
persistence backdoor.

**Session ceiling.** At most 20 live sessions per account; creating the 21st
revokes the oldest. Otherwise "log in from 10 000 places" is an unbounded
storage-growth vector, and a user has no way to see or clear the pile.

**Credential-stuffing lockout.** Consecutive failures are counted per account
*and* per source IP. The account locks only when failures arrive from several
distinct IPs — that is the signature of a distributed stuffing attack. A
single-IP burst is handled by the IP budget instead, because locking an account
on one IP's failures would let an attacker deliberately lock out any user they
know the email of (an availability attack against the victim).
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from backend.services import db
from backend.services import input_guard
from backend.services import security
from backend.services.security import LIMITS

PBKDF2_ITERATIONS = 600_000
SESSION_DAYS = LIMITS.SESSION_IDLE_DAYS
MAX_PASSWORD_LEN = LIMITS.MAX_PASSWORD_LEN
MIN_PASSWORD_LEN = input_guard.MIN_PASSWORD_LEN

#: Kept for import compatibility. The *safe* linear-time pattern; validation
#: now goes through :func:`input_guard.valid_email`, which is stricter and
#: cannot be made quadratic by any input.
EMAIL_RE = input_guard.EMAIL_SAFE_RE
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-]{32,128}$")

# Credential-stuffing lockout tuning.
LOCKOUT_FAILURES = 12          # failures on one account ...
LOCKOUT_DISTINCT_IPS = 3       # ... from at least this many IPs ...
LOCKOUT_WINDOW_MIN = 15        # ... inside this window ...
LOCKOUT_MINUTES = 15           # ... locks the account for this long.


class AuthError(ValueError):
    """Uniform, non-informative auth failure."""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


def _parse(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        value = datetime.fromisoformat(ts)
    except (TypeError, ValueError):
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


# -- passwords ----------------------------------------------------------------
def hash_password(password: str, *, iterations: int = PBKDF2_ITERATIONS) -> str:
    """PBKDF2-HMAC-SHA256 with a fresh 16-byte salt.

    The length ceiling is re-checked here, not only at the API boundary, so a
    future internal caller cannot reintroduce the long-password DoS by
    bypassing the route layer.
    """
    if password is None or len(password) > MAX_PASSWORD_LEN:
        raise AuthError("Password is too long.")
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time verification of a stored hash.

    Every failure mode returns ``False`` rather than raising: a corrupt or
    truncated hash row must not become a 500, and the caller's uniform error
    must not depend on *why* verification failed.
    """
    try:
        if password is None or len(password) > MAX_PASSWORD_LEN:
            return False
        parts = (stored or "").split("$")
        if len(parts) != 4:
            return False
        scheme, iterations, salt_hex, digest_hex = parts
        if scheme != "pbkdf2":
            return False
        # Reject absurd iteration counts: a row tampered to say 10**12 would
        # turn one login into an unbounded CPU burn.
        rounds = int(iterations)
        if not (10_000 <= rounds <= 2_000_000):
            return False
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def password_acceptable(password: str) -> tuple[bool, str]:
    """Policy check, returning a user-safe reason.

    Length floor and ceiling only. We deliberately do **not** impose character
    class rules: NIST SP 800-63B is explicit that composition requirements push
    users toward predictable substitutions (``Password1!``) and reduce real
    entropy. The ceiling is a DoS control; the floor is a brute-force control.
    """
    if password is None or len(password) < MIN_PASSWORD_LEN:
        return False, f"Password must be at least {MIN_PASSWORD_LEN} characters."
    if len(password) > MAX_PASSWORD_LEN:
        return False, f"Password must be at most {MAX_PASSWORD_LEN} characters."
    # Reject the handful of values that are effectively no password at all.
    if password.strip().lower() in _BLOCKED_PASSWORDS:
        return False, "That password is too common — choose a stronger one."
    return True, ""


#: Small built-in deny-list. A full HaveIBeenPwned k-anonymity lookup would be
#: better but requires an outbound call, which this codebase refuses to make on
#: the auth path (no third party learns which emails are registering).
_BLOCKED_PASSWORDS = frozenset({
    "password", "password1", "password123", "12345678", "123456789",
    "1234567890", "qwerty123", "qwertyui", "abcdefgh", "iloveyou",
    "feefix123", "feefixindia", "letmein1", "welcome1", "admin123",
    "11111111", "00000000", "87654321", "passw0rd", "password1!",
})


def validate_credentials(email: str, password: str) -> str:
    """Validate a (email, password) pair. Returns the canonical email.

    Length is checked *first* so an oversized field never reaches a parser —
    that ordering is the whole defence against algorithmic-complexity attacks
    on validation.
    """
    if input_guard.reject_if_overlong(email, LIMITS.MAX_EMAIL_LEN):
        raise AuthError("Enter a valid email address.")
    canonical = input_guard.valid_email(email)
    if canonical is None:
        raise AuthError("Enter a valid email address.")

    ok, reason = password_acceptable(password)
    if not ok:
        raise AuthError(reason)
    return canonical


# -- users ----------------------------------------------------------------------
def register(email: str, password: str, name: str | None = None) -> dict:
    canonical = validate_credentials(email, password)
    safe_name = input_guard.bounded(name, LIMITS.MAX_NAME_LEN) or None

    conn = db.get_connection()
    with db._lock:
        exists = conn.execute("SELECT id FROM users WHERE email=?", (canonical,)).fetchone()
        if exists:
            raise AuthError("An account with this email already exists.")
        user_id = uuid.uuid4().hex[:12]
        now = _iso(_utcnow())
        conn.execute(
            "INSERT INTO users (id, email, password_hash, name, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?)",
            (user_id, canonical, hash_password(password), safe_name, now, now),
        )
        conn.commit()
    db.audit(user_id, "auth.register", security.redact_email(canonical))
    return {"id": user_id, "email": canonical, "name": safe_name}


def login(email: str, password: str, *, client_ip: str = "unknown",
          user_agent: str = "") -> dict:
    """Verify credentials and return the user, or raise a uniform AuthError.

    The error text is identical for "no such account" and "wrong password".
    The KDF always runs, so the *timing* is identical too — otherwise response
    latency is a user-enumeration oracle.
    """
    canonical = ""
    if not input_guard.reject_if_overlong(email, LIMITS.MAX_EMAIL_LEN):
        canonical = input_guard.valid_email(email) or (email or "").strip().lower()
    else:
        canonical = (email or "").strip().lower()

    if input_guard.reject_if_overlong(password, MAX_PASSWORD_LEN):
        # Rejected before any KDF work. Same message as a wrong password.
        _note_failure(None, client_ip)
        raise AuthError("Invalid email or password.")

    conn = db.get_connection()
    row = conn.execute(
        "SELECT id, email, name, password_hash FROM users WHERE email=?", (canonical,)
    ).fetchone()

    if row is not None and _is_locked(conn, row["id"]):
        # Locked accounts answer exactly like a wrong password: revealing the
        # lock would confirm the account exists and that it is under attack.
        _note_failure(row["id"], client_ip)
        raise AuthError("Invalid email or password.")

    # Always run the KDF so unknown-email and wrong-password take similar time.
    stored = row["password_hash"] if row else hash_password("dummy")
    if not row or not verify_password(password, stored):
        _note_failure(row["id"] if row else None, client_ip)
        db.audit(row["id"] if row else None, "auth.login_failed",
                 security.redact_email(canonical))
        raise AuthError("Invalid email or password.")

    _clear_failures(conn, row["id"])
    db.audit(row["id"], "auth.login", None)
    return {"id": row["id"], "email": row["email"], "name": row["name"]}


# -- credential-stuffing lockout ------------------------------------------------
def _note_failure(user_id: str | None, client_ip: str) -> None:
    """Record a failed attempt for lockout analysis. Best-effort, never fatal."""
    if not user_id:
        return
    try:
        conn = db.get_connection()
        now = _utcnow()
        with db._lock:
            conn.execute(
                "INSERT INTO login_failures (user_id, ip_hash, occurred_at) VALUES (?,?,?)",
                (user_id, security.fingerprint(client_ip), _iso(now)),
            )
            cutoff = _iso(now - timedelta(minutes=LOCKOUT_WINDOW_MIN))
            conn.execute("DELETE FROM login_failures WHERE occurred_at < ?", (cutoff,))
            row = conn.execute(
                "SELECT COUNT(*) AS n, COUNT(DISTINCT ip_hash) AS ips"
                " FROM login_failures WHERE user_id=? AND occurred_at>=?",
                (user_id, cutoff),
            ).fetchone()
            if row and row["n"] >= LOCKOUT_FAILURES and row["ips"] >= LOCKOUT_DISTINCT_IPS:
                conn.execute(
                    "UPDATE users SET locked_until=? WHERE id=?",
                    (_iso(now + timedelta(minutes=LOCKOUT_MINUTES)), user_id),
                )
                conn.execute("DELETE FROM login_failures WHERE user_id=?", (user_id,))
                security.audit_security_event(
                    "auth.account_locked",
                    f"user={user_id} failures={row['n']} ips={row['ips']}",
                    user_id,
                )
            conn.commit()
    except Exception:  # pragma: no cover - lockout must never break login
        pass


def _is_locked(conn, user_id: str) -> bool:
    try:
        row = conn.execute("SELECT locked_until FROM users WHERE id=?", (user_id,)).fetchone()
    except Exception:
        return False
    until = _parse(row["locked_until"]) if row else None
    return bool(until and until > _utcnow())


def _clear_failures(conn, user_id: str) -> None:
    try:
        with db._lock:
            conn.execute("UPDATE users SET locked_until=NULL, failed_attempts=0 WHERE id=?",
                         (user_id,))
            conn.execute("DELETE FROM login_failures WHERE user_id=?", (user_id,))
            conn.commit()
    except Exception:  # pragma: no cover
        pass


# -- sessions ---------------------------------------------------------------------
def _token_hash(token: str) -> str:
    """Tokens are stored only as digests.

    SHA-256 (not PBKDF2) is correct here: the input is 256 bits of CSPRNG
    output, so there is nothing to brute-force and a slow KDF would only buy
    latency. This is the same reasoning that makes fast hashes right for
    session tokens and wrong for passwords.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def client_fingerprint(user_agent: str, token_hint: str = "") -> str | None:
    """Non-reversible binding value for a session.

    ``None`` disables binding for that session (used when the client presents
    no user agent, e.g. a server-to-server integration).
    """
    if not bind_clients_enabled():
        return None
    ua = (user_agent or "").strip()
    if not ua:
        return None
    return security.fingerprint(ua, token_hint)


def bind_clients_enabled() -> bool:
    """Whether stolen-token replay is blunted by user-agent binding."""
    if security.env_str("FEEFIX_BIND_CLIENT").lower() in ("0", "false", "no", "off"):
        return False
    return True


def create_session(user_id: str, client: str | None = None, *,
                   user_agent: str = "") -> tuple[str, datetime]:
    """Mint an opaque, revocable session token.

    Enforces the per-account session ceiling by revoking the oldest sessions
    first, so an attacker who can trigger logins cannot grow the table without
    bound.
    """
    token = secrets.token_urlsafe(32)
    now = _utcnow()
    expires = now + timedelta(days=SESSION_DAYS)
    absolute = now + timedelta(days=LIMITS.SESSION_ABSOLUTE_DAYS)
    fp = client_fingerprint(user_agent) or (client or None)

    conn = db.get_connection()
    with db._lock:
        _enforce_session_ceiling(conn, user_id)
        conn.execute(
            "INSERT INTO auth_sessions"
            " (token_hash, user_id, created_at, expires_at, absolute_expires_at, last_seen, client, client_fp)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (_token_hash(token), user_id, _iso(now), _iso(expires), _iso(absolute),
             _iso(now), client, fp),
        )
        conn.commit()
    return token, expires


def _enforce_session_ceiling(conn, user_id: str) -> None:
    rows = conn.execute(
        "SELECT token_hash FROM auth_sessions WHERE user_id=?"
        " ORDER BY last_seen DESC LIMIT -1 OFFSET ?",
        (user_id, LIMITS.MAX_SESSIONS_PER_USER - 1),
    ).fetchall()
    for row in rows:
        conn.execute("DELETE FROM auth_sessions WHERE token_hash=?", (row["token_hash"],))
    if rows:
        security.audit_security_event(
            "auth.sessions_evicted", f"user={user_id} count={len(rows)}", user_id
        )


def resolve_token(token: str | None, *, user_agent: str | None = None) -> dict | None:
    """Bearer token → user dict (rolling refresh) or ``None``.

    Rejects, in order: malformed shape, unknown digest, expired idle window,
    expired absolute lifetime, and a client fingerprint that does not match the
    one that created the session. Every rejection revokes the row, so a replayed
    or stolen token is burned on first misuse rather than remaining live.
    """
    clean = input_guard.valid_bearer_token(token)
    if clean is None:
        return None

    conn = db.get_connection()
    row = conn.execute(
        "SELECT s.token_hash, s.expires_at, s.absolute_expires_at, s.client_fp,"
        " u.id AS uid, u.email, u.name, u.locked_until"
        " FROM auth_sessions s JOIN users u ON u.id = s.user_id"
        " WHERE s.token_hash=?",
        (_token_hash(clean),),
    ).fetchone()
    if not row:
        return None

    now = _utcnow()
    expires = _parse(row["expires_at"])
    absolute = _parse(row["absolute_expires_at"]) or (
        (expires - timedelta(days=SESSION_DAYS) + timedelta(days=LIMITS.SESSION_ABSOLUTE_DAYS))
        if expires else None
    )
    if expires is None or expires < now or (absolute is not None and absolute < now):
        revoke_token(clean)
        return None

    if _is_locked(conn, row["uid"]):
        # A locked account's live sessions are not usable. Revoking here means
        # locking actually stops an attacker who is already inside.
        revoke_all_user_tokens(row["uid"])
        security.audit_security_event("auth.locked_session_revoked", None, row["uid"])
        return None

    stored_fp = row["client_fp"]
    if stored_fp and user_agent is not None:
        presented = client_fingerprint(user_agent)
        if presented and not security.constant_time_eq(presented, stored_fp):
            # Same token, different client: treat as theft, revoke everything
            # for the account so the legitimate user is forced to re-auth
            # rather than silently sharing a session with an attacker.
            revoke_all_user_tokens(row["uid"])
            security.audit_security_event(
                "auth.token_client_mismatch", f"user={row['uid']}", row["uid"]
            )
            return None

    with db._lock:
        # Rolling idle window, hard-capped by the absolute expiry.
        renewed = min(now + timedelta(days=SESSION_DAYS), absolute) if absolute else \
            now + timedelta(days=SESSION_DAYS)
        conn.execute(
            "UPDATE auth_sessions SET last_seen=?, expires_at=? WHERE token_hash=?",
            (_iso(now), _iso(renewed), row["token_hash"]),
        )
        conn.commit()
    return {"id": row["uid"], "email": row["email"], "name": row["name"]}


def revoke_token(token: str) -> bool:
    clean = input_guard.valid_bearer_token(token)
    if clean is None:
        return False
    conn = db.get_connection()
    with db._lock:
        cur = conn.execute("DELETE FROM auth_sessions WHERE token_hash=?",
                           (_token_hash(clean),))
        conn.commit()
    return cur.rowcount > 0


def revoke_all_user_tokens(user_id: str) -> None:
    conn = db.get_connection()
    with db._lock:
        conn.execute("DELETE FROM auth_sessions WHERE user_id=?", (user_id,))
        conn.commit()


def purge_expired_sessions() -> int:
    """Housekeeping: drop sessions past either expiry. Bounded table growth."""
    conn = db.get_connection()
    now = _iso(_utcnow())
    with db._lock:
        cur = conn.execute(
            "DELETE FROM auth_sessions WHERE expires_at < ?"
            " OR (absolute_expires_at IS NOT NULL AND absolute_expires_at < ?)",
            (now, now),
        )
        conn.execute(
            "DELETE FROM login_failures WHERE occurred_at < ?",
            (_iso(_utcnow() - timedelta(minutes=LOCKOUT_WINDOW_MIN)),),
        )
        conn.commit()
    return cur.rowcount


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
        conn.execute("DELETE FROM auth_identities WHERE user_id=?", (user_id,))
        conn.execute("DELETE FROM login_failures WHERE user_id=?", (user_id,))
        conn.execute("DELETE FROM auth_sessions WHERE user_id=?", (user_id,))
        conn.execute("DELETE FROM users WHERE id=?", (user_id,))
        conn.commit()
    db.audit(user_id, "auth.delete_account", f"owned_sessions={len(owned)}")


def change_password(user_id: str, current: str, new: str) -> None:
    """Rotate a password and revoke every other session.

    Revoking on change is what makes "I think my password leaked" an action the
    user can take that actually works. The current password is verified with the
    same uniform-error discipline as login.
    """
    ok, reason = password_acceptable(new)
    if not ok:
        raise AuthError(reason)
    conn = db.get_connection()
    row = conn.execute("SELECT password_hash FROM users WHERE id=?", (user_id,)).fetchone()
    if not row or not verify_password(current, row["password_hash"]):
        raise AuthError("Current password is incorrect.")
    with db._lock:
        conn.execute(
            "UPDATE users SET password_hash=?, updated_at=? WHERE id=?",
            (hash_password(new), _iso(_utcnow()), user_id),
        )
        conn.commit()
    revoke_all_user_tokens(user_id)
    db.audit(user_id, "auth.password_changed", None)
    security.audit_security_event("auth.password_changed", None, user_id)
