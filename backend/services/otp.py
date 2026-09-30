"""OTP (one-time-passcode) & OAuth sign-in — free-tier, stdlib-only.

WHAT THIS MODULE PROVIDES
=========================
1. **Email OTP** — 6-digit codes delivered over SMTP. Works with *any*
   provider (Gmail, Yahoo, outlook, ProtonMail bridges …) — the recipient's
   mailbox provider is irrelevant; delivery depends only on YOUR SMTP relay.
   Without an SMTP relay configured, codes surface as ``dev_code`` (log +
   API echo) so demos keep working.
2. **Phone OTP (any country, E.164)** — the same challenges delivered by
   SMS. SMS is the one part that genuinely cannot be free (no free SMS
   gateway exists) — the code is provider-pluggable (Twilio default) and
   falls back to ``dev_code`` when unconfigured.
3. **GitHub OAuth** — web flow (authorize → callback → user fetch) with
   signed one-time state tokens. Free forever; the only setup cost is a
   2-minute OAuth App registration on github.com.

SECURITY POSTURE (mirrors backend/services/auth.py)
===================================================
* codes are 6-digit ``secrets`` draws with a per-code random salt; only
  HMAC-SHA256(salt ⊕ code) is stored — DB leak reveals nothing usable
* 300 s expiry, ≤ 5 verify attempts (challenge burns after), 40 s resend
  cooldown, ≤ 5 requests/hour per destination
* code comparison is constant-time (``hmac.compare_digest``)
* one-time OAuth state rows (single-read, then deleted)
* identical 401/422 errors regardless of whether an account exists
  (no user-enumeration); every step lands in the audit_log table
* all SQL parameterized; providers reached only over HTTPS, 8 s timeouts

Every function below imports lazily where a third-party package would be
needed, so this module stays importable with Python stdlib alone.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import smtplib
import ssl
import uuid
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from urllib import parse, request as urlreq

from backend.services import auth as auth_svc
from backend.services import db

# ------------------------------------------------------------------ config --
CODE_LEN = 6
CODE_TTL_S = 300            # 5 minutes
VERIFY_ATTEMPTS = 5
RESEND_COOLDOWN_S = 40
REQ_PER_HOUR = 5
OAUTH_STATE_TTL_S = 600
E164_RE = re.compile(r"^\+[1-9]\d{7,14}$")
RUNTIME_DIR = Path(__file__).resolve().parents[2] / "runtime"
_HTTP_TIMEOUT_S = 8


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts)


# ------------------------------------------------------- schema (self-owned) --
# Additive: owned entirely by this module, independent of db._MIGRATIONS.
_SCHEMA = [
    """CREATE TABLE IF NOT EXISTS otp_challenges (
        id            TEXT PRIMARY KEY,
        channel       TEXT NOT NULL,           -- 'email' | 'phone'
        address       TEXT NOT NULL,           -- normalized destination
        code_hash     TEXT NOT NULL,           -- hmac(salt, code)
        salt          TEXT NOT NULL,
        attempts_left INTEGER NOT NULL,
        expires_at    TEXT NOT NULL,
        resend_after  TEXT NOT NULL,
        created_at    TEXT NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS idx_otp_address ON otp_challenges(channel, address)",
    """CREATE TABLE IF NOT EXISTS auth_identities (
        kind      TEXT NOT NULL,               -- 'email' | 'phone' | 'github'
        key       TEXT NOT NULL,               -- normalized address / gh id
        user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at TEXT NOT NULL,
        PRIMARY KEY (kind, key)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_identity_user ON auth_identities(user_id)",
    """CREATE TABLE IF NOT EXISTS oauth_states (
        state      TEXT PRIMARY KEY,
        created_at TEXT NOT NULL
    )""",
]


def _ensure_schema() -> None:
    conn = db.get_connection()
    with db._lock:
        for stmt in _SCHEMA:
            conn.execute(stmt)
        conn.commit()


def _pepper() -> bytes:
    """Server-side pepper so a bare DB dump can't brute force 6-digit codes."""
    env = os.environ.get("FEEFIX_OTP_PEPPER")
    if env:
        return env.encode()
    path = RUNTIME_DIR / ".otp_pepper"
    if path.exists():
        return path.read_bytes()
    path.parent.mkdir(parents=True, exist_ok=True)
    rng = secrets.token_bytes(32)
    path.write_bytes(rng)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return rng


def _hash_code(code: str, salt_hex: str) -> str:
    salt = bytes.fromhex(salt_hex)
    return hmac.new(_pepper(), salt + code.encode(), hashlib.sha256).hexdigest()


# ------------------------------------------------------------- normalisation --
def normalize(channel: str, address: str) -> str:
    address = (address or "").strip()
    if channel == "email":
        address = address.lower()
        if not auth_svc.EMAIL_RE.match(address):
            raise auth_svc.AuthError("Enter a valid email address.")
        return address
    if channel == "phone":
        address = re.sub(r"[\s\-()]", "", address)
        if not address.startswith("+"):
            guess = re.sub(r"\D", "", address)
            if len(guess) == 10:                     # bare Indian mobile
                address = "+91" + guess
        if not E164_RE.match(address):
            raise auth_svc.AuthError("Use international format, e.g. +919876543210.")
        return address
    raise auth_svc.AuthError("Unknown channel.")


# ------------------------------------------------------------- challenge API --
def request_code(channel: str, address: str, client_ip: str = "unknown") -> dict:
    """Create a challenge. Returns delivery data (incl. dev_code if applicable)."""
    from backend.services import ratelimit

    _ensure_schema()
    channel = "email" if channel == "email" else ("phone" if channel == "phone" else "")
    address = normalize(channel, address)
    if not ratelimit.check_auth(client_ip, f"otp:{channel}:{address}"):
        raise auth_svc.AuthError("Too many attempts — try again later.")

    conn = db.get_connection()
    now = _utcnow()
    cutoff = _iso(now - timedelta(hours=1))

    with db._lock:
        recent = conn.execute(
            "SELECT COUNT(*) AS n FROM otp_challenges WHERE channel=? AND address=? AND created_at>=?",
            (channel, address, cutoff),
        ).fetchone()["n"]
        if recent >= REQ_PER_HOUR:
            raise auth_svc.AuthError("Too many codes requested — wait an hour.")

        live = conn.execute(
            "SELECT resend_after FROM otp_challenges WHERE channel=? AND address=? AND expires_at>=?"
            " ORDER BY created_at DESC LIMIT 1",
            (channel, address, _iso(now)),
        ).fetchone()
        if live and _parse(live["resend_after"]) > now:
            raise auth_svc.AuthError(
                f"Code already sent — resend available in {max(1, int((_parse(live['resend_after']) - now).total_seconds()))} s."
            )

        # Opportunistic sweep: expired rows are never usable anywhere again.
        conn.execute("DELETE FROM otp_challenges WHERE expires_at < ?", (_iso(now),))

        code = "".join(secrets.choice("0123456789") for _ in range(CODE_LEN))
        salt = secrets.token_bytes(16).hex()
        conn.execute(
            "INSERT INTO otp_challenges"
            " (id, channel, address, code_hash, salt, attempts_left, expires_at, resend_after, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (
                uuid.uuid4().hex,
                channel,
                address,
                _hash_code(code, salt),
                salt,
                VERIFY_ATTEMPTS,
                _iso(now + timedelta(seconds=CODE_TTL_S)),
                _iso(now + timedelta(seconds=RESEND_COOLDOWN_S)),
                _iso(now),
            ),
        )
        conn.commit()

    delivered = _deliver(channel, address, code)
    db.audit(None, f"otp.request.{channel}", f"to={address} via={delivered['via']}")
    resp = {
        "sent": True,
        "channel": channel,
        "address": _mask(channel, address),
        "via": delivered["via"],
        "ttl_s": CODE_TTL_S,
        "resend_in": RESEND_COOLDOWN_S,
    }
    if delivered["via"] == "dev":
        resp["dev_code"] = code
    return resp


def verify_code(channel: str, address: str, code: str, name: str | None = None) -> dict | None:
    """Burn the challenge and return the authenticated user, or None."""
    _ensure_schema()
    channel = "email" if channel == "email" else ("phone" if channel == "phone" else "")
    try:
        address = normalize(channel, address)
    except auth_svc.AuthError:
        return None
    code = (code or "").strip()

    conn = db.get_connection()
    row = conn.execute(
        "SELECT * FROM otp_challenges WHERE channel=? AND address=?"
        " ORDER BY created_at DESC LIMIT 1",
        (channel, address),
    ).fetchone()
    if not row or _parse(row["expires_at"]) < _utcnow():
        return None

    ok = hmac.compare_digest(_hash_code(code, row["salt"]), row["code_hash"])
    with db._lock:
        if ok:
            # single-use: consume every challenge for this destination
            conn.execute("DELETE FROM otp_challenges WHERE channel=? AND address=?",
                         (channel, address))
            conn.commit()
        else:
            if row["attempts_left"] <= 1:
                conn.execute("DELETE FROM otp_challenges WHERE id=?", (row["id"],))
                conn.commit()
                raise auth_svc.AuthError("Too many wrong codes — request a new one.")
            conn.execute(
                "UPDATE otp_challenges SET attempts_left=attempts_left-1 WHERE id=?",
                (row["id"],),
            )
            conn.commit()
    if not ok:
        return None

    user = _user_for_identity(channel, address, name)
    db.audit(user["id"], f"auth.otp_login.{channel}", None)
    return user


# -------------------------------------------------------------- identity mgmt --
def _user_for_identity(kind: str, key: str, name: str | None) -> dict:
    conn = db.get_connection()
    hit = conn.execute(
        "SELECT u.id, u.email, u.name FROM auth_identities i"
        " JOIN users u ON u.id = i.user_id WHERE i.kind=? AND i.key=?",
        (kind, key),
    ).fetchone()
    if hit:
        return {"id": hit["id"], "email": hit["email"], "name": hit["name"]}

    email = key if kind == "email" else f"{kind}:{key}@login.feefix.local"
    now = _iso(_utcnow())
    user_id = uuid.uuid4().hex[:12]
    with db._lock:
        if kind == "email":
            existing = conn.execute(
                "SELECT id, email, name FROM users WHERE email=?", (key,)
            ).fetchone()
            if existing:                     # merge with a password account
                conn.execute(
                    "INSERT OR IGNORE INTO auth_identities (kind, key, user_id, created_at)"
                    " VALUES (?,?,?,?)",
                    (kind, key, existing["id"], now),
                )
                conn.commit()
                return {"id": existing["id"], "email": existing["email"], "name": existing["name"]}
        conn.execute(
            "INSERT INTO users (id, email, password_hash, name, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?)",
            (user_id, email, auth_svc.hash_password(secrets.token_urlsafe(24)),
             (name or "").strip() or None, now, now),
        )
        conn.execute(
            "INSERT INTO auth_identities (kind, key, user_id, created_at) VALUES (?,?,?,?)",
            (kind, key, user_id, now),
        )
        conn.commit()
    return {"id": user_id, "email": email, "name": name}


def _mask(channel: str, address: str) -> str:
    if channel == "email":
        u, d = address.split("@", 1)
        return (u[:2] if len(u) > 2 else u[:1]) + "***@" + d
    return address[:4] + "****" + address[-2:]


# ---------------------------------------------------------------- delivery ---
def _deliver(channel: str, address: str, code: str) -> dict:
    if channel == "email":
        return _deliver_email(address, code)
    return _deliver_sms(address, code)


def _deliver_email(address: str, code: str) -> dict:
    host = os.environ.get("OTP_SMTP_HOST", "").strip()
    if not host:
        return {"via": "dev", "error": "smtp not configured"}
    port = int(os.environ.get("OTP_SMTP_PORT", "587"))
    user = os.environ.get("OTP_SMTP_USER", "")
    pw = os.environ.get("OTP_SMTP_PASS", "").replace(" ", "")
    sender = os.environ.get("OTP_SMTP_FROM", user or "no-reply@feefix.local")
    try:
        msg = EmailMessage()
        msg["From"] = sender
        msg["To"] = address
        msg["Subject"] = "Your FeeFix sign-in code"
        msg.set_content(
            f"Your FeeFix code is {code}\n\n"
            f"It expires in {CODE_TTL_S // 60} minutes. If you didn't request "
            "it, ignore this email.\n"
        )
        ctx = ssl.create_default_context()
        if port == 465:
            with smtplib.SMTP_SSL(host, port, timeout=8, context=ctx) as s:
                if user:
                    s.login(user, pw)
                s.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=8) as s:
                s.starttls(context=ctx)
                if user:
                    s.login(user, pw)
                s.send_message(msg)
        return {"via": "smtp"}
    except Exception as exc:
        db.audit(None, "otp.email.error", f"{exc.__class__.__name__}: {str(exc)[:120]}")
        return {"via": "dev", "error": "smtp failed"}


def _deliver_sms(address: str, code: str) -> dict:
    """Twilio-compatible REST send. Free SMS gateways do not exist — this is
    the standard paid path (~$0.01-0.05/msg with a trial credit)."""
    sid = os.environ.get("OTP_TWILIO_SID", "").strip()
    token = os.environ.get("OTP_TWILIO_TOKEN", "").strip()
    sender = os.environ.get("OTP_TWILIO_FROM", "").strip()
    if not (sid and token and sender):
        return {"via": "dev", "error": "sms provider not configured"}
    body = parse.urlencode({
        "To": address,
        "From": sender,
        "Body": f"Your FeeFix code is {code} (valid {CODE_TTL_S // 60} min)",
    }).encode()
    req = urlreq.Request(
        f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json",
        data=body,
        headers={
            "Authorization": "Basic "
            + base64.b64encode(f"{sid}:{token}".encode()).decode(),
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    try:
        with urlreq.urlopen(req, timeout=_HTTP_TIMEOUT_S) as r:
            r.read()
        return {"via": "twilio"}
    except Exception as exc:
        db.audit(None, "otp.sms.error", f"{exc.__class__.__name__}: {str(exc)[:120]}")
        return {"via": "dev", "error": "sms send failed"}


# ============================================================ GitHub OAuth ===
GH_AUTHORIZE = "https://github.com/login/oauth/authorize"
GH_TOKEN = "https://github.com/login/oauth/access_token"
GH_API_USER = "https://api.github.com/user"
GH_API_EMAILS = "https://api.github.com/user/emails"


def github_configured() -> bool:
    return bool(os.environ.get("GITHUB_CLIENT_ID") and os.environ.get("GITHUB_CLIENT_SECRET"))


def _callback_url() -> str:
    base = os.environ.get("FEEFIX_BASE_URL", "").rstrip("/") or (
        "https://" + os.environ.get("RENDER_EXTERNAL_HOSTNAME", "feefix-india.onrender.com")
    )
    return base + "/api/auth/github/callback"


def github_start() -> str:
    """Authorize URL with a one-time server-side state (CSRF defence)."""
    if not github_configured():
        raise auth_svc.AuthError("GitHub sign-in is not configured on this deployment.")
    _ensure_schema()
    state = secrets.token_urlsafe(24)
    conn = db.get_connection()
    with db._lock:
        conn.execute(
            "INSERT INTO oauth_states (state, created_at) VALUES (?,?)",
            (state, _iso(_utcnow())),
        )
        conn.commit()
    q = parse.urlencode({
        "client_id": os.environ["GITHUB_CLIENT_ID"],
        "redirect_uri": _callback_url(),
        "scope": "read:user user:email",
        "state": state,
    })
    return GH_AUTHORIZE + "?" + q


def _http_json_post(url: str, data: dict) -> dict:
    req = urlreq.Request(
        url,
        data=parse.urlencode(data).encode(),
        headers={"Accept": "application/json",
                 "Content-Type": "application/x-www-form-urlencoded"},
    )
    with urlreq.urlopen(req, timeout=_HTTP_TIMEOUT_S) as r:
        return json.loads(r.read().decode())


def _http_json_get(url: str, gh_token: str):
    req = urlreq.Request(url, headers={
        "Authorization": f"Bearer {gh_token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "feefix-india",
    })
    with urlreq.urlopen(req, timeout=_HTTP_TIMEOUT_S) as r:
        return json.loads(r.read().decode())


def _pop_state(state: str) -> bool:
    conn = db.get_connection()
    with db._lock:
        row = conn.execute(
            "SELECT created_at FROM oauth_states WHERE state=?", (state or "",)
        ).fetchone()
        conn.execute("DELETE FROM oauth_states WHERE state=?", (state or "",))
        # opportunistic sweep of expired states
        conn.execute(
            "DELETE FROM oauth_states WHERE created_at < ?",
            (_iso(_utcnow() - timedelta(seconds=OAUTH_STATE_TTL_S)),),
        )
        conn.commit()
    if not row:
        return False
    return _parse(row["created_at"]) > _utcnow() - timedelta(seconds=OAUTH_STATE_TTL_S)


def github_finish(code: str, state: str) -> dict:
    """Callback: exchange code → fetch profile → upsert → return user."""
    if not github_configured():
        raise auth_svc.AuthError("GitHub sign-in is not configured on this deployment.")
    if not _pop_state(state):
        raise auth_svc.AuthError("Sign-in link expired or invalid — try again.")
    try:
        tok = _http_json_post(GH_TOKEN, {
            "client_id": os.environ["GITHUB_CLIENT_ID"],
            "client_secret": os.environ["GITHUB_CLIENT_SECRET"],
            "code": code,
            "redirect_uri": _callback_url(),
        })
        gh_token = tok.get("access_token")
        if not gh_token:
            raise auth_svc.AuthError("GitHub rejected the code — try again.")
        prof = _http_json_get(GH_API_USER, gh_token)
        emails = _http_json_get(GH_API_EMAILS, gh_token) or []
    except auth_svc.AuthError:
        raise
    except Exception:
        raise auth_svc.AuthError("Couldn't reach GitHub — try again.")

    gh_id = str(prof.get("id") or "")
    if not gh_id:
        raise auth_svc.AuthError("GitHub profile unreadable — try again.")
    email = next(
        (e["email"] for e in emails if e.get("primary") and e.get("verified")), None
    ) or prof.get("email")
    name = (prof.get("name") or prof.get("login") or "friend").strip()

    conn = db.get_connection()
    hit = conn.execute(
        "SELECT u.id, u.email, u.name FROM auth_identities i JOIN users u"
        " ON u.id=i.user_id WHERE i.kind='github' AND i.key=?",
        (gh_id,),
    ).fetchone()
    if not hit and email:
        hit = conn.execute(
            "SELECT id, email, name FROM users WHERE email=?", (email.lower(),)
        ).fetchone()
        if hit:  # attach github identity to existing account
            now = _iso(_utcnow())
            with db._lock:
                conn.execute(
                    "INSERT OR IGNORE INTO auth_identities (kind, key, user_id, created_at)"
                    " VALUES ('github',?,?,?)",
                    (gh_id, hit["id"], now),
                )
                conn.commit()
    if hit:
        db.audit(hit["id"], "auth.github_login", None)
        return {"id": hit["id"], "email": hit["email"], "name": hit["name"]}

    user = _user_for_identity("github", gh_id, name)
    if email:
        with db._lock:
            conn.execute(
                "INSERT OR IGNORE INTO auth_identities (kind, key, user_id, created_at)"
                " VALUES ('email',?,?,?)",
                (user["id"], email.lower(), _iso(_utcnow())),
            )
            conn.commit()
        user["email"] = email
        conn.execute("UPDATE users SET email=? WHERE id=?", (email.lower(), user["id"]))
        conn.commit()
    db.audit(user["id"], "auth.github_login", None)
    return user


def methods() -> dict:
    """Which sign-in doors are open — the UI dims ones that are not."""
    return {
        "password": True,
        "otp_email": True,                       # dev-code fallback always works
        "otp_phone": bool(os.environ.get("OTP_TWILIO_SID")),
        "github": github_configured(),
    }
