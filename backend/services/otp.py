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
from backend.services import input_guard
from backend.services import ratelimit
from backend.services import security
from backend.services.security import LIMITS

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
# Outbound responses are read with a ceiling: a compromised or spoofed upstream
# must not be able to make us allocate without limit.
_MAX_RESPONSE_BYTES = 256 * 1024


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
    """Server-side pepper so a bare DB dump can't brute force 6-digit codes.

    A 6-digit code has only 10^6 possibilities. Without a pepper, anyone who
    obtains ``otp_challenges`` can recover every live code in seconds on a
    laptop — the salt stops precomputation but not a direct search, because the
    search space is the code itself. The pepper is the only thing that makes
    the stored hash useless without also having the server's key material.

    Delegated to :func:`security.load_secret`, which additionally enforces a
    length floor, creates the key file ``0600`` from birth (no window where it
    is world-readable), and refuses to run with weak material in production.
    Cached per process: re-reading the file on every hash would be a syscall
    per OTP attempt and would make the pepper a hot-path dependency.
    """
    global _PEPPER_CACHE
    if _PEPPER_CACHE is None:
        _PEPPER_CACHE = security.load_secret(
            "FEEFIX_OTP_PEPPER",
            fallback_path=RUNTIME_DIR / ".otp_pepper",
            min_bytes=32,
        )
    return _PEPPER_CACHE


_PEPPER_CACHE: bytes | None = None


def reset_pepper_cache() -> None:
    """Drop the memoised pepper (tests rotate ``FEEFIX_OTP_PEPPER``)."""
    global _PEPPER_CACHE
    _PEPPER_CACHE = None


def _hash_code(code: str, salt_hex: str) -> str:
    salt = bytes.fromhex(salt_hex)
    return hmac.new(_pepper(), salt + code.encode(), hashlib.sha256).hexdigest()


# ------------------------------------------------------------- normalisation --
def normalize(channel: str, address: str) -> str:
    """Canonicalise a destination, or raise a uniform AuthError.

    Length is checked before parsing and validation is backtracking-free
    (:mod:`backend.services.input_guard`), so neither an oversized field nor a
    crafted address can make this function slow. The old email pattern here was
    the ReDoS-vulnerable ``^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$``; a 20 KB address cost
    718 ms of CPU on an unauthenticated endpoint.
    """
    if channel == "email":
        canonical = input_guard.valid_email(address)
        if canonical is None:
            raise auth_svc.AuthError("Enter a valid email address.")
        return canonical
    if channel == "phone":
        canonical = input_guard.valid_phone(address)
        if canonical is None:
            raise auth_svc.AuthError("Use international format, e.g. +919876543210.")
        return canonical
    raise auth_svc.AuthError("Unknown channel.")


def _canonical_channel(channel: str) -> str:
    """Whitelist the channel value; anything else becomes unusable."""
    return "email" if channel == "email" else ("phone" if channel == "phone" else "")


# ------------------------------------------------------------- challenge API --
def request_code(channel: str, address: str, client_ip: str = "unknown") -> dict:
    """Create a challenge and deliver it. Never returns the code in production.

    THE BUG THIS REPLACES
    ---------------------
    The previous version echoed the live code in the HTTP response whenever
    ``_deliver`` reported ``via == "dev"`` — and ``_deliver_email`` returned
    ``"dev"`` not only when SMTP was unconfigured but also **when SMTP was
    configured and the send failed**. Reproduced before the fix::

        POST /api/auth/otp/request {"channel":"email","address":"victim@x.com"}
        → {"sent": true, ..., "dev_code": "836443"}

    That is remote account takeover of *any* address on the platform, with no
    password and no second factor: request a code for the victim, read it out
    of your own response, verify it, receive their session token. A single
    mis-set ``OTP_SMTP_HOST``, one expired SMTP credential, or one attacker who
    can make the mail relay unreachable turns the entire user base into
    accounts that can be signed into at will.

    The fix is layered, because this is the highest-impact control in the file:

    1. Delivery capability is checked **before** a challenge is created, so a
       code that cannot be delivered never exists in the first place.
    2. A delivery *failure* deletes the challenge and surfaces an error. It
       never falls back to an echo path.
    3. The echo itself is gated on :func:`security.dev_code_echo_allowed`,
       which requires a non-production environment **and** an explicit
       ``FEEFIX_DEV_OTP_ECHO=1``. Two independent switches, both fail-closed.
    """
    _ensure_schema()
    channel = _canonical_channel(channel)
    address = normalize(channel, address)

    # Length ceiling before any storage work.
    if input_guard.reject_if_overlong(address, LIMITS.MAX_EMAIL_LEN):
        raise auth_svc.AuthError("Enter a valid email address.")

    # Per-(IP, destination) budget, then a per-destination budget that does not
    # depend on the sender at all. The second one exists to protect people who
    # never used FeeFix: without it, an attacker can make this platform send
    # unlimited paid SMS to an arbitrary number — a cost attack on us and a
    # harassment attack on the recipient.
    if not ratelimit.check_auth(client_ip, f"otp:{channel}:{address}"):
        raise auth_svc.AuthError("Too many attempts — try again later.")
    try:
        ratelimit.guard_otp_destination(client_ip, channel, address)
    except ratelimit.RateLimited:
        security.audit_security_event(
            "otp.destination_flood_blocked",
            f"channel={channel} to={_mask(channel, address)}",
        )
        raise auth_svc.AuthError("Too many codes requested for this number — wait an hour.")

    # 1. Capability gate — refuse before creating anything.
    capability = _delivery_capability(channel)
    if capability == "unavailable":
        security.audit_security_event(
            "otp.delivery_unconfigured", f"channel={channel} env={security.environment()}"
        )
        raise auth_svc.AuthError(
            "Code sign-in isn't available on this deployment right now — "
            "please use your password instead."
        )
    echo = capability == "dev" and security.dev_code_echo_allowed()

    conn = db.get_connection()
    now = _utcnow()
    cutoff = _iso(now - timedelta(hours=1))
    challenge_id = uuid.uuid4().hex

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
            wait = max(1, int((_parse(live["resend_after"]) - now).total_seconds()))
            raise auth_svc.AuthError(f"Code already sent — resend available in {wait} s.")

        # Opportunistic sweep: expired rows are never usable anywhere again.
        conn.execute("DELETE FROM otp_challenges WHERE expires_at < ?", (_iso(now),))

        code = "".join(secrets.choice("0123456789") for _ in range(CODE_LEN))
        salt = secrets.token_bytes(16).hex()
        conn.execute(
            "INSERT INTO otp_challenges"
            " (id, channel, address, code_hash, salt, attempts_left, expires_at, resend_after, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            (
                challenge_id,
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

    if delivered["via"] == "failed":
        # 2. The code exists but nobody received it. Destroy it and tell the
        #    user honestly — a generic "sent!" would leave them waiting for a
        #    message that will never arrive, and leaving the row alive would
        #    burn their resend cooldown against nothing.
        _delete_challenge(challenge_id)
        security.audit_security_event(
            "otp.delivery_failed",
            f"channel={channel} to={_mask(channel, address)} reason={delivered.get('error', '')}",
        )
        raise auth_svc.AuthError(
            "We couldn't deliver that code just now. Please try again in a minute."
        )

    # The address reaches the audit log masked. It is PII, and the log is the
    # one artefact that tends to be copied into dashboards and bug reports.
    db.audit(None, f"otp.request.{channel}",
             f"to={_mask(channel, address)} via={delivered['via']}")

    resp = {
        "sent": True,
        "channel": channel,
        "address": _mask(channel, address),
        "via": delivered["via"],
        "ttl_s": CODE_TTL_S,
        "resend_in": RESEND_COOLDOWN_S,
    }
    # 3. The only path by which a code ever appears in a response body.
    if echo and delivered["via"] == "dev":
        resp["dev_code"] = code
    return resp


def _delete_challenge(challenge_id: str) -> None:
    conn = db.get_connection()
    with db._lock:
        conn.execute("DELETE FROM otp_challenges WHERE id=?", (challenge_id,))
        conn.commit()


def _delivery_capability(channel: str) -> str:
    """``"live"`` | ``"dev"`` | ``"unavailable"`` — can we actually deliver?

    Decided from configuration alone, before any code is generated. In
    production an unconfigured channel is ``unavailable``; outside production
    it is ``dev``, which keeps the demo working without ever being reachable
    from a live deployment.
    """
    if channel == "email":
        configured = bool(security.env_str("OTP_SMTP_HOST"))
    elif channel == "phone":
        configured = bool(
            security.env_str("OTP_TWILIO_SID")
            and security.env_str("OTP_TWILIO_TOKEN")
            and security.env_str("OTP_TWILIO_FROM")
        )
    else:
        return "unavailable"
    if configured:
        return "live"
    return "dev" if security.unsafe_features_allowed() else "unavailable"


def verify_code(channel: str, address: str, code: str, name: str | None = None) -> dict | None:
    """Burn the challenge and return the authenticated user, or None."""
    _ensure_schema()
    channel = _canonical_channel(channel)
    try:
        address = normalize(channel, address)
    except auth_svc.AuthError:
        return None

    # Shape-gate the code BEFORE computing an HMAC over it. A caller who sends
    # a megabyte of digits should cost one length check, not one hash.
    code = (code or "").strip()
    if not code or len(code) > CODE_LEN + 2 or not code.isdigit():
        return None

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
    # The name is attacker-controlled free text that later lands in the UI and
    # in the OAuth handoff HTML. Bound it, strip bidi/control characters and
    # normalise it here, at the point of entry, so no downstream renderer has
    # to remember to.
    name = input_guard.bounded(name, LIMITS.MAX_NAME_LEN) or None
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
# Delivery outcomes are three-valued on purpose. The old code returned
# ``via="dev"`` for BOTH "not configured" and "configured but the send threw",
# and ``request_code`` echoed the live code whenever it saw ``"dev"``. Collapsing
# a failure into a development convenience is what made that an account-takeover
# bug. Here: "smtp"/"twilio" = delivered, "dev" = deliberately faked in a
# non-production environment, "failed" = tried and did not work.
FAKED = "dev"
FAILED = "failed"


def _deliver(channel: str, address: str, code: str) -> dict:
    if channel == "email":
        return _deliver_email(address, code)
    return _deliver_sms(address, code)


def _deliver_email(address: str, code: str) -> dict:
    host = security.env_str("OTP_SMTP_HOST")
    if not host:
        # Not configured. Whether this is acceptable was already decided by
        # _delivery_capability(); reaching here unconfigured in production is
        # impossible, so this branch is a dev/no-op signal only.
        return {"via": FAKED if security.unsafe_features_allowed() else FAILED,
                "error": "smtp not configured"}

    port = security.env_int("OTP_SMTP_PORT", 587, minimum=1, maximum=65535)
    user = security.env_str("OTP_SMTP_USER")
    password = security.env_str("OTP_SMTP_PASS").replace(" ", "")
    sender = security.env_str("OTP_SMTP_FROM", user or "no-reply@feefix.local")
    timeout = security.env_int("OTP_SMTP_TIMEOUT_S", 8, minimum=2, maximum=30)

    # Hostnames are allow-listed by shape before we open a socket to them. The
    # value comes from our own environment, but an operator who pastes a URL
    # instead of a host must not turn this into an SSRF pivot.
    if not _SAFE_HOST_RE.match(host):
        db.audit(None, "otp.email.error", "smtp host rejected by validation")
        return {"via": FAILED, "error": "smtp host invalid"}

    try:
        msg = EmailMessage()
        msg["From"] = sender
        msg["To"] = address
        msg["Subject"] = "Your FeeFix sign-in code"
        msg.set_content(
            f"Your FeeFix code is {code}\n\n"
            f"It expires in {CODE_TTL_S // 60} minutes. If you didn't request "
            "it, ignore this email and consider changing your password.\n"
        )
        # Header injection: a newline in the recipient address would let a
        # caller add Bcc/Cc headers and copy an attacker on someone else's code.
        # valid_email() already forbids control characters; this asserts it.
        if any(ord(c) < 32 for c in address):
            return {"via": FAILED, "error": "address rejected"}

        ctx = ssl.create_default_context()
        if port == 465:
            with smtplib.SMTP_SSL(host, port, timeout=timeout, context=ctx) as s:
                if user:
                    s.login(user, password)
                s.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=timeout) as s:
                # STARTTLS is mandatory, not opportunistic: an auth-less
                # plaintext SMTP session leaks the relay credentials and the
                # code to anyone on the path.
                s.starttls(context=ctx)
                if user:
                    s.login(user, password)
                s.send_message(msg)
        return {"via": "smtp"}
    except Exception as exc:
        # str(exc) from an SMTP library can contain the relay hostname, the
        # login it failed on, or the server's own banner. scrub_text() removes
        # credential-shaped key=value pairs and bounds the length; the class
        # name is enough for an operator to diagnose.
        db.audit(None, "otp.email.error",
                 security.scrub_text(f"{exc.__class__.__name__}: {exc}", 160))
        return {"via": FAILED, "error": "smtp failed"}


_SAFE_HOST_RE = re.compile(r"^[A-Za-z0-9._-]{1,253}$")


def _deliver_sms(address: str, code: str) -> dict:
    """Twilio-compatible REST send.

    Free SMS gateways do not exist, so this is the standard paid path
    (~$0.01-0.05/msg with a trial credit). Credentials are read once and never
    logged; the URL is a hardcoded HTTPS constant, so no user input can steer
    the request to another host (SSRF).
    """
    sid = security.env_str("OTP_TWILIO_SID")
    token = security.env_str("OTP_TWILIO_TOKEN")
    sender = security.env_str("OTP_TWILIO_FROM")
    if not (sid and token and sender):
        return {"via": FAKED if security.unsafe_features_allowed() else FAILED,
                "error": "sms provider not configured"}
    # Account SID is interpolated into the URL path; constrain its shape so a
    # malformed value cannot inject a path or query segment.
    if not re.match(r"^AC[A-Za-z0-9]{16,40}$", sid):
        db.audit(None, "otp.sms.error", "twilio sid rejected by validation")
        return {"via": FAILED, "error": "sms provider misconfigured"}

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
            r.read(_MAX_RESPONSE_BYTES)
        return {"via": "twilio"}
    except Exception as exc:
        # A Twilio error body can echo the request, including the auth header.
        # Only the exception class survives into the log.
        db.audit(None, "otp.sms.error", security.scrub_text(exc.__class__.__name__, 80))
        return {"via": FAILED, "error": "sms send failed"}


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
    """Which sign-in doors are genuinely open on this deployment.

    This is a capability *advertisement*, so it must not claim a door is open
    when the code behind it would only be echoed to the caller in development.
    An unavailable method is reported as unavailable and the UI dims it, rather
    than letting a user request a code that can never be delivered.
    """
    dev_echo = security.dev_code_echo_allowed()
    email_live = bool(security.env_str("OTP_SMTP_HOST"))
    phone_live = bool(
        security.env_str("OTP_TWILIO_SID")
        and security.env_str("OTP_TWILIO_TOKEN")
        and security.env_str("OTP_TWILIO_FROM")
    )
    return {
        "password": True,
        # A door is "open" when a code can actually reach the owner of the
        # address — either because a provider is configured, or because this is
        # a development deployment that echoes the code to the requester.
        "otp_email": email_live or dev_echo,
        "otp_phone": phone_live or dev_echo,
        "github": github_configured(),
        # The UI shows a "demo mode" banner when this is set, so a developer
        # never mistakes an echoed code for real delivery.
        "dev_otp_echo": dev_echo,
    }
