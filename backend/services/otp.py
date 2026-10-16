"""OTP (one-time-passcode) & OAuth sign-in — real delivery, stdlib-only.

WHAT THIS MODULE PROVIDES
=========================
1. **Email OTP** — 6-digit codes delivered to the recipient's real mailbox.
   Delivery is provider-pluggable and chosen from the environment:
     * ``smtp``    — any SMTP relay (Gmail app password, Yahoo, Outlook, Zoho,
       Amazon SES, Postmark, Mailgun, …). The *recipient's* mailbox provider is
       irrelevant; delivery depends only on YOUR relay.
     * ``brevo`` / ``resend`` — HTTPS APIs with free tiers, for hosts that
       block outbound SMTP ports (Render/Fly/HF Spaces free tiers often do).
     * ``webhook`` — your own HTTPS endpoint (JSON POST).
2. **Phone OTP (any country, E.164)** — the same challenge delivered by SMS
   through a pluggable gateway: ``twilio``, ``msg91`` (India/DLT), ``fast2sms``
   (India), ``vonage`` (Nexmo) or your own HTTPS ``webhook``. SMS is the one
   part that genuinely cannot be free — every gateway bills per message.
3. **Console fallback — development only** — with no gateway configured, the
   code is written to the server log and ``runtime/otp_outbox.jsonl`` (and, only
   outside production, echoed to the client as ``dev_code``) so local demos and
   the test suite keep working. **Production never echoes a code**: a deployment
   with no gateway answers 503 and the UI hides that door instead of pretending
   to have sent something.
4. **GitHub OAuth** — web flow (authorize → callback → user fetch) with signed
   one-time state tokens. Free forever; the only setup cost is a 2-minute OAuth
   App registration on github.com.

SECURITY POSTURE (mirrors backend/services/auth.py)
===================================================
* codes are 6-digit ``secrets`` draws with a per-code random salt; only
  HMAC-SHA256(pepper, salt ‖ code) is stored — DB leak reveals nothing usable
* 300 s expiry, ≤ 5 verify attempts (challenge burns after), 40 s resend
  cooldown, ≤ 5 codes/hour and ≤ 10 codes/day per destination
* code comparison is constant-time (``hmac.compare_digest``); a challenge is
  consumed atomically, so two concurrent verifies cannot both win
* delivery failures are *reported*, never hidden: the response says whether a
  real gateway carried the code, and a failed send is audited
* no code is ever written to a log, an outbox file or an API response when
  ``FEEFIX_ENV=production`` — the demo path is compiled out by configuration
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
import logging
import os
import re
import secrets
import smtplib
import ssl
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid
from pathlib import Path
from urllib import parse, request as urlreq

from backend.services import auth as auth_svc
from backend.services import db
from backend.services import secrets as secrets_svc

log = logging.getLogger("feefix.otp")

# ------------------------------------------------------------------ config --
#: Defaults. Every value is overridable through the environment (clamped to a
#: safe range by ``_int_env``), so an operator can tune without a code change.
CODE_TTL_S = 300            # 5 minutes
RESEND_COOLDOWN_S = 40
REQ_PER_HOUR = 5
CODE_LEN = 6
VERIFY_ATTEMPTS = 5
DAILY_PER_ADDRESS = 10      # anti-toll-fraud: hard cap per destination/24 h
OAUTH_STATE_TTL_S = 600
DELIVERY_ATTEMPTS = 2       # one retry for transient provider failures
RETRY_BACKOFF_S = 0.5
E164_RE = re.compile(r"^\+[1-9]\d{7,14}$")
RUNTIME_DIR = Path(__file__).resolve().parents[2] / "runtime"
OTP_OUTBOX = RUNTIME_DIR / "otp_outbox.jsonl"
_HTTP_TIMEOUT_S = 8
_OUTBOX_MAX_BYTES = 64 * 1024
_OUTBOX_KEEP_LINES = 50
_outbox_lock = threading.Lock()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts)


def _env(name: str, default: str = "") -> str:
    value = os.environ.get(name)
    return value.strip() if value and value.strip() else default


def _flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _int_env(name: str, default: int, low: int, high: int) -> int:
    raw = _env(name)
    try:
        value = int(raw) if raw else default
    except ValueError:
        log.warning("[otp] %s=%r is not an integer — using %s", name, raw, default)
        return default
    return max(low, min(high, value))


def _is_production() -> bool:
    return secrets_svc.is_production()


def _ttl_s() -> int:
    return _int_env("FEEFIX_OTP_TTL_S", CODE_TTL_S, 60, 900)


def _resend_s() -> int:
    return _int_env("FEEFIX_OTP_RESEND_S", RESEND_COOLDOWN_S, 15, 300)


def _per_hour() -> int:
    return _int_env("FEEFIX_OTP_PER_HOUR", REQ_PER_HOUR, 1, 20)


def _daily_cap() -> int:
    return _int_env("FEEFIX_OTP_DAILY_CAP", DAILY_PER_ADDRESS, 3, 50)


def _attempts() -> int:
    return _int_env("FEEFIX_OTP_ATTEMPTS", VERIFY_ATTEMPTS, 3, 10)


def _ttl_minutes() -> int:
    return max(1, _ttl_s() // 60)


# ------------------------------------------------------------- errors -------
class OtpError(auth_svc.AuthError):
    """Base sign-in error carrying the HTTP status the API should answer with.

    Subclasses of :class:`AuthError` on purpose: every existing caller that
    catches ``AuthError`` still works, while the routes can map each failure to
    the honest status code (422 bad input, 429 too many, 502 provider down,
    503 not configured) instead of flattening everything into "invalid".
    """

    status_code = 422
    retry_after: int | None = None


class OtpValidationError(OtpError):
    status_code = 422


class OtpRateLimited(OtpError):
    status_code = 429

    def __init__(self, message: str, retry_after: int | None = None):
        super().__init__(message)
        self.retry_after = retry_after


class OtpInvalidCode(OtpError):
    status_code = 401


class OtpExpired(OtpError):
    status_code = 410


class OtpTooManyAttempts(OtpError):
    status_code = 429


class OtpNotConfigured(OtpError):
    """No gateway for this channel and no demo allowed (always in production)."""

    status_code = 503


class OtpSendFailed(OtpError):
    """A gateway is configured but the message did not leave the building."""

    status_code = 502


# ------------------------------------------------------- schema (self-owned) --
# Additive: owned entirely by this module, independent of db._MIGRATIONS.
_SCHEMA = [
    """CREATE TABLE IF NOT EXISTS otp_challenges (
        id            TEXT PRIMARY KEY,
        channel       TEXT NOT NULL,           -- 'email' | 'phone'
        address       TEXT NOT NULL,           -- normalized destination
        code_hash     TEXT NOT NULL,           -- hmac(pepper, salt ‖ code)
        salt          TEXT NOT NULL,
        attempts_left INTEGER NOT NULL,
        expires_at    TEXT NOT NULL,
        resend_after  TEXT NOT NULL,
        created_at    TEXT NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS idx_otp_address ON otp_challenges(channel, address)",
    # Every accepted send, kept for 24 h. The challenge rows cannot carry this
    # bookkeeping: they are swept the moment they expire (5 min), which quietly
    # turned "≤5 codes/hour" into "≤5 codes per five minutes". Once every
    # message costs real money on an SMS gateway, an unenforced cap is a
    # billing incident (SMS pumping), so the counters get their own table.
    """CREATE TABLE IF NOT EXISTS otp_sends (
        id         TEXT PRIMARY KEY,
        channel    TEXT NOT NULL,
        address    TEXT NOT NULL,
        created_at TEXT NOT NULL,
        via        TEXT NOT NULL,               -- gateway, or 'pending' before delivery
        delivered  INTEGER NOT NULL DEFAULT 0
    )""",
    "CREATE INDEX IF NOT EXISTS idx_otp_sends ON otp_sends(channel, address, created_at)",
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


def _https_only(url: str) -> str:
    """Reject anything that is not ``https://`` before we open a connection.

    Outbound calls carry provider credentials (Twilio auth, GitHub OAuth), so the
    scheme is pinned: no ``file:``, ``ftp:`` or ``http:`` downgrade, and no
    redirect into a plaintext scheme. ``# nosec B310`` on the call sites below is
    justified by this check running immediately before them.
    """
    parsed = parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ValueError(f"refusing to open non-https URL: {parsed.scheme or 'no scheme'}")
    return url


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
    """Canonical form of a destination: lowercase email, E.164 phone.

    Accepts what students actually type: ``98765 43210``, ``098765-43210``,
    ``+91 98765 43210``, ``0091 98765 43210``, ``you@Gmail.com``.
    """
    address = (address or "").strip()
    if channel == "email":
        address = address.lower()
        if not auth_svc.EMAIL_RE.match(address):
            raise OtpValidationError("Enter a valid email address.")
        return address
    if channel == "phone":
        compact = re.sub(r"[\s\-().]", "", address)
        digits = re.sub(r"\D", "", compact)
        default_country = re.sub(r"\D", "", _env("OTP_DEFAULT_COUNTRY_CODE", "+91")) or "91"
        if compact.startswith("+"):
            candidate = "+" + digits
        elif compact.startswith("00"):
            candidate = "+" + digits[2:]
        elif len(digits) == 10:                       # bare Indian mobile
            candidate = "+" + default_country + digits
        elif len(digits) == 11 and digits.startswith("0"):   # trunk prefix
            candidate = "+" + default_country + digits[1:]
        elif 11 <= len(digits) <= 15:                 # already carries a country code
            candidate = "+" + digits
        else:
            candidate = compact
        if not E164_RE.match(candidate):
            raise OtpValidationError(
                "That doesn't look like a mobile number — use the international"
                " format, e.g. +919876543210."
            )
        return candidate
    raise OtpValidationError("Unknown sign-in channel.")


def _channel(channel: str) -> str:
    value = (channel or "").strip().lower()
    if value not in ("email", "phone"):
        raise OtpValidationError("Choose email or phone sign-in.")
    return value


# =============================================================== delivery ====
@dataclass(frozen=True)
class Delivery:
    """Outcome of one delivery attempt.

    ``delivered`` is the only field the sign-in flow trusts. ``via`` names the
    gateway ("smtp", "twilio", …) or the dev fallback ("console"); ``error`` is a
    short, credential-free reason that is safe to log (and, outside production,
    to show the developer); ``detail`` is a provider message id used for support.
    """

    delivered: bool
    via: str
    error: str | None = None
    retryable: bool = False
    detail: str | None = None
    #: False when this deployment has no gateway for the channel at all — the
    #: difference between "the relay refused the message" (502, try again) and
    #: "there is no relay" (503, and no amount of retrying will help).
    configured: bool = True

    def as_dict(self) -> dict:
        return {"delivered": self.delivered, "via": self.via, "error": self.error}


def _unconfigured(provider: str, error: str | None = None) -> Delivery:
    return Delivery(False, provider, error or "not configured", retryable=False,
                    configured=False)


def _is_demo(channel: str, delivery: Delivery) -> bool:
    """Whether the API may hand the code back instead of delivering it.

    Only ever true outside production, only for a send that did not reach a real
    gateway, and only when the operator has not switched the demo off.
    """
    return (not delivery.delivered) and dev_echo_enabled(channel)


def dev_echo_enabled(channel: str) -> bool:
    """May this deployment return a sign-in code in the API response?

    ``False`` in production, always, no matter what is set in the environment
    (a production boot that asks for it is refused by
    :func:`backend.services.secrets.enforce_secret_hygiene`). Outside production
    it defaults to on so a laptop with no gateway can still exercise the flow —
    the code is then labelled a demo everywhere it is shown.
    """
    if _is_production():
        return False
    per_channel = _flag(f"FEEFIX_OTP_DEV_ECHO_{channel.upper()}", default=True)
    return _flag("FEEFIX_OTP_DEV_ECHO", default=True) and per_channel


def email_provider() -> str | None:
    """Configured email gateway, or ``None`` (= console/demo only)."""
    explicit = _env("OTP_EMAIL_PROVIDER").lower()
    if explicit:
        return explicit if explicit in _EMAIL_SENDERS and _email_ready(explicit) else None
    for name in ("smtp", "brevo", "resend", "webhook"):
        if _email_ready(name):
            return name
    return None


def sms_provider() -> str | None:
    """Configured SMS gateway, or ``None`` (= console/demo only)."""
    explicit = _env("OTP_SMS_PROVIDER").lower()
    if explicit:
        return explicit if explicit in _SMS_SENDERS and _sms_ready(explicit) else None
    for name in ("twilio", "msg91", "fast2sms", "vonage", "webhook"):
        if _sms_ready(name):
            return name
    return None


def _email_ready(name: str) -> bool:
    if name == "smtp":
        return bool(_env("OTP_SMTP_HOST"))
    if name == "brevo":
        return bool(_env("OTP_BREVO_API_KEY"))
    if name == "resend":
        return bool(_env("OTP_RESEND_API_KEY"))
    if name == "webhook":
        return bool(_env("OTP_EMAIL_WEBHOOK_URL"))
    return False


def _sms_ready(name: str) -> bool:
    if name == "twilio":
        return bool(_env("OTP_TWILIO_SID") and _env("OTP_TWILIO_TOKEN")
                    and (_env("OTP_TWILIO_FROM") or _env("OTP_TWILIO_MESSAGING_SERVICE_SID")))
    if name == "msg91":
        return bool(_env("OTP_MSG91_AUTH_KEY") and _env("OTP_MSG91_TEMPLATE_ID"))
    if name == "fast2sms":
        return bool(_env("OTP_FAST2SMS_KEY"))
    if name == "vonage":
        return bool(_env("OTP_VONAGE_API_KEY") and _env("OTP_VONAGE_API_SECRET"))
    if name == "webhook":
        return bool(_env("OTP_SMS_WEBHOOK_URL"))
    return False


def delivery_status(channel: str) -> dict:
    """Per-channel truth: which gateway carries the code, or that none does."""
    channel = "email" if channel == "email" else "phone"
    provider = email_provider() if channel == "email" else sms_provider()
    demo = provider is None and dev_echo_enabled(channel)
    return {
        "provider": provider,
        "real": provider is not None,      # a real gateway will carry the code
        "demo": demo,                      # code is shown in the UI instead
        "usable": provider is not None or demo,
    }


def delivery_report() -> dict:
    """Operator-facing summary (boot log, /api/health, /api/auth/methods)."""
    status = {channel: delivery_status(channel) for channel in ("email", "phone")}
    return {
        "email": status["email"],
        "phone": status["phone"],
        "production": _is_production(),
        "demo_mode": any(item["demo"] for item in status.values()),
        "dev_inbox": dev_inbox_available(),
        "ttl_s": _ttl_s(),
        "resend_cooldown_s": _resend_s(),
        "attempts": _attempts(),
    }


def _not_configured_message(channel: str) -> str:
    """Actionable, operator-facing reason for a 503 (names the env vars)."""
    if channel == "email":
        return (
            "Email sign-in isn't configured on this deployment. Set OTP_SMTP_HOST,"
            " OTP_SMTP_USER and OTP_SMTP_PASS (a Gmail app password works), or"
            " OTP_BREVO_API_KEY / OTP_RESEND_API_KEY / OTP_EMAIL_WEBHOOK_URL."
        )
    return (
        "SMS sign-in isn't configured on this deployment. Set OTP_TWILIO_SID,"
        " OTP_TWILIO_TOKEN and OTP_TWILIO_FROM — or OTP_MSG91_AUTH_KEY +"
        " OTP_MSG91_TEMPLATE_ID, OTP_FAST2SMS_KEY, OTP_VONAGE_API_KEY +"
        " OTP_VONAGE_API_SECRET, or OTP_SMS_WEBHOOK_URL."
    )


def _sms_text(code: str) -> str:
    """Message body. Overridable because Indian DLT requires the *registered*
    template text, verbatim."""
    template = _env("OTP_SMS_TEMPLATE") or (
        "{code} is your FeeFix verification code. Valid for {minutes} minutes."
        " Never share it with anyone."
    )
    return (template.replace("{code}", code)
                    .replace("{minutes}", str(_ttl_minutes())))


def _email_bodies(code: str) -> tuple[str, str]:
    minutes = _ttl_minutes()
    text = (
        f"Your FeeFix verification code is {code}\n\n"
        f"It expires in {minutes} minutes. Enter it on the sign-in screen to finish.\n"
        "If you didn't request this code, ignore this email — nobody can sign in"
        " without it.\n"
    )
    html = (
        '<div style="font-family:Segoe UI,Roboto,Helvetica,Arial,sans-serif;'
        'font-size:15px;color:#111827;line-height:1.55">'
        '<p style="margin:0 0 12px">Your FeeFix verification code is:</p>'
        f'<p style="margin:0 0 12px;font-size:30px;font-weight:700;'
        f'letter-spacing:8px;color:#1d4ed8">{code}</p>'
        f'<p style="margin:0 0 12px">It expires in {minutes} minutes. Enter it on the'
        " sign-in screen to finish.</p>"
        '<p style="margin:0;color:#6b7280;font-size:13px">If you didn\'t request this'
        " code, ignore this email — nobody can sign in without it.</p>"
        "</div>"
    )
    return text, html


def _email_message(address: str, code: str, sender: str) -> EmailMessage:
    text, html = _email_bodies(code)
    msg = EmailMessage()
    msg["From"] = formataddr((_env("OTP_SMTP_FROM_NAME", "FeeFix"), sender))
    msg["To"] = address
    msg["Subject"] = _env("OTP_EMAIL_SUBJECT", "Your FeeFix verification code")
    msg["Date"] = formatdate(localtime=True)
    domain = sender.split("@")[-1] if "@" in sender else None
    msg["Message-ID"] = make_msgid(domain=domain)
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")
    return msg


def _post_json(url: str, payload: dict, headers: dict | None = None, *,
               form: bool = False, timeout: int = _HTTP_TIMEOUT_S) -> tuple[int, str]:
    """HTTPS POST returning ``(status, body)`` — HTTP errors are *results*, not
    exceptions, so a provider's 400 with a reason is reported to the operator
    instead of being swallowed as "unknown failure"."""
    if form:
        body = parse.urlencode({k: str(v) for k, v in payload.items()}).encode()
        content_type = "application/x-www-form-urlencoded"
    else:
        body = json.dumps(payload).encode("utf-8")
        content_type = "application/json"
    req = urlreq.Request(
        _https_only(url),
        data=body,
        headers={"Content-Type": content_type, "Accept": "application/json",
                 **(headers or {})},
        method="POST",
    )
    try:
        with urlreq.urlopen(req, timeout=timeout) as resp:  # nosec B310
            return resp.status, resp.read(8192).decode("utf-8", "replace")
    except urlreq.HTTPError as exc:
        return exc.code, exc.read(4096).decode("utf-8", "replace")


def _json_or_empty(text: str) -> dict:
    try:
        data = json.loads(text or "")
    except (ValueError, TypeError):
        return {}
    return data if isinstance(data, dict) else {}


def _provider_error(text: str, keys: tuple[str, ...] = ("message", "error", "detail")) -> str:
    """Short, credential-free reason from a provider's error body."""
    data = _json_or_empty(text)
    for key in keys:
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()[:160]
    flat = " ".join((text or "").split())
    return flat[:160] if flat else "provider rejected the request"


def _http_result(status: int, text: str, provider: str) -> Delivery:
    """Uniform success/retry decision for an HTTPS provider response."""
    if 200 <= status < 300:
        data = _json_or_empty(text)
        message_id = None
        for key in ("id", "sid", "messageId", "message_id", "request_id"):
            value = data.get(key)
            if isinstance(value, str) and value:
                message_id = value[:64]
                break
        return Delivery(True, provider, None, detail=message_id)
    return Delivery(False, provider, _provider_error(text),
                    retryable=status >= 500 or status == 429)


def _attempt(send, address: str, code: str, provider: str) -> Delivery:
    """Run one provider with a single retry for transient failures."""
    last = Delivery(False, provider, "no attempt made", retryable=True)
    for attempt in range(1, DELIVERY_ATTEMPTS + 1):
        try:
            last = send(address, code)
        except Exception as exc:  # noqa: BLE001 — a provider bug must never 500 a sign-in
            last = Delivery(False, provider, f"{exc.__class__.__name__}", retryable=True)
        if last.delivered:
            return last
        if not last.retryable or attempt == DELIVERY_ATTEMPTS:
            break
        time.sleep(RETRY_BACKOFF_S * attempt)
    return last


# ------------------------------------------------------------ email senders --
def _send_smtp(address: str, code: str) -> Delivery:
    host = _env("OTP_SMTP_HOST")
    if not host:
        return _unconfigured("smtp")
    port = _int_env("OTP_SMTP_PORT", 587, 1, 65535)
    user = _env("OTP_SMTP_USER")
    password = _env("OTP_SMTP_PASS").replace(" ", "")   # Gmail app passwords arrive spaced
    sender = _env("OTP_SMTP_FROM", user or f"no-reply@{host}")
    secure = _flag("OTP_SMTP_SECURE", port == 465)
    # STARTTLS is required by default. `auto` exists for local relays (MailHog,
    # Papercut, a company smarthost on port 25) that do not offer it — it is an
    # explicit opt-in, because silently mailing credentials over plaintext is
    # exactly the kind of convenience a later "why was it unencrypted?" blames.
    starttls = _env("OTP_SMTP_STARTTLS", "required").lower()
    timeout = _int_env("OTP_SMTP_TIMEOUT", 10, 3, 30)
    msg = _email_message(address, code, sender)
    ctx = ssl.create_default_context()
    try:
        if secure:
            with smtplib.SMTP_SSL(host, port, timeout=timeout, context=ctx) as smtp:
                if user:
                    smtp.login(user, password)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=timeout) as smtp:
                smtp.ehlo()
                supports_tls = smtp.has_extn("starttls")
                if starttls == "off" or not supports_tls:
                    if starttls == "required" and not supports_tls:
                        raise smtplib.SMTPNotSupportedError(
                            f"{host} does not offer STARTTLS (set"
                            " OTP_SMTP_STARTTLS=auto for a local relay)"
                        )
                    log.warning("[otp] %s does not offer STARTTLS — sending the code"
                                " over an unencrypted connection", host)
                else:
                    smtp.starttls(context=ctx)
                    smtp.ehlo()
                if user:
                    smtp.login(user, password)
                smtp.send_message(msg)
        return Delivery(True, "smtp")
    except smtplib.SMTPNotSupportedError as exc:
        # Configuration, not weather: retrying cannot add an extension.
        return Delivery(False, "smtp", str(exc)[:160], retryable=False)
    except smtplib.SMTPAuthenticationError:
        # A wrong app password is a *configuration* error: retrying cannot help
        # and the operator needs to hear about it in words, not a stack trace.
        return Delivery(False, "smtp",
                        "SMTP login refused — check OTP_SMTP_USER/OTP_SMTP_PASS"
                        " (Gmail needs a 16-character app password)", retryable=False)
    except (smtplib.SMTPRecipientsRefused, smtplib.SMTPSenderRefused) as exc:
        return Delivery(False, "smtp", f"address refused by the relay: {exc.__class__.__name__}",
                        retryable=False)
    except smtplib.SMTPException as exc:
        return Delivery(False, "smtp", f"SMTP error: {exc.__class__.__name__}", retryable=True)
    except (OSError, ssl.SSLError) as exc:
        # Includes timeouts and ports blocked by the host (a real Render/Fly
        # free-tier failure mode) — worth one retry, then report honestly.
        return Delivery(False, "smtp", f"connection failed: {exc.__class__.__name__}",
                        retryable=True)


def _send_brevo(address: str, code: str) -> Delivery:
    key = _env("OTP_BREVO_API_KEY")
    if not key:
        return _unconfigured("brevo")
    sender = _env("OTP_SMTP_FROM", _env("OTP_BREVO_FROM"))
    if not sender:
        return _unconfigured("brevo", "OTP_BREVO_FROM/OTP_SMTP_FROM is not set")
    text, html = _email_bodies(code)
    status, body = _post_json(
        "https://api.brevo.com/v3/smtp/email",
        {
            "sender": {"email": sender, "name": _env("OTP_SMTP_FROM_NAME", "FeeFix")},
            "to": [{"email": address}],
            "subject": _env("OTP_EMAIL_SUBJECT", "Your FeeFix verification code"),
            "htmlContent": html,
            "textContent": text,
        },
        headers={"api-key": key},
    )
    return _http_result(status, body, "brevo")


def _send_resend(address: str, code: str) -> Delivery:
    key = _env("OTP_RESEND_API_KEY")
    if not key:
        return _unconfigured("resend")
    sender = _env("OTP_SMTP_FROM", _env("OTP_RESEND_FROM", "FeeFix <onboarding@resend.dev>"))
    text, html = _email_bodies(code)
    status, body = _post_json(
        "https://api.resend.com/emails",
        {
            "from": sender,
            "to": [address],
            "subject": _env("OTP_EMAIL_SUBJECT", "Your FeeFix verification code"),
            "text": text,
            "html": html,
        },
        headers={"Authorization": f"Bearer {key}"},
    )
    return _http_result(status, body, "resend")


def _send_email_webhook(address: str, code: str) -> Delivery:
    url = _env("OTP_EMAIL_WEBHOOK_URL")
    if not url:
        return _unconfigured("webhook")
    text, html = _email_bodies(code)
    subject = _env("OTP_EMAIL_SUBJECT", "Your FeeFix verification code")
    headers = {}
    token = _env("OTP_EMAIL_WEBHOOK_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    status, body = _post_json(
        url,
        {"to": address, "channel": "email", "code": code, "subject": subject,
         "text": text, "html": html,
         "from": _env("OTP_SMTP_FROM", "no-reply@feefix.in")},
        headers=headers,
    )
    return _http_result(status, body, "webhook")


# -------------------------------------------------------------- SMS senders --
def _send_twilio(address: str, code: str) -> Delivery:
    sid = _env("OTP_TWILIO_SID")
    token = _env("OTP_TWILIO_TOKEN")
    sender = _env("OTP_TWILIO_FROM")
    service = _env("OTP_TWILIO_MESSAGING_SERVICE_SID")
    if not (sid and token and (sender or service)):
        return _unconfigured("twilio")
    payload = {"To": address, "Body": _sms_text(code)}
    if service:
        payload["MessagingServiceSid"] = service
    else:
        payload["From"] = sender
    status, body = _post_json(
        f"https://api.twilio.com/2010-04-01/Accounts/{parse.quote(sid, safe='')}/Messages.json",
        payload,
        headers={
            "Authorization": "Basic "
            + base64.b64encode(f"{sid}:{token}".encode()).decode(),
        },
        form=True,
    )
    return _http_result(status, body, "twilio")


def _send_msg91(address: str, code: str) -> Delivery:
    """MSG91 — the mainstream Indian SMS gateway.

    ``flow`` (default) posts to the Flow API with a DLT-approved template;
    ``OTP_MSG91_MODE=otp`` uses the classic Send-OTP endpoint with our own code.
    """
    authkey = _env("OTP_MSG91_AUTH_KEY")
    template = _env("OTP_MSG91_TEMPLATE_ID")
    if not (authkey and template):
        return _unconfigured("msg91")
    mobile = address.lstrip("+")                       # MSG91 wants 91XXXXXXXXXX
    if _env("OTP_MSG91_MODE", "flow").lower() in ("otp", "send-otp", "send_otp"):
        query = parse.urlencode({
            "authkey": authkey, "template_id": template, "mobile": mobile, "otp": code,
        })
        status, body = _post_json(f"https://control.msg91.com/api/v5/otp?{query}", {},
                                  headers={"authkey": authkey})
        return _msg91_result(status, body)
    var_name = _env("OTP_MSG91_VAR", "VAR1")
    payload = {
        "template_id": template,
        "short_url": "0",
        "recipients": [{"mobiles": mobile, var_name: code}],
    }
    sender_id = _env("OTP_MSG91_SENDER_ID")
    if sender_id:
        payload["sender"] = sender_id
    status, body = _post_json("https://control.msg91.com/api/v5/flow/", payload,
                              headers={"authkey": authkey})
    return _msg91_result(status, body)


def _msg91_result(status: int, body: str) -> Delivery:
    """MSG91 answers ``{"type":"error", "message": …}`` with HTTP 200 on a bad
    template or an exhausted wallet — a status-code-only check would call that
    a delivered code and leave the student waiting."""
    if 200 <= status < 300:
        data = _json_or_empty(body)
        if str(data.get("type", "")).lower() == "success":
            return Delivery(True, "msg91", detail=str(data.get("message") or "")[:64] or None)
        if data:
            return Delivery(False, "msg91", _provider_error(body), retryable=False)
        return Delivery(True, "msg91")
    return _http_result(status, body, "msg91")


def _send_fast2sms(address: str, code: str) -> Delivery:
    """Fast2SMS — cheapest Indian SMS route (https://www.fast2sms.com)."""
    key = _env("OTP_FAST2SMS_KEY")
    if not key:
        return _unconfigured("fast2sms")
    if not address.startswith("+91"):
        return Delivery(False, "fast2sms",
                        "Fast2SMS only delivers to Indian (+91) numbers", retryable=False)
    route = _env("OTP_FAST2SMS_ROUTE", "q").lower()
    payload = {"route": route, "numbers": address[3:]}
    if route == "dlt":
        payload.update({
            "sender_id": _env("OTP_FAST2SMS_SENDER_ID"),
            "message": _env("OTP_FAST2SMS_TEMPLATE_ID"),
            "variables_values": code,
        })
    else:
        payload["message"] = _sms_text(code)
    status, body = _post_json("https://www.fast2sms.com/dev/bulkV2", payload,
                              headers={"authorization": key})
    if 200 <= status < 300:
        # Fast2SMS reports failure as {"return": false, "message": "…"} with a
        # 200, so the body decides — not the status line.
        data = _json_or_empty(body)
        if data.get("return") in (True, "true") or data.get("request_id"):
            return Delivery(True, "fast2sms", detail=str(data.get("request_id") or "")[:64] or None)
        if data:
            return Delivery(False, "fast2sms", _provider_error(body), retryable=False)
    return _http_result(status, body, "fast2sms")


def _send_vonage(address: str, code: str) -> Delivery:
    key = _env("OTP_VONAGE_API_KEY")
    secret = _env("OTP_VONAGE_API_SECRET")
    if not (key and secret):
        return _unconfigured("vonage")
    status, body = _post_json(
        "https://rest.nexmo.com/sms/json",
        {"api_key": key, "api_secret": secret, "to": address.lstrip("+"),
         "from": _env("OTP_VONAGE_FROM", "FeeFix"), "text": _sms_text(code)},
        form=True,
    )
    if not (200 <= status < 300):
        return Delivery(False, "vonage", _provider_error(body), retryable=status >= 500)
    messages = _json_or_empty(body).get("messages") or [{}]
    first = messages[0] if isinstance(messages[0], dict) else {}
    if str(first.get("status")) != "0":
        return Delivery(False, "vonage",
                        first.get("error-text") or f"status {first.get('status')}",
                        retryable=False)
    return Delivery(True, "vonage", detail=str(first.get("message-id") or "") or None)


def _send_sms_webhook(address: str, code: str) -> Delivery:
    url = _env("OTP_SMS_WEBHOOK_URL")
    if not url:
        return _unconfigured("webhook")
    headers = {}
    token = _env("OTP_SMS_WEBHOOK_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    status, body = _post_json(
        url,
        {"to": address, "channel": "sms", "code": code, "text": _sms_text(code),
         "sender": _env("OTP_TWILIO_FROM", "FeeFix")},
        headers=headers,
    )
    return _http_result(status, body or '{"ok":true}', "webhook")


_EMAIL_SENDERS = {
    "smtp": _send_smtp,
    "brevo": _send_brevo,
    "resend": _send_resend,
    "webhook": _send_email_webhook,
}
_SMS_SENDERS = {
    "twilio": _send_twilio,
    "msg91": _send_msg91,
    "fast2sms": _send_fast2sms,
    "vonage": _send_vonage,
    "webhook": _send_sms_webhook,
}


# ---------------------------------------------------------- dev outbox ------
def _outbox_write(channel: str, address: str, code: str, via: str) -> None:
    """Record a console/dev delivery so a developer can read the code from a
    file or ``GET /api/auth/otp/dev-inbox`` instead of hunting the log.

    Never called in production: the file would be a plaintext credential store.
    """
    if _is_production():
        return
    entry = {"channel": channel, "address": address, "code": code, "via": via,
             "created_at": _iso(_utcnow())}
    try:
        with _outbox_lock:
            RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
            if OTP_OUTBOX.exists() and OTP_OUTBOX.stat().st_size > _OUTBOX_MAX_BYTES:
                keep = OTP_OUTBOX.read_text(encoding="utf-8").splitlines()[-_OUTBOX_KEEP_LINES:]
                OTP_OUTBOX.write_text("\n".join(keep) + "\n", encoding="utf-8")
            with OTP_OUTBOX.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
            os.chmod(OTP_OUTBOX, 0o600)
    except OSError as exc:  # the outbox is a convenience; never fail a sign-in for it
        log.warning("[otp] could not write %s: %s", OTP_OUTBOX.name, exc.__class__.__name__)


def dev_inbox_available() -> bool:
    """Whether the development inbox exists at all (never in production)."""
    return (not _is_production()) and (
        dev_echo_enabled("email") or dev_echo_enabled("phone")
    )


def dev_inbox(address: str | None = None, limit: int = 10) -> list[dict]:
    """Codes the console fallback "delivered", newest first (dev/CI only)."""
    if not dev_inbox_available() or not OTP_OUTBOX.exists():
        return []
    wanted = None
    if address:
        for channel in ("email", "phone"):
            try:
                wanted = normalize(channel, address)
            except auth_svc.AuthError:
                continue
            break
    entries: list[dict] = []
    try:
        lines = OTP_OUTBOX.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    for line in reversed(lines):
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if not isinstance(entry, dict) or "code" not in entry:
            continue
        if wanted and entry.get("address") != wanted:
            continue
        entries.append({k: entry.get(k) for k in ("channel", "address", "code", "via", "created_at")})
        if len(entries) >= max(1, min(limit, 50)):
            break
    return entries


# ------------------------------------------------------------- delivery ------
def _console_fallback(channel: str, address: str, code: str) -> Delivery:
    """No gateway configured.

    Outside production the code goes to the server log and the dev outbox, and
    the caller may hand it back labelled as a demo. In **production** nothing is
    written and nothing is echoed: a sign-in code that exists only in a log is a
    credential leak, not a fallback, so the request fails closed instead.
    """
    if _is_production():
        return Delivery(False, "unconfigured", _not_configured_message(channel),
                        retryable=False, configured=False)
    log.warning("[otp] no %s gateway configured — dev code for %s is %s",
                channel, address, code)
    _outbox_write(channel, address, code, "console")
    return Delivery(False, "console", "no gateway configured — development fallback",
                    retryable=False, configured=False)


def _deliver(channel: str, address: str, code: str) -> Delivery:
    provider = email_provider() if channel == "email" else sms_provider()
    if provider is None:
        return _console_fallback(channel, address, code)
    sender = _EMAIL_SENDERS[provider] if channel == "email" else _SMS_SENDERS[provider]
    delivery = _attempt(sender, address, code, provider)
    if delivery.delivered:
        db.audit(None, f"otp.send.{channel}", f"via={provider} id={delivery.detail or '-'}")
    else:
        db.audit(None, f"otp.send_failed.{channel}",
                 f"via={provider} error={delivery.error}")
    return delivery


def _public_delivery(delivery: Delivery, demo: bool) -> dict:
    """What the client is told about delivery.

    Providers' error text is shown outside production only — an operator needs
    it to fix the relay, and a production user cannot act on it anyway.
    """
    payload = {"via": delivery.via, "delivered": delivery.delivered, "demo": demo}
    if delivery.error and not _is_production():
        payload["error"] = delivery.error
    return payload


# ------------------------------------------------------------- challenge API --
def request_code(channel: str, address: str, client_ip: str = "unknown") -> dict:
    """Create a challenge and *actually* deliver it.

    Returns delivery facts: ``sent`` (a code is on its way — ``delivered`` by a
    real gateway, or shown as a labelled demo), ``via``, ``demo``, ``ttl_s``
    and ``resend_in``. ``dev_code`` is present only in a labelled development
    demo. Raises :class:`OtpError` subclasses so the API can answer
    422/429/502/503 honestly, instead of flattening every failure into "bad
    code" — the difference between "your relay is down" and "there is no relay"
    is the difference between a retry and a call to the operator.
    """
    from backend.services import ratelimit

    _ensure_schema()
    channel = _channel(channel)
    address = normalize(channel, address)
    if not ratelimit.check_auth(client_ip, f"otp:{channel}:{address}"):
        raise OtpRateLimited("Too many attempts — try again later.", retry_after=60)

    conn = db.get_connection()
    now = _utcnow()
    hour_ago = _iso(now - timedelta(hours=1))
    day_ago = _iso(now - timedelta(hours=24))
    ttl_s, resend_s = _ttl_s(), _resend_s()

    with db._lock:
        recent = conn.execute(
            "SELECT COUNT(*) AS n FROM otp_sends WHERE channel=? AND address=? AND created_at>=?",
            (channel, address, hour_ago),
        ).fetchone()["n"]
        if recent >= _per_hour():
            raise OtpRateLimited("Too many codes requested — try again in an hour.",
                                 retry_after=3600)

        # Anti-toll-fraud: a destination that keeps asking for codes burns real
        # money (SMS) and is the classic first sign of an SMS-pumping attack.
        daily = conn.execute(
            "SELECT COUNT(*) AS n FROM otp_sends WHERE channel=? AND address=? AND created_at>=?",
            (channel, address, day_ago),
        ).fetchone()["n"]
        if daily >= _daily_cap():
            raise OtpRateLimited(
                "That's a lot of codes for today — contact support if this isn't you.",
                retry_after=3600,
            )

        last = conn.execute(
            "SELECT created_at FROM otp_sends WHERE channel=? AND address=?"
            " ORDER BY created_at DESC LIMIT 1",
            (channel, address),
        ).fetchone()
        if last:
            ready_at = _parse(last["created_at"]) + timedelta(seconds=resend_s)
            if ready_at > now:
                wait = max(1, int((ready_at - now).total_seconds()) + 1)
                raise OtpRateLimited(f"Code already sent — you can resend in {wait} s.",
                                     retry_after=wait)

        # Opportunistic sweep: neither an expired challenge nor a >24 h send is
        # usable anywhere again.
        conn.execute("DELETE FROM otp_challenges WHERE expires_at < ?", (_iso(now),))
        conn.execute("DELETE FROM otp_sends WHERE created_at < ?", (day_ago,))

        code = "".join(secrets.choice("0123456789") for _ in range(CODE_LEN))
        salt = secrets.token_bytes(16).hex()
        challenge_id = uuid.uuid4().hex
        send_id = uuid.uuid4().hex
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
                _attempts(),
                _iso(now + timedelta(seconds=ttl_s)),
                _iso(now + timedelta(seconds=resend_s)),
                _iso(now),
            ),
        )
        # Counted *before* the network call, so two concurrent requests cannot
        # both slip past the cap, and removed again if the send fails.
        conn.execute(
            "INSERT INTO otp_sends (id, channel, address, created_at, via, delivered)"
            " VALUES (?,?,?,?,'pending',0)",
            (send_id, channel, address, _iso(now)),
        )
        conn.commit()

    # Network I/O happens outside the DB lock: a slow relay must not freeze
    # every other request. A failure here rolls the bookkeeping back, so neither
    # the challenge nor the caller's hourly/daily budget is spent on a message
    # that nobody received.
    delivery = _deliver(channel, address, code)
    demo = _is_demo(channel, delivery)
    if not delivery.delivered and not demo:
        with db._lock:
            conn.execute("DELETE FROM otp_challenges WHERE id=?", (challenge_id,))
            conn.execute("DELETE FROM otp_sends WHERE id=?", (send_id,))
            conn.commit()
        db.audit(None, f"otp.request.{channel}", f"to={address} failed via={delivery.via}")
        if not delivery.configured:
            # Always name the environment variables: this message is read by the
            # person who can actually fix it.
            detail = _not_configured_message(channel)
            if delivery.via not in ("console", "unconfigured") and delivery.error:
                detail = f"{detail} ({delivery.error})"
            raise OtpNotConfigured(detail)
        raise OtpSendFailed(
            "We couldn't send the code right now — please try again in a minute."
        )

    with db._lock:
        conn.execute(
            "UPDATE otp_sends SET via=?, delivered=? WHERE id=?",
            (delivery.via, 1 if delivery.delivered else 0, send_id),
        )
        conn.commit()

    db.audit(None, f"otp.request.{channel}",
             f"to={address} via={delivery.via} delivered={delivery.delivered}")
    response = {
        "sent": True,
        "channel": channel,
        "address": _mask(channel, address),
        "via": delivery.via,
        "delivered": delivery.delivered,
        "demo": demo,
        "delivery": _public_delivery(delivery, demo),
        "ttl_s": ttl_s,
        "resend_in": resend_s,
    }
    if demo:
        # Development only (see dev_echo_enabled): production cannot reach here.
        response["dev_code"] = code
        response["message"] = (
            "Demo mode: no %s gateway is configured on this server, so the code is"
            " shown here instead of being sent." % ("email" if channel == "email" else "SMS")
        )
    return response


def verify_code(channel: str, address: str, code: str, name: str | None = None) -> dict | None:
    """Burn the challenge and return the authenticated user.

    Raises :class:`OtpInvalidCode` / :class:`OtpExpired` /
    :class:`OtpTooManyAttempts` (all with the same wording whether or not the
    destination has an account — no user enumeration). Returns ``None`` only for
    an unusable input, which the route treats as a plain 401.
    """
    _ensure_schema()
    channel = _channel(channel)
    try:
        address = normalize(channel, address)
    except auth_svc.AuthError:
        return None          # unusable destination → the same 401 as a wrong code
    code = re.sub(r"\D", "", code or "")
    if not code:
        return None

    conn = db.get_connection()
    now = _utcnow()
    with db._lock:
        # Read-modify-write inside one lock: two concurrent attempts on the last
        # remaining try must not both be accepted.
        row = conn.execute(
            "SELECT * FROM otp_challenges WHERE channel=? AND address=?"
            " ORDER BY created_at DESC LIMIT 1",
            (channel, address),
        ).fetchone()
        if not row:
            return None
        if _parse(row["expires_at"]) < now:
            conn.execute("DELETE FROM otp_challenges WHERE id=?", (row["id"],))
            conn.commit()
            raise OtpExpired("That code expired — request a new one.")
        ok = hmac.compare_digest(_hash_code(code, row["salt"]), row["code_hash"])
        if ok:
            # single-use: consume every challenge for this destination
            conn.execute("DELETE FROM otp_challenges WHERE channel=? AND address=?",
                         (channel, address))
            conn.commit()
        elif row["attempts_left"] <= 1:
            conn.execute("DELETE FROM otp_challenges WHERE id=?", (row["id"],))
            conn.commit()
            raise OtpTooManyAttempts(
                "Too many wrong codes — request a new one."
            )
        else:
            left = row["attempts_left"] - 1
            conn.execute(
                "UPDATE otp_challenges SET attempts_left=? WHERE id=?", (left, row["id"])
            )
            conn.commit()
            raise OtpInvalidCode(
                f"That code didn't match — {left} attempt{'s' if left != 1 else ''} left."
            )

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
        if "@" not in address:
            return address[:2] + "***"
        user, domain = address.split("@", 1)
        return (user[:2] if len(user) > 2 else user[:1]) + "***@" + domain
    return address[:4] + "****" + address[-2:] if len(address) > 8 else address


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
    with urlreq.urlopen(_https_only(req.full_url), timeout=_HTTP_TIMEOUT_S) as r:  # nosec B310
        return json.loads(r.read().decode())


def _http_json_get(url: str, gh_token: str):
    req = urlreq.Request(url, headers={
        "Authorization": f"Bearer {gh_token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "feefix-india",
    })
    with urlreq.urlopen(_https_only(req.full_url), timeout=_HTTP_TIMEOUT_S) as r:  # nosec B310
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
    """Which sign-in doors are open — the UI dims ones that are not.

    ``otp_email``/``otp_phone`` mean "this door works here": either a real
    gateway will carry the code, or the labelled development demo is available.
    ``delivery`` says which of the two it is, so the UI can be honest — a code
    shown in the browser because no gateway exists is a demo, never a delivery,
    and it can never happen in production.
    """
    email = delivery_status("email")
    phone = delivery_status("phone")
    return {
        "password": True,
        "otp_email": email["usable"],
        "otp_phone": phone["usable"],
        "github": github_configured(),
        "delivery": delivery_report(),
    }
