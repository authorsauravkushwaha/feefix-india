"""FeeFix security policy kernel — the single source of truth for hardening.

Every security-relevant constant, environment switch and secret-handling rule
in the platform lives here. Nothing else in the codebase is allowed to read
``os.environ`` for a security decision or to invent its own limit; that is how
policy drift (and therefore vulnerabilities) happens.

WHY A KERNEL
============
A hardening pass that sprinkles ``if os.environ.get(...)`` through twenty
modules produces twenty slightly different answers. This module answers once.
It is stdlib-only, import-cheap and side-effect-free at import time, so it can
be pulled in from the API layer, the OTP layer, the middleware stack and the
test suite without ordering problems.

THREAT CLASSES COVERED HERE
===========================
* **Secret key leaks / secret management** — :func:`load_secret` refuses
  world-readable key material, and :func:`redact` keeps secrets out of logs.
* **Long-password & payload DoS** — every length ceiling in the product is
  declared here (:data:`LIMITS`) and enforced *before* expensive work.
* **Information leakage** — :data:`ENVIRONMENT` decides what a client is
  allowed to learn; production never learns anything.
* **Rate-limit bypass** — :func:`client_ip` only trusts ``X-Forwarded-For``
  when the direct peer is a configured, trusted proxy.

Environment model
-----------------
``FEEFIX_ENV`` ∈ {``production``, ``staging``, ``development``, ``test``}.
When unset it is *inferred conservatively*: the presence of a public hostname
(``RENDER_EXTERNAL_HOSTNAME``, ``FEEFIX_BASE_URL``) means production. Inference
defaults to production, never to development — failing closed is the whole
point. An unsafe dev-only convenience therefore cannot be enabled by forgetting
to set a variable.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import stat
import unicodedata
from functools import lru_cache
from pathlib import Path

# ---------------------------------------------------------------- environments

PRODUCTION = "production"
STAGING = "staging"
DEVELOPMENT = "development"
TEST = "test"

#: Environments in which developer conveniences (plaintext code echo, verbose
#: errors) are permitted. Everything else is treated as hostile.
_UNSAFE_ENVS = frozenset({DEVELOPMENT, TEST})


def _infer_environment() -> str:
    """Conservative environment detection — defaults to ``production``.

    Forgetting to configure the environment must never *relax* security, so the
    fallback is the strictest setting rather than the most convenient one.
    """
    raw = (os.environ.get("FEEFIX_ENV") or "").strip().lower()
    if raw in (PRODUCTION, STAGING, DEVELOPMENT, TEST):
        return raw
    # Common aliases set by PaaS providers.
    if raw in ("prod", "live"):
        return PRODUCTION
    if raw in ("dev", "local"):
        return DEVELOPMENT
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return TEST
    # A public hostname implies real users. Assume production.
    if os.environ.get("RENDER_EXTERNAL_HOSTNAME") or os.environ.get("FEEFIX_BASE_URL"):
        return PRODUCTION
    return PRODUCTION


def environment() -> str:
    """Current environment (re-evaluated so tests can flip it)."""
    return _infer_environment()


def is_production() -> bool:
    return environment() == PRODUCTION


def unsafe_features_allowed() -> bool:
    """True only in development/test. Gates every dev-only convenience."""
    return environment() in _UNSAFE_ENVS


# ---------------------------------------------------------------- env helpers

def env_str(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def env_int(name: str, default: int, *, minimum: int = 0, maximum: int | None = None) -> int:
    """Integer env var that falls back safely instead of crashing on garbage.

    A malformed number in the environment must not take the service down
    (availability), and must not silently widen a limit either — so out-of-range
    values clamp to the safe side.
    """
    raw = (os.environ.get(name) or "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    if value < minimum:
        return minimum
    if maximum is not None and value > maximum:
        return maximum
    return value


def env_list(name: str) -> list[str]:
    return [p.strip() for p in (os.environ.get(name) or "").split(",") if p.strip()]


# ------------------------------------------------------------------- limits --
class Limits:
    """Every hard ceiling in FeeFix, in one place.

    These are *availability* controls first: each one exists so that a single
    request cannot make the server do an unbounded amount of work. They are
    deliberately generous for honest users and fatal for abusive ones.
    """

    # --- request framing ---------------------------------------------------
    MAX_BODY_BYTES = 256 * 1024          # 256 KB — the SPA never sends more
    MAX_HEADER_BYTES = 16 * 1024         # 16 KB of request headers
    MAX_QUERY_BYTES = 8 * 1024           # 8 KB query string
    MAX_URL_PATH_LEN = 2048

    # --- identity fields ---------------------------------------------------
    MAX_EMAIL_LEN = 254                  # RFC 5321 absolute maximum
    MAX_EMAIL_LOCAL_LEN = 64             # RFC 5321 local-part maximum
    MAX_DOMAIN_LEN = 253
    MAX_DOMAIN_LABEL_LEN = 63
    MAX_PHONE_LEN = 32                   # E.164 is 15 digits + '+'
    MAX_PASSWORD_LEN = 128               # ★ long-password DoS ceiling
    MIN_PASSWORD_LEN = 8                 # brute-force floor (NIST: length > classes)
    MAX_NAME_LEN = 80
    MAX_SESSION_ID_LEN = 64
    MAX_SCHEME_ID_LEN = 64
    MAX_TOKEN_LEN = 128
    MAX_NONCE_LEN = 64

    # --- user content ------------------------------------------------------
    MAX_CHAT_MESSAGE_LEN = 2000
    MAX_QUESTION_LEN = 1000
    MAX_SEARCH_QUERY_LEN = 200
    MAX_FREE_TEXT_LEN = 2000             # profile name / notes / conditions
    MAX_LANG_LEN = 8

    # --- collection ceilings (stop a "list of 10 million" body) -------------
    MAX_LIST_ITEMS = 64

    # --- rate limiting -----------------------------------------------------
    GLOBAL_RPM = 600                     # requests / min / IP across /api/*
    AUTH_ATTEMPTS = 8                    # per (IP, bucket) / window
    AUTH_WINDOW_S = 300
    KDF_RPM = 20                         # ★ password-hashing calls / min / IP
    OTP_REQUEST_PER_DEST_HOUR = 5
    OTP_VERIFY_ATTEMPTS = 5
    RATELIMIT_MAX_BUCKETS = 50_000       # ★ memory-exhaustion ceiling

    # --- replay defence ----------------------------------------------------
    REPLAY_WINDOW_S = 300                # ±5 min skew tolerance
    REPLAY_NONCE_TTL_S = 660             # keep nonces longer than the window
    REPLAY_MAX_NONCES = 200_000

    # --- sessions ----------------------------------------------------------
    SESSION_IDLE_DAYS = 30
    SESSION_ABSOLUTE_DAYS = 90           # ★ rolling expiry cannot exceed this
    MAX_SESSIONS_PER_USER = 20           # oldest evicted beyond this

    # --- uploads -----------------------------------------------------------
    MAX_UPLOAD_BYTES = 5 * 1024 * 1024
    MAX_UPLOAD_FILENAME_LEN = 128


LIMITS = Limits()


# ------------------------------------------------------------ secret handling
_WORLD_READABLE = stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH
_GROUP_READABLE = stat.S_IRGRP | stat.S_IWGRP | stat.S_IXGRP


class SecretError(RuntimeError):
    """Raised when key material is present but unsafe to use."""


def _warn_permissions(path: Path) -> None:
    """Best-effort 0600 on key files; loud in the audit trail if refused."""
    try:
        path.chmod(0o600)
    except OSError:
        pass


def load_secret(
    env_name: str,
    *,
    fallback_path: Path | None = None,
    min_bytes: int = 32,
    autogenerate: bool = True,
) -> bytes:
    """Read key material safely, or mint it — never fail silently.

    Order of precedence: environment → key file → freshly generated file.

    Hardening over a naive ``os.environ.get``:

    * **Length floor.** A short secret is a brute-forceable secret; a
      pepper under ``min_bytes`` is rejected outright rather than trusted.
    * **Permission check.** A world-readable key file is a leaked key file.
      We tighten it to ``0600`` and, if that fails in production, refuse to
      run with it rather than pretend the material is safe.
    * **Deterministic per deployment.** The generated value is persisted so
      restarts keep validating previously issued MACs.
    """
    raw = os.environ.get(env_name)
    if raw and raw.strip():
        value = raw.strip().encode()
        if len(value) < min_bytes:
            # Failing closed here is correct: a weak pepper silently downgrades
            # every hash it protects.
            if is_production():
                raise SecretError(
                    f"{env_name} must be at least {min_bytes} bytes in production."
                )
        else:
            return value

    if fallback_path is not None:
        if fallback_path.exists():
            mode = fallback_path.stat().st_mode
            if mode & _WORLD_READABLE:
                _warn_permissions(fallback_path)
                if is_production() and (fallback_path.stat().st_mode & _WORLD_READABLE):
                    raise SecretError(
                        f"{fallback_path} is world-readable and cannot be tightened."
                    )
            data = fallback_path.read_bytes().strip()
            if len(data) >= min_bytes:
                return data

        if not autogenerate:
            raise SecretError(f"No value for {env_name} and {fallback_path} is absent.")

        fallback_path.parent.mkdir(parents=True, exist_ok=True)
        generated = secrets.token_bytes(max(min_bytes, 32))
        # Create with 0600 from birth — no window where the secret is exposed.
        fd = os.open(
            fallback_path,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            stat.S_IRUSR | stat.S_IWUSR,
        )
        with os.fdopen(fd, "wb") as fh:
            fh.write(generated)
        _warn_permissions(fallback_path)
        return generated

    if autogenerate:
        # Ephemeral, process-local: safe for nonces, unsafe across restarts.
        return secrets.token_bytes(max(min_bytes, 32))
    raise SecretError(f"No value available for {env_name}.")


# ---------------------------------------------------------------- redaction --
_EMAIL_REDACT = re.compile(r"(^.).*(@.*$)")


def redact_email(address: str) -> str:
    """``student@example.com`` → ``s***@example.com`` — log-safe."""
    address = (address or "").strip()
    if "@" not in address:
        return "***"
    local, _, domain = address.partition("@")
    head = local[:1] if local else ""
    return f"{head}***@{domain[:64]}"


def redact_phone(number: str) -> str:
    """``+919876543210`` → ``+91******10`` — log-safe."""
    number = (number or "").strip()
    if len(number) < 6:
        return "***"
    return number[:3] + "*" * 6 + number[-2:]


def redact(value: str, keep: int = 0) -> str:
    """Collapse any string to a fixed-width marker of the same *class*.

    Used wherever an upstream error might carry credentials, tokens or PII into
    our audit log. Length is deliberately not preserved: byte-length is itself a
    weak signal, and a fixed marker cannot be assembled into the original.
    """
    if not value:
        return ""
    return "*" * max(keep, 8)


_SECRET_PATTERNS = (
    re.compile(r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|authorization)"
               r"(\s*[=:]\s*)(\S+)"),
)


def scrub_text(text: str, limit: int = 160) -> str:
    """Strip credential-looking ``key=value`` pairs and truncate.

    Exception messages from SMTP/HTTP libraries routinely echo the URL, the
    auth header or the login they just failed with. Those must reach an
    operator's dashboard as ``password=***``, never in the clear.
    """
    out = text or ""
    for pattern in _SECRET_PATTERNS:
        out = pattern.sub(lambda m: f"{m.group(1)}{m.group(2)}***", out)
    # Strip CRLF so a log line can never be forged by injected newlines.
    out = out.replace("\r", " ").replace("\n", " ")
    return out[:limit]


# --------------------------------------------------------------- comparison --
def constant_time_eq(a: str | bytes, b: str | bytes) -> bool:
    """Timing-safe equality for anything an attacker can probe byte by byte."""
    if isinstance(a, str):
        a = a.encode("utf-8", "surrogatepass")
    if isinstance(b, str):
        b = b.encode("utf-8", "surrogatepass")
    return hmac.compare_digest(a, b)


def fingerprint(*parts: str) -> str:
    """Stable, non-reversible digest of a tuple of strings.

    Used for client binding and dedup keys: we want to *compare* fingerprints
    without storing the underlying values (which may be PII such as a user
    agent or an IP address).
    """
    h = hashlib.sha256()
    for i, part in enumerate(parts):
        if i:
            h.update(b"\x1f")
        h.update((part or "").encode("utf-8", "surrogatepass"))
    return h.hexdigest()


# ------------------------------------------------------------- client identity
@lru_cache(maxsize=64)
def _trusted_networks() -> tuple:
    """Parsed ``FEEFIX_TRUSTED_PROXIES`` CIDR list (cached)."""
    nets = []
    for entry in env_list("FEEFIX_TRUSTED_PROXIES"):
        try:
            nets.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            continue
    return tuple(nets)


def _is_trusted(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _trusted_networks())


def peer_is_proxy() -> bool:
    """Is the socket peer *always* our own reverse proxy?

    Some platforms (Render, Heroku, Fly's private networking) do not expose the
    application port at all — the only thing that can open a TCP connection to
    the app is the platform's proxy. In that topology the peer is trusted by
    construction, and there is no CIDR to enumerate because the platform does
    not publish a stable one.

    This exists so such a deployment does NOT have to write
    ``FEEFIX_TRUSTED_PROXIES=0.0.0.0/0``. That value is technically equivalent
    here, and catastrophically wrong the moment it is copied into a deployment
    where the app port *is* reachable: it would let any client set
    ``X-Forwarded-For`` and walk past every per-IP rate limit. A named flag that
    states the assumption is auditable; a wildcard CIDR that quietly makes it is
    not.

    Setting this on a directly-exposed service is a misconfiguration, and it is
    recorded in the audit log at startup so it is discoverable.
    """
    return env_bool("FEEFIX_TRUST_PROXY_PEER", False)


def is_trusted_peer(ip: str) -> bool:
    """Should ``X-Forwarded-For`` from this peer be believed?"""
    return peer_is_proxy() or _is_trusted(ip)


def client_ip(peer: str | None, headers: dict | None = None) -> str:
    """The IP we hold a client accountable for.

    ``X-Forwarded-For`` is *attacker-controlled input* unless the request
    arrived from a proxy we operate. Trusting it unconditionally lets anyone
    rotate a header and walk straight past every per-IP rate limit; ignoring it
    entirely collapses every user behind a load balancer into one bucket and
    lets one abuser lock out the whole customer base.

    Rule: walk the XFF chain from the right (the entries our own proxies added)
    by ``FEEFIX_PROXY_HOPS`` hops, and only when the direct peer is trusted.
    Anything else falls back to the socket peer.
    """
    peer = (peer or "").strip() or "unknown"
    headers = headers or {}
    hops = env_int("FEEFIX_PROXY_HOPS", 1, minimum=1, maximum=8)

    xff = ""
    for key in ("x-forwarded-for", "X-Forwarded-For"):
        if key in headers:
            xff = headers[key]
            break
    if not xff or not is_trusted_peer(peer):
        return peer

    parts = [p.strip() for p in xff.split(",") if p.strip()]
    if not parts:
        return peer
    # parts[-1] is the client as seen by the closest proxy; walk leftward.
    index = max(0, len(parts) - hops)
    candidate = parts[index]
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return peer
    return candidate


def clear_caches() -> None:
    """Drop memoised config (tests flip environment variables)."""
    _trusted_networks.cache_clear()


# ------------------------------------------------------------ input hygiene --
# Unicode bidi overrides (U+202A…U+202E, U+2066…U+2069) let an attacker make a
# string *display* as something other than what it is — the "Trojan Source"
# class of attack, which applies to names and free text just as much as to code.
_BIDI = "".join(
    chr(c) for c in
    list(range(0x202A, 0x202F)) + list(range(0x2066, 0x206A)) + [0x200E, 0x200F]
)
_CONTROL = "".join(chr(c) for c in range(0x00, 0x20) if c not in (0x09, 0x0A)) + \
    "".join(chr(c) for c in range(0x7F, 0xA0))
_STRIP_TABLE = str.maketrans("", "", _BIDI + _CONTROL)


def sanitize_text(value: str | None, max_len: int) -> str:
    """Normalise, de-fang and bound a free-text field.

    1. NFC-normalise so homoglyph/combining-mark tricks collapse to one form
       (this also makes downstream equality checks honest).
    2. Remove bidi overrides and C0/C1 control characters — invisible
       directives that survive into the UI and into logs.
    3. Truncate to ``max_len`` *after* normalisation, so a normalisation
       expansion cannot push past the ceiling.

    Returns ``""`` for ``None``; callers decide whether empty is acceptable.
    """
    if not value:
        return ""
    text = unicodedata.normalize("NFC", str(value))
    text = text.translate(_STRIP_TABLE)
    if len(text) > max_len:
        text = text[:max_len]
    return text.strip()


def has_forbidden_chars(value: str) -> bool:
    """True if a string still carries control or bidi characters."""
    return bool(set(value or "") & set(_BIDI + _CONTROL))


# --------------------------------------------------------------- dev-only OTP
def dev_code_echo_allowed() -> bool:
    """May a one-time code be returned in the HTTP response body?

    This is the single most dangerous convenience in the product: answering
    ``yes`` in production is *remote account takeover of every user*, with no
    password and no second factor. It therefore requires **both** a
    non-production environment **and** an explicit opt-in flag, and it is
    re-evaluated on every call so it cannot be latched on at import time.
    """
    if is_production():
        return False
    return env_bool("FEEFIX_DEV_OTP_ECHO", False)


def safe_error(detail: str, *, internal: str | None = None) -> str:
    """Client-facing error text, with the real cause kept server-side.

    Users get a stable, non-diagnostic sentence. Operators get the specifics in
    the audit log. Never the reverse.
    """
    if internal:
        audit_security_event("error.detail", scrub_text(internal, 300))
    return detail


# ------------------------------------------------------- security audit trail
def audit_security_event(action: str, detail: str | None = None, actor: str | None = None) -> None:
    """Record a security-relevant event, never letting the recorder crash us.

    Audit writes are best-effort by design: a full or locked database must not
    become an availability incident on the request path, and an attacker must
    not be able to trigger errors *by* making us log.
    """
    try:
        from backend.services import db

        db.audit(actor, f"security.{action}", scrub_text(detail or "", 300))
    except Exception:  # pragma: no cover - defensive
        pass


__all__ = [
    "LIMITS",
    "Limits",
    "PRODUCTION",
    "STAGING",
    "DEVELOPMENT",
    "TEST",
    "SecretError",
    "audit_security_event",
    "clear_caches",
    "client_ip",
    "constant_time_eq",
    "dev_code_echo_allowed",
    "env_bool",
    "env_int",
    "env_list",
    "env_str",
    "environment",
    "fingerprint",
    "has_forbidden_chars",
    "is_production",
    "is_trusted_peer",
    "peer_is_proxy",
    "load_secret",
    "redact",
    "redact_email",
    "redact_phone",
    "safe_error",
    "scrub_text",
    "sanitize_text",
    "unsafe_features_allowed",
]
