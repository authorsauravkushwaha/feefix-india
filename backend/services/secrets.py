"""Secret access & hygiene — secrets come from the environment, never the repo.

Design rules this module enforces:

* Secrets (SMTP password, Twilio token, GitHub client secret, the OTP pepper)
  are read **only** from environment variables at call time. No secret is ever
  hard-coded, defaulted to a real value, or written into the source tree.
* :func:`weak_secret_findings` is called at startup to report secrets that are
  missing where one is expected or set to a placeholder — catching the most
  common cause of a *secret leak*: a default that ships.

Warn → block
------------
A boot-time ``log.warning`` for ``CHANGE_ME`` was advisory: the service happily
served production traffic with a placeholder credential. :func:`enforce_secret_hygiene`
now **refuses to start** when the deployment says it is production
(``FEEFIX_ENV=production``) or opts in explicitly (``FEEFIX_SECRETS_STRICT=1``),
listing every blocking finding. Non-production environments still warn, so
local development and CI are not obstructed — the check is strict exactly where
it matters.
"""

from __future__ import annotations

import logging
import math
import os

log = logging.getLogger("feefix.secrets")

# Secrets that, if set, must look real. name → minimum acceptable length.
_EXPECTED_SECRETS = {
    "GITHUB_CLIENT_SECRET": 20,
    "OTP_SMTP_PASS": 8,
    "OTP_TWILIO_TOKEN": 20,
    "FEEFIX_OTP_PEPPER": 16,
}

_PLACEHOLDERS = {
    "", "changeme", "change-me", "change_me", "secret", "password", "test",
    "todo", "xxx", "xxxx", "your-secret-here", "none", "null", "example",
    "your_client_secret", "client_secret", "abcdef", "123456", "placeholder",
    "your_password", "passw0rd", "letmein", "admin", "root", "dummy", "sample",
}

#: Secret → the environment variable that proves the integration is half-configured.
_COMPANIONS = {
    "GITHUB_CLIENT_SECRET": "GITHUB_CLIENT_ID",
    "OTP_SMTP_PASS": "OTP_SMTP_USER",
    "OTP_TWILIO_TOKEN": "OTP_TWILIO_SID",
}

#: Secrets whose *absence* blocks a strict boot when their integration is on.
_DELIVERY_SECRETS = ("OTP_SMTP_PASS", "OTP_TWILIO_TOKEN")
_OTP_CHANNEL_HINTS = (
    "OTP_SMTP_HOST",
    "OTP_SMTP_USER",
    "OTP_TWILIO_SID",
    "OTP_TWILIO_FROM",
    "OTP_TWILIO_ACCOUNT_SID",
)

_LOW_ENTROPY_BITS_PER_CHAR = 2.5


class SecretHygieneError(RuntimeError):
    """Raised at boot when a strict deployment has a placeholder/missing secret."""


def strict_mode() -> bool:
    """Whether secret findings block startup.

    ``FEEFIX_SECRETS_STRICT`` wins when set; otherwise production implies strict.
    """
    raw = os.environ.get("FEEFIX_SECRETS_STRICT")
    if raw is not None and raw.strip():
        return raw.strip().lower() in ("1", "true", "yes", "on")
    return (os.environ.get("FEEFIX_ENV") or "").strip().lower() in ("prod", "production")


def get_secret(name: str, *, required: bool = False, default: str | None = None) -> str | None:
    """Read a secret from the environment. No insecure fallback is ever invented."""
    value = os.environ.get(name)
    if value:
        return value
    if required:
        raise RuntimeError(f"Required secret {name} is not set in the environment.")
    return default


def _entropy_bits_per_char(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def _weak_reasons(value: str, min_len: int) -> list[str]:
    """Why a value looks wrong — empty list means "plausible secret"."""
    v = (value or "").strip()
    if v.lower() in _PLACEHOLDERS:
        return ["placeholder value"]
    reasons: list[str] = []
    if len(v) < min_len:
        reasons.append(f"shorter than {min_len} characters")
    entropy = _entropy_bits_per_char(v)
    if entropy < _LOW_ENTROPY_BITS_PER_CHAR:
        reasons.append(f"low entropy ({entropy:.2f} bits/char)")
    return reasons


def _looks_weak(value: str, min_len: int) -> bool:
    return bool(_weak_reasons(value, min_len))


def _otp_delivery_configured() -> bool:
    return any(os.environ.get(name) for name in _OTP_CHANNEL_HINTS)


def assess_secrets() -> list[dict]:
    """Structured findings: ``{level, name, message}`` with level in blocking|warning."""
    findings: list[dict] = []
    for name, min_len in _EXPECTED_SECRETS.items():
        value = os.environ.get(name)
        if value is None:
            # Absent is fine for optional integrations; flag when a partial
            # config implies it should be present (its companion id is set).
            companion = _COMPANIONS.get(name)
            if companion and os.environ.get(companion):
                findings.append(
                    {
                        "level": "blocking",
                        "name": name,
                        "message": f"{name} is unset but {companion} is configured.",
                    }
                )
            elif name == "FEEFIX_OTP_PEPPER" and _otp_delivery_configured():
                findings.append(
                    {
                        "level": "blocking",
                        "name": name,
                        "message": (
                            "FEEFIX_OTP_PEPPER is unset while an OTP delivery channel is"
                            " configured — a per-process pepper generated on disk breaks"
                            " code verification across instances/restarts."
                        ),
                    }
                )
            continue
        reasons = _weak_reasons(value, min_len)
        if reasons:
            findings.append(
                {
                    "level": "blocking",
                    "name": name,
                    "message": (
                        f"{name} looks like a placeholder/weak value ({'; '.join(reasons)})"
                        " — rotate it."
                    ),
                }
            )
    if not findings:
        return findings
    # Any finding is a warning in non-strict environments; the same finding is
    # blocking once the deployment declares itself production.
    if not strict_mode():
        for finding in findings:
            finding["level"] = "warning"
    return findings


def weak_secret_findings() -> list[str]:
    """Human-readable warnings about missing/placeholder secrets (log at boot)."""
    return [f["message"] for f in assess_secrets()]


def enforce_secret_hygiene() -> list[str]:
    """Assess secrets at boot; raise in strict mode, warn otherwise.

    Returns the (possibly empty) list of findings when it does not raise, so the
    caller can log them.
    """
    findings = assess_secrets()
    blocking = [f for f in findings if f["level"] == "blocking"]
    if blocking and strict_mode():
        detail = "\n  - ".join(f["message"] for f in blocking)
        raise SecretHygieneError(
            "Refusing to start: secret hygiene failed in strict mode "
            f"(FEEFIX_ENV={os.environ.get('FEEFIX_ENV', 'unset')}).\n  - {detail}\n"
            "Fix the secrets, or set FEEFIX_SECRETS_STRICT=0 to downgrade to a warning."
        )
    return [f["message"] for f in findings]
