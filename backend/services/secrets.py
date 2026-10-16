"""Secret access, hygiene and *enforcement*.

Secrets (SMTP password, Twilio token, GitHub client secret, the OTP pepper) are
read **only from environment variables** at call time. No secret is ever
hard-coded, defaulted to a real value, or written into the source tree.

The previous version of this module could only ``log.warning`` about a
placeholder secret, which means a production deploy still running
``GITHUB_CLIENT_SECRET=changeme`` booted happily — an advisory control that
nobody reads is not a control. It now has teeth:

* :func:`strict_mode` is on when ``FEEFIX_STRICT_SECRETS=1`` **or** the
  deployment looks like production (``FEEFIX_ENV=production``, ``RENDER=true``,
  ``FLY_APP_NAME`` set, ``K_SERVICE`` set — the platform-provided env vars).
* :func:`enforce_secret_policy` **raises** in strict mode, so the process never
  reaches "serving traffic with a placeholder credential"; in development it
  still warns loudly and keeps going.
* A secret is only *required* when its companion is configured (``GITHUB_CLIENT_ID``
  without ``GITHUB_CLIENT_SECRET`` is a broken half-config) or when the operator
  declares it explicitly via ``FEEFIX_REQUIRED_SECRETS=A,B`` — so an unused
  integration can't block a deploy.
* :func:`secret_status` exposes presence/quality (never values) for
  ``/api/health``, and :func:`rotation_id` fingerprints *which* secret a running
  process loaded so key rotation is observable.
"""

from __future__ import annotations

import hashlib
import logging
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
    "", "changeme", "change-me", "change_me", "changeit", "secret", "password",
    "test", "todo", "xxx", "xxxx", "your-secret-here", "none", "null", "example",
    "your_client_secret", "client_secret", "abcdef", "123456", "placeholder",
    "your_api_key", "apikey", "sample", "dummy", "insecure", "default",
}
_PLACEHOLDER_HINTS = ("changeme", "change-me", "placeholder", "your-", "your_", "example", "todo", "xxxx")
_PROD_MARKERS = ("FEEFIX_ENV", "RENDER", "FLY_APP_NAME", "K_SERVICE", "HEROKU_APP_NAME")


def get_secret(name: str, *, required: bool = False, default: str | None = None) -> str | None:
    """Read a secret from the environment. No insecure fallback is ever invented."""
    value = os.environ.get(name)
    if value:
        return value
    if required:
        raise RuntimeError(f"Required secret {name} is not set in the environment.")
    return default


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def _is_production() -> bool:
    env = os.environ.get("FEEFIX_ENV", "").strip().lower()
    if env in ("production", "prod"):
        return True
    for marker in _PROD_MARKERS[1:]:  # platform-provided vars
        value = os.environ.get(marker, "").strip().lower()
        if value and value not in ("false", "0", "none", ""):
            return True
    return False


def strict_mode() -> bool:
    """Should a bad secret configuration stop the process?"""
    if os.environ.get("FEEFIX_STRICT_SECRETS", "").strip():
        return _env_flag("FEEFIX_STRICT_SECRETS")
    return _is_production()


def _looks_weak(value: str, min_len: int) -> bool:
    v = (value or "").strip()
    low = v.lower()
    if low in _PLACEHOLDERS:
        return True
    if len(v) < min_len:
        return True
    if any(hint in low for hint in _PLACEHOLDER_HINTS):
        return True
    # A secret made of one repeated character or a trivial sequence is not one.
    if len(set(v)) < 6:
        return True
    if low in {"1234567890", "0123456789", "qwertyuiop", "abcdefghij"}:
        return True
    return False


def _companion(name: str) -> str:
    return name.replace("_SECRET", "_CLIENT_ID").replace("_TOKEN", "_SID")


def _explicitly_required() -> set[str]:
    raw = os.environ.get("FEEFIX_REQUIRED_SECRETS", "")
    return {part.strip() for part in raw.split(",") if part.strip()}


def weak_secret_findings() -> list[str]:
    """Human-readable problems with the configured secrets (never the values)."""
    findings: list[str] = []
    required_extra = _explicitly_required()
    for name, min_len in _EXPECTED_SECRETS.items():
        value = os.environ.get(name)
        if value is None:
            companion = _companion(name)
            if name in required_extra:
                findings.append(f"{name} is required (FEEFIX_REQUIRED_SECRETS) but unset.")
            elif companion and os.environ.get(companion):
                findings.append(f"{name} is unset but {companion} is configured.")
            continue
        if _looks_weak(value, min_len):
            findings.append(f"{name} looks like a placeholder/weak value — rotate it.")
    for name in sorted(required_extra - set(_EXPECTED_SECRETS)):
        if not os.environ.get(name):
            findings.append(f"{name} is required (FEEFIX_REQUIRED_SECRETS) but unset.")
    return findings


def enforce_secret_policy() -> list[str]:
    """Apply the secret policy at boot: raise in strict mode, warn otherwise.

    Called from ``create_app``. In strict mode a finding is fatal *by design*: a
    deployment that would serve traffic with a placeholder credential should not
    come up at all.
    """
    findings = weak_secret_findings()
    if not findings:
        return findings
    if strict_mode():
        raise RuntimeError(
            "Refusing to start: secret policy violations in strict mode "
            f"({'; '.join(findings)}). Fix the environment or set "
            "FEEFIX_STRICT_SECRETS=0 for a non-production run."
        )
    for finding in findings:
        log.warning("[secrets] %s", finding)
    return findings


def secret_status() -> dict:
    """Presence/quality per secret — names and states only, never values."""
    status: dict[str, str] = {}
    required_extra = _explicitly_required()
    for name, min_len in _EXPECTED_SECRETS.items():
        value = os.environ.get(name)
        if value is None:
            status[name] = "required-missing" if name in required_extra else "unset"
        elif _looks_weak(value, min_len):
            status[name] = "weak"
        else:
            status[name] = "set"
    return {
        "strict": strict_mode(),
        "production_like": _is_production(),
        "secrets": status,
        "findings": len(weak_secret_findings()),
    }


def rotation_id(name: str) -> str | None:
    """Short fingerprint of the loaded value, so key rotation is observable.

    Not a secret: a truncated SHA-256 of the value cannot be used to recover it,
    but it changes the moment the credential is rotated — which is exactly the
    signal an incident response needs ("did the running process pick up the new
    token?").
    """
    value = os.environ.get(name)
    if not value:
        return None
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
