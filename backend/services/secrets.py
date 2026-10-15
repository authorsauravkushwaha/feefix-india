"""Secret access & hygiene — secrets come from the environment, never the repo.

Design rules this module enforces:

* Secrets (SMTP password, Twilio token, GitHub client secret, the OTP pepper)
  are read **only** from environment variables at call time. No secret is ever
  hard-coded, defaulted to a real value, or written into the source tree.
* :func:`weak_secret_findings` is called at startup to warn (loudly, in logs)
  when a secret is missing where one is expected or is set to a placeholder —
  catching the most common cause of a *secret leak*: a default that ships.
"""

from __future__ import annotations

import os

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
}


def get_secret(name: str, *, required: bool = False, default: str | None = None) -> str | None:
    """Read a secret from the environment. No insecure fallback is ever invented."""
    value = os.environ.get(name)
    if value:
        return value
    if required:
        raise RuntimeError(f"Required secret {name} is not set in the environment.")
    return default


def _looks_weak(value: str, min_len: int) -> bool:
    v = (value or "").strip()
    if v.lower() in _PLACEHOLDERS:
        return True
    if len(v) < min_len:
        return True
    return False


def weak_secret_findings() -> list[str]:
    """Human-readable warnings about missing/placeholder secrets (log at boot)."""
    findings: list[str] = []
    for name, min_len in _EXPECTED_SECRETS.items():
        value = os.environ.get(name)
        if value is None:
            # Absent is fine for optional integrations; only flag when a partial
            # config implies it should be present (its companion id is set).
            companion = name.replace("_SECRET", "_CLIENT_ID").replace("_TOKEN", "_SID")
            if companion and os.environ.get(companion):
                findings.append(f"{name} is unset but {companion} is configured.")
            continue
        if _looks_weak(value, min_len):
            findings.append(f"{name} looks like a placeholder/weak value — rotate it.")
    return findings
