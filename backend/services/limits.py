"""Centralized input-size and resource limits — the first line of defence.

Every user-supplied string is bounded *here* so that a single source of truth
governs the pydantic request schemas, the service layer and the request-body
gate. Bounding input length is what makes several classic denial-of-service
classes non-viable on FeeFix:

* **Long-password DoS** — password KDFs grow with the secret's length, so the
  password is capped (and additionally pre-hashed, see ``services/auth.py``).
* **ReDoS** — no regex ever runs over an unbounded string; inputs are clipped
  before any ``re`` engine touches them.
* **Giant-payload DoS** — every request body is capped *per endpoint*, while it
  is being read (see ``services/body_limit.py``), before a handler parses it.

Per-endpoint caps, not one blunt number
---------------------------------------
A single global body cap is wrong in both directions: too small for a real
document upload and needlessly large for a 2000-character chat turn. So caps are
per route class — chat is 64 KB, grounded Q&A 32 KB, profile writes 64 KB, the
ordinary JSON API 256 KB, and the document-upload route gets the upload budget.
Every knob is environment-tunable so a deployment can raise a limit for a real
need *without* weakening the rest of the surface::

    FEEFIX_MAX_BODY_BYTES=524288        # default cap for the JSON API
    FEEFIX_MAX_UPLOAD_BYTES=20000000    # document upload budget
    FEEFIX_MAX_MESSAGE_LEN=4000         # field caps, same idea

``body_limit_for(path)`` maps a path to its cap; ``limit_report()`` returns the
effective configuration (surfaced by ``GET /api/health`` and the API docs) so
clients and operators can see the numbers instead of guessing.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


def _int_env(name: str, default: int, *, lo: int = 1, hi: int = 1 << 40) -> int:
    """Read a positive int from the environment; ignore junk instead of crashing.

    A typo in an env var must never take the service down (availability), and an
    out-of-range value must never be able to disable a bound (security), so the
    value is clamped into ``[lo, hi]``.
    """
    raw = os.environ.get(name)
    if raw is None or not str(raw).strip():
        return default
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, value))


# -- credential / identity fields ------------------------------------------- #
MIN_PASSWORD_LEN = 8
MAX_PASSWORD_LEN = _int_env("FEEFIX_MAX_PASSWORD_LEN", 256)   # passphrase-friendly, bounds KDF work
MAX_EMAIL_LEN = 254             # RFC 5321 practical maximum
MAX_NAME_LEN = _int_env("FEEFIX_MAX_NAME_LEN", 100)
MAX_ADDRESS_LEN = 320           # email or E.164 phone destination

# -- free-text fields -------------------------------------------------------- #
MAX_MESSAGE_LEN = _int_env("FEEFIX_MAX_MESSAGE_LEN", 2000)    # chat turn
MAX_QUESTION_LEN = _int_env("FEEFIX_MAX_QUESTION_LEN", 1000)   # grounded Q&A question
MAX_SEARCH_LEN = _int_env("FEEFIX_MAX_SEARCH_LEN", 200)        # semantic / keyword search query

# -- identifiers ------------------------------------------------------------- #
MAX_SESSION_ID_LEN = 64
MAX_SCHEME_ID_LEN = 64
MAX_LANG_LEN = 8
MAX_DOC_TYPE_LEN = _int_env("FEEFIX_MAX_DOC_TYPE_LEN", 32)

# -- transport --------------------------------------------------------------- #
# Default cap for the ordinary JSON API. Deliberately far below the old blunt
# 1 MB: no legitimate JSON call on this API comes close, and a small cap is what
# keeps a json-parser flood cheap to reject.
DEFAULT_MAX_BODY_BYTES = _int_env("FEEFIX_MAX_BODY_BYTES", 256_000)
# Multipart framing (boundaries, headers, part metadata) rides along with the
# file bytes, so the upload route's body cap is the file budget plus slack.
UPLOAD_BODY_OVERHEAD = _int_env("FEEFIX_UPLOAD_BODY_OVERHEAD", 64_000)


def _body_limit_for(path: str) -> int:
    """Per-route body cap. Longest-prefix wins; unknown paths get the default."""
    if path.startswith("/api/students/") and path.rstrip("/").endswith("/documents"):
        return MAX_UPLOAD_BYTES + UPLOAD_BODY_OVERHEAD
    if path.startswith("/api/chat"):
        # A MAX_MESSAGE_LEN-char message in JSON (escapes, surrogate pairs) stays
        # comfortably inside this.
        return _int_env("FEEFIX_MAX_CHAT_BODY_BYTES", 64_000)
    if path.startswith("/api/ask"):
        return _int_env("FEEFIX_MAX_ASK_BODY_BYTES", 32_000)
    if path.startswith("/api/auth/"):
        return _int_env("FEEFIX_MAX_AUTH_BODY_BYTES", 8_000)
    if path.startswith("/api/match") or path.startswith("/api/students/") or path.startswith("/api/tracker/"):
        return _int_env("FEEFIX_MAX_PROFILE_BODY_BYTES", 64_000)
    return DEFAULT_MAX_BODY_BYTES


@dataclass(frozen=True)
class BodyLimit:
    """The cap that applies to a request path, with its source for the log line."""

    max_bytes: int
    scope: str


def body_limit_for(path: str) -> BodyLimit:
    """Resolve the body cap for ``path`` (used by the ASGI body-limit gate)."""
    path = path or "/"
    scope = "default"
    if path.startswith("/api/students/") and path.rstrip("/").endswith("/documents"):
        scope = "upload"
    elif path.startswith("/api/chat"):
        scope = "chat"
    elif path.startswith("/api/ask"):
        scope = "ask"
    elif path.startswith("/api/auth/"):
        scope = "auth"
    elif path.startswith(("/api/match", "/api/students/", "/api/tracker/")):
        scope = "profile"
    return BodyLimit(max_bytes=_body_limit_for(path), scope=scope)


# -- uploads (see services/upload.py) --------------------------------------- #
MAX_UPLOAD_BYTES = _int_env("FEEFIX_MAX_UPLOAD_BYTES", 8_000_000)   # 8 MB per document
UPLOAD_ALLOWED_EXTS = frozenset({".pdf", ".png", ".jpg", ".jpeg"})
# Uploads land outside the web root (never served statically, never executable).
UPLOAD_DIR = os.environ.get("FEEFIX_UPLOAD_DIR", "") or "runtime/uploads"


def limit_report() -> dict:
    """Effective limits — surfaced by /api/health so clients can adapt, not guess."""
    return {
        "body": {
            "default": DEFAULT_MAX_BODY_BYTES,
            "chat": _body_limit_for("/api/chat"),
            "ask": _body_limit_for("/api/ask"),
            "auth": _body_limit_for("/api/auth/login"),
            "profile": _body_limit_for("/api/students/x/profile"),
            "upload": _body_limit_for("/api/students/x/documents"),
        },
        "fields": {
            "password": {"min": MIN_PASSWORD_LEN, "max": MAX_PASSWORD_LEN},
            "email": MAX_EMAIL_LEN,
            "message": MAX_MESSAGE_LEN,
            "question": MAX_QUESTION_LEN,
            "search": MAX_SEARCH_LEN,
            "name": MAX_NAME_LEN,
            "address": MAX_ADDRESS_LEN,
        },
        "upload": {"max_bytes": MAX_UPLOAD_BYTES, "extensions": sorted(UPLOAD_ALLOWED_EXTS)},
    }
