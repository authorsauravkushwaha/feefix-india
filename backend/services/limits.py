"""Centralized input-size and resource limits — the first line of defence.

Every user-supplied string is bounded *here* so that a single constant governs
both the pydantic request schemas and the service layer. Bounding input length
is what makes several classic denial-of-service classes non-viable on FeeFix:

* **Long-password DoS** — the KDF cost grows with the secret's length, so the
  password is capped (and additionally pre-hashed, see ``services/passwords.py``).
* **ReDoS** — no regex ever runs over an unbounded string; inputs are clipped
  before any ``re`` engine touches them.
* **Giant-payload DoS** — request bodies are bounded *per endpoint* and the cap
  is enforced **while the body streams in** (see ``services/request_limits.py``),
  not merely by trusting ``Content-Length``.

Blunt-cap → policy-cap
----------------------
A single global 1 MB cap is hostile to legitimate large inputs (a document
upload, a long notes field) while being far too generous for a 2000-character
chat turn. Limits here are therefore:

1. **Per endpoint** — ``BODY_POLICIES`` maps a request (method, path) to the
   smallest cap that endpoint can legitimately need. A 4 MB certificate upload
   and a 64 KB chat turn get the numbers they actually deserve.
2. **Environment-tunable** — every number can be raised/lowered per deployment
   (``FEEFIX_MAX_*``) without touching code, so an operator can size limits for
   *their* traffic instead of inheriting ours.
3. **Still hard-bounded** — every policy is clamped to ``ABSOLUTE_MAX_BODY_BYTES``
   so no configuration mistake (or hostile env) can remove the outer cap.

The same rules apply to *field* length caps, which are env-tunable too.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from functools import lru_cache


def _env_int(name: str, default: int, *, minimum: int = 1, maximum: int | None = None) -> int:
    """Read an int from the environment, ignoring junk rather than crashing.

    A malformed override must never take the service down, and must never
    silently *weaken* a limit: invalid values fall back to the safe default.
    """
    raw = os.environ.get(name)
    if raw is None or not str(raw).strip():
        return default
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return default
    if value < minimum:
        return default
    if maximum is not None:
        value = min(value, maximum)
    return value


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


# -- credential / identity fields ------------------------------------------- #
MIN_PASSWORD_LEN = _env_int("FEEFIX_MIN_PASSWORD_LEN", 8, minimum=8, maximum=64)
MAX_PASSWORD_LEN = _env_int("FEEFIX_MAX_PASSWORD_LEN", 256, minimum=64, maximum=4096)
MAX_EMAIL_LEN = _env_int("FEEFIX_MAX_EMAIL_LEN", 254, minimum=32, maximum=512)
MAX_NAME_LEN = _env_int("FEEFIX_MAX_NAME_LEN", 100, minimum=8, maximum=400)
MAX_ADDRESS_LEN = _env_int("FEEFIX_MAX_ADDRESS_LEN", 320, minimum=32, maximum=1024)

# -- free-text fields -------------------------------------------------------- #
# Sized for real student input (a long question, a long chat turn) and tunable
# per deployment: a BPO/counsellor deployment can raise MAX_MESSAGE_LEN without
# a code change, an API-only deployment can lower it.
MAX_MESSAGE_LEN = _env_int("FEEFIX_MAX_MESSAGE_LEN", 2000, minimum=200, maximum=20_000)
MAX_QUESTION_LEN = _env_int("FEEFIX_MAX_QUESTION_LEN", 1000, minimum=100, maximum=10_000)
MAX_SEARCH_LEN = _env_int("FEEFIX_MAX_SEARCH_LEN", 200, minimum=32, maximum=2_000)
MAX_NOTES_LEN = _env_int("FEEFIX_MAX_NOTES_LEN", 64_000, minimum=500, maximum=200_000)

# -- identifiers ------------------------------------------------------------- #
MAX_SESSION_ID_LEN = _env_int("FEEFIX_MAX_SESSION_ID_LEN", 64, minimum=16, maximum=256)
MAX_SCHEME_ID_LEN = _env_int("FEEFIX_MAX_SCHEME_ID_LEN", 64, minimum=16, maximum=256)
MAX_LANG_LEN = _env_int("FEEFIX_MAX_LANG_LEN", 8, minimum=2, maximum=32)

# -- uploads (see services/upload.py and services/uploads.py) ---------------- #
# A phone photo of a marksheet or income certificate is commonly 4–8 MB.
# 2 MB rejected real documents; 8 MB fits under the 16 MB absolute ceiling.
MAX_UPLOAD_BYTES = _env_int("FEEFIX_MAX_UPLOAD_BYTES", 8_000_000, minimum=1024)
MAX_UPLOAD_FILES_PER_SESSION = _env_int("FEEFIX_MAX_UPLOAD_FILES", 20, minimum=1, maximum=500)
MAX_UPLOAD_TOTAL_BYTES_PER_SESSION = _env_int(
    "FEEFIX_MAX_UPLOAD_TOTAL_BYTES", 40_000_000, minimum=1024
)
UPLOAD_ALLOWED_EXTS = frozenset({".pdf", ".png", ".jpg", ".jpeg"})

# -- transport --------------------------------------------------------------- #
# Outer bound that no per-endpoint policy (and no env override) may exceed.
ABSOLUTE_MAX_BODY_BYTES = _env_int(
    "FEEFIX_ABSOLUTE_MAX_BODY_BYTES", 16_000_000, minimum=64_000
)
# Headroom for multipart envelope/boundary overhead around a file payload.
MULTIPART_OVERHEAD_BYTES = 64_000


@dataclass(frozen=True)
class BodyPolicy:
    """A request-body cap that applies to one class of endpoint."""

    name: str
    pattern: re.Pattern[str]
    max_bytes: int
    rationale: str

    def matches(self, method: str, path: str) -> bool:
        return bool(self.pattern.match(path))


def _policy(
    name: str, regex: str, default_bytes: int, env: str, rationale: str, *, minimum: int = 1024
) -> BodyPolicy:
    size = _env_int(env, default_bytes, minimum=minimum, maximum=ABSOLUTE_MAX_BODY_BYTES)
    return BodyPolicy(name=name, pattern=re.compile(regex), max_bytes=size, rationale=rationale)


# Ordered: the FIRST matching policy wins, so put the most specific first.
BODY_POLICIES: tuple[BodyPolicy, ...] = (
    _policy(
        "upload",
        r"^/api/uploads(/|$)",
        MAX_UPLOAD_BYTES + MULTIPART_OVERHEAD_BYTES,
        "FEEFIX_MAX_BODY_UPLOAD_BYTES",
        "multipart envelope around a file capped at MAX_UPLOAD_BYTES",
    ),
    _policy(
        "profile",
        r"^/api/students/[^/]+/profile$",
        256_000,
        "FEEFIX_MAX_BODY_PROFILE_BYTES",
        "profile JSON (free-text notes live here) — generous, not unlimited",
    ),
    _policy(
        "notes",
        r"^/api/students/[^/]+/notes$",
        MAX_NOTES_LEN + 8_000,
        "FEEFIX_MAX_BODY_NOTES_BYTES",
        "long-form notes field plus JSON envelope",
    ),
    _policy(
        "bulk",
        r"^/api/tracker/[^/]+/bulk$",
        512_000,
        "FEEFIX_MAX_BODY_BULK_BYTES",
        "a batch of tracker updates — not held to a single-status cap, not a document",
    ),
    _policy(
        "tracker",
        r"^/api/tracker/",
        16_000,
        "FEEFIX_MAX_BODY_TRACKER_BYTES",
        "one status update is a few hundred bytes",
    ),
    _policy(
        "dispatch",
        r"^/api/students/[^/]+/reminders/dispatch$",
        8_000,
        "FEEFIX_MAX_BODY_DISPATCH_BYTES",
        "a small dispatch request",
    ),
    _policy(
        "conversation",
        r"^/api/(ask|chat|match)$",
        64_000,
        "FEEFIX_MAX_BODY_CONVERSATION_BYTES",
        "bounded free-text turn — nothing legitimate approaches 64 KB",
    ),
    _policy(
        "events",
        r"^/api/events$",
        32_000,
        "FEEFIX_MAX_BODY_EVENTS_BYTES",
        "small structured telemetry payload",
    ),
    _policy(
        "auth",
        r"^/api/auth/",
        16_000,
        "FEEFIX_MAX_BODY_AUTH_BYTES",
        "credentials and codes are tiny; the KDF must never see a large body",
    ),
    _policy(
        "api-default",
        r"^/api/",
        _env_int("FEEFIX_MAX_BODY_BYTES", 1_000_000, minimum=16_000,
                 maximum=ABSOLUTE_MAX_BODY_BYTES),
        "FEEFIX_MAX_BODY_BYTES",
        "catch-all for JSON API traffic",
    ),
    _policy(
        "static-default",
        r"^/",
        _env_int("FEEFIX_MAX_BODY_BYTES", 1_000_000, minimum=16_000,
                 maximum=ABSOLUTE_MAX_BODY_BYTES),
        "FEEFIX_MAX_BODY_BYTES",
        "non-API paths (static assets never POST, but stay bounded)",
    ),
)

# Back-compat: the historical single global cap, still exported and still the
# value used by the catch-all policy above.
MAX_BODY_BYTES = _env_int(
    "FEEFIX_MAX_BODY_BYTES", 1_000_000, minimum=16_000, maximum=ABSOLUTE_MAX_BODY_BYTES
)


def body_limit_for(method: str, path: str) -> BodyPolicy:
    """The body policy governing ``method path`` (always returns *some* policy)."""
    for policy in BODY_POLICIES:
        if policy.matches(method, path):
            return policy
    return BODY_POLICIES[-1]


@lru_cache(maxsize=256)
def _cached_body_limit(method: str, path: str) -> tuple[str, int]:
    policy = body_limit_for(method, path)
    return policy.name, policy.max_bytes


def body_limit_bytes(method: str, path: str) -> int:
    """Cheap, cached lookup used by request middleware."""
    return _cached_body_limit(method, path)[1]


#: Methods that may legally carry a request body.
BODY_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def describe_limits() -> list[dict]:
    """Machine-readable limit table — served at ``/api/meta`` and in docs."""
    return [
        {
            "name": p.name,
            "match": p.pattern.pattern,
            "max_bytes": p.max_bytes,
            "rationale": p.rationale,
        }
        for p in BODY_POLICIES
    ]


def reset_cache() -> None:  # tests
    _cached_body_limit.cache_clear()
