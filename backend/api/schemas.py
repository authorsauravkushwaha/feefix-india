"""API request schemas (responses are assembled by the matching service).

EVERY STRING FIELD HAS A CEILING
================================
An unbounded ``str`` field in a pydantic model is an unbounded allocation and
an unbounded amount of downstream work. The two that mattered most here:

* ``password`` had no maximum. It was UTF-8 encoded, PBKDF2-hashed at 600 000
  iterations and stored — so a single request could carry a 10 MB field and the
  server would happily process it. That is the **long-password DoS**: the
  attacker pays one upload, the server pays the hashing, the memory and the
  database write. Ceiling now applied here (fast 422) *and* re-checked inside
  :func:`backend.services.auth.hash_password`, so a future internal caller
  cannot bypass the route layer.
* ``message`` on ``/api/chat`` had no maximum. Measured: a 40 MB message was
  accepted and cost ~3 s of CPU. Ceiling now 2 000 characters.

Length is validated by pydantic *before* the handler runs, which means an
oversized value is rejected before it can reach a regex, a KDF or a database —
and rejection cost is constant rather than proportional to the payload.

These models are also the enforcement point for the "no free-form value reaches
a filter" rule: enums are enums, identifiers carry a pattern, and anything that
becomes a dict key, a path segment or a SQL parameter is shape-constrained here
as well as at the service layer (defence in depth — one of the two will be
refactored eventually).
"""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from backend.models.student import StudentProfile
from backend.services.security import LIMITS

#: Identifier pattern shared by everything used as a store key or path
#: segment. Mutually-exclusive character classes, so no backtracking.
_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_-]{3,63}$"
_SLUG_PATTERN = r"^[a-z0-9][a-z0-9-]{0,63}$"


class MatchRequest(BaseModel):
    profile: StudentProfile = Field(default_factory=StudentProfile)


class ProfileUpsertRequest(BaseModel):
    profile: StudentProfile
    lang: str = Field(
        default="en",
        max_length=LIMITS.MAX_LANG_LEN,
        description="Language for generated explanations: en | bn | hi | ta",
    )

    @field_validator("lang")
    @classmethod
    def _lang_allowed(cls, value: str) -> str:
        # Whitelist rather than pattern: an unknown language falls back to
        # English instead of being passed to a template lookup.
        return value if value in ("en", "bn", "hi", "ta") else "en"


class TrackRequest(BaseModel):
    status: str | None = Field(
        default=None,
        max_length=20,
        description="saved | planning | applied | under_review | approved | rejected; null clears",
    )


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=LIMITS.MAX_CHAT_MESSAGE_LEN)
    chat_id: str | None = Field(default=None, max_length=LIMITS.MAX_SESSION_ID_LEN)


class DispatchRequest(BaseModel):
    limit: int = Field(default=10, ge=1, le=50)


class AskRequest(BaseModel):
    question: str = Field(min_length=2, max_length=LIMITS.MAX_QUESTION_LEN)
    session_id: str | None = Field(
        default=None,
        max_length=LIMITS.MAX_SESSION_ID_LEN,
        description="When given, answers are personalised with the saved profile",
    )


class EventRequest(BaseModel):
    session_id: str = Field(min_length=4, max_length=LIMITS.MAX_SESSION_ID_LEN,
                            pattern=_ID_PATTERN)
    scheme_id: str = Field(min_length=2, max_length=LIMITS.MAX_SCHEME_ID_LEN,
                           pattern=_SLUG_PATTERN)
    type: str = Field(
        max_length=20,
        description="viewed | saved | planning | applied | under_review | approved | rejected | missed | matched",
    )


class RegisterRequest(BaseModel):
    email: str = Field(min_length=3, max_length=LIMITS.MAX_EMAIL_LEN)
    #: ★ the long-password DoS ceiling — enforced before any hashing.
    password: str = Field(min_length=1, max_length=LIMITS.MAX_PASSWORD_LEN)
    name: str | None = Field(default=None, max_length=LIMITS.MAX_NAME_LEN)


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=LIMITS.MAX_EMAIL_LEN)
    #: Login needs the same ceiling as registration. An attacker does not have
    #: to own an account to make the server hash one.
    password: str = Field(min_length=1, max_length=LIMITS.MAX_PASSWORD_LEN)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=LIMITS.MAX_PASSWORD_LEN)
    new_password: str = Field(min_length=1, max_length=LIMITS.MAX_PASSWORD_LEN)


class LinkSessionRequest(BaseModel):
    session_id: str = Field(min_length=4, max_length=LIMITS.MAX_SESSION_ID_LEN,
                            pattern=_ID_PATTERN)


class OtpRequestBody(BaseModel):
    channel: str = Field(max_length=8, description="email | phone")
    #: The ceiling is generous enough for a real address and small enough that
    #: normalisation cannot be made slow.
    address: str = Field(min_length=3, max_length=LIMITS.MAX_EMAIL_LEN)

    @field_validator("channel")
    @classmethod
    def _channel_allowed(cls, value: str) -> str:
        return value if value in ("email", "phone") else ""


class OtpVerifyBody(BaseModel):
    channel: str = Field(max_length=8, description="email | phone")
    address: str = Field(min_length=3, max_length=LIMITS.MAX_EMAIL_LEN)
    #: Bounded to the code length (+2 of slack for clients that pad). Anything
    #: longer is rejected without an HMAC being computed over it.
    code: str = Field(min_length=4, max_length=8)
    name: str | None = Field(default=None, max_length=LIMITS.MAX_NAME_LEN)

    @field_validator("channel")
    @classmethod
    def _channel_allowed(cls, value: str) -> str:
        return value if value in ("email", "phone") else ""
