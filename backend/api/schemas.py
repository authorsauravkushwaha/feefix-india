"""API request schemas (responses are assembled by the matching service).

Every free-text field is length-bounded (see ``services/limits.py``) so the
validation layer rejects oversized payloads *before* any regex, KDF, or parser
runs — the first line of defence against ReDoS, long-password DoS and
giant-payload floods.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import AfterValidator, BaseModel, Field

from backend.models.student import StudentProfile
from backend.services.limits import (
    MAX_ADDRESS_LEN,
    MAX_NOTES_LEN,
    MAX_EMAIL_LEN,
    MAX_MESSAGE_LEN,
    MAX_NAME_LEN,
    MAX_PASSWORD_LEN,
    MAX_SCHEME_ID_LEN,
    MAX_SEARCH_LEN,
    MAX_SESSION_ID_LEN,
    MIN_PASSWORD_LEN,
)


def _no_lone_surrogates(value: str) -> str:
    """Reject text that is not valid Unicode.

    ``json.loads`` happily produces lone surrogates (``"\ud800"``); echoing such
    a value back raised ``UnicodeEncodeError`` mid-response, i.e. a client-driven
    500. Rejecting it at the boundary turns that into an honest 422.
    Invalid *encoding* is a client error, and the client can fix it.
    """
    if any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
        raise ValueError("Text contains invalid Unicode (unpaired surrogate).")
    return value


#: Free-text field type: length-bounded elsewhere, Unicode-validated here.
SafeText = Annotated[str, AfterValidator(_no_lone_surrogates)]


class MatchRequest(BaseModel):
    profile: StudentProfile = Field(default_factory=StudentProfile)


class ProfileUpsertRequest(BaseModel):
    profile: StudentProfile
    lang: str = Field(
        default="en",
        max_length=8,
        description="Language for generated explanations: en | bn | hi | ta",
    )


class TrackRequest(BaseModel):
    status: str | None = Field(
        default=None,
        max_length=32,
        description="saved | planning | applied | under_review | approved | rejected; null clears",
    )


class ChatRequest(BaseModel):
    message: SafeText = Field(min_length=1, max_length=MAX_MESSAGE_LEN)
    chat_id: str | None = Field(default=None, max_length=MAX_SESSION_ID_LEN)


class DispatchRequest(BaseModel):
    limit: int = Field(default=10, ge=1, le=50)


class NotesRequest(BaseModel):
    notes: SafeText = Field(
        default="",
        max_length=MAX_NOTES_LEN,
        description=(
            "Long-form application notes. This field is deliberately large"
            " (see FEEFIX_MAX_NOTES_LEN) and its endpoint carries its own body"
            " policy, so a legitimate large note is not rejected by a"
            " one-size-fits-all cap."
        ),
    )


class AskRequest(BaseModel):
    question: SafeText = Field(min_length=2, max_length=1000)
    session_id: str | None = Field(
        default=None,
        max_length=MAX_SESSION_ID_LEN,
        description="When given, answers are personalised with the saved profile",
    )


class EventRequest(BaseModel):
    session_id: str = Field(max_length=MAX_SESSION_ID_LEN)
    scheme_id: str = Field(max_length=MAX_SCHEME_ID_LEN)
    type: str = Field(max_length=32, description="viewed | saved | planning | applied | under_review | approved | rejected | missed | matched")


class RegisterRequest(BaseModel):
    email: str = Field(max_length=MAX_EMAIL_LEN)
    password: str = Field(min_length=MIN_PASSWORD_LEN, max_length=MAX_PASSWORD_LEN)
    name: SafeText | None = Field(default=None, max_length=MAX_NAME_LEN)


class LoginRequest(BaseModel):
    email: str = Field(max_length=MAX_EMAIL_LEN)
    password: str = Field(min_length=1, max_length=MAX_PASSWORD_LEN)


class LinkSessionRequest(BaseModel):
    session_id: str = Field(min_length=4, max_length=MAX_SESSION_ID_LEN)


class OtpRequestBody(BaseModel):
    channel: str = Field(max_length=8, description="email | phone")
    address: str = Field(min_length=3, max_length=MAX_ADDRESS_LEN)


class OtpVerifyBody(BaseModel):
    channel: str = Field(max_length=8, description="email | phone")
    address: str = Field(min_length=3, max_length=MAX_ADDRESS_LEN)
    code: str = Field(min_length=4, max_length=8)
    name: SafeText | None = Field(default=None, max_length=MAX_NAME_LEN)
