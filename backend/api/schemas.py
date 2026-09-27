"""API request schemas (responses are assembled by the matching service)."""

from __future__ import annotations

from pydantic import BaseModel, Field

from backend.models.student import StudentProfile


class MatchRequest(BaseModel):
    profile: StudentProfile = Field(default_factory=StudentProfile)


class ProfileUpsertRequest(BaseModel):
    profile: StudentProfile


class TrackRequest(BaseModel):
    status: str | None = Field(
        default=None,
        description="saved | planning | applied | under_review | approved | rejected; null clears",
    )


class ChatRequest(BaseModel):
    message: str
    chat_id: str | None = None


class DispatchRequest(BaseModel):
    limit: int = Field(default=10, ge=1, le=50)


class AskRequest(BaseModel):
    question: str = Field(min_length=2, max_length=1000)
    session_id: str | None = Field(
        default=None,
        description="When given, answers are personalised with the saved profile",
    )
