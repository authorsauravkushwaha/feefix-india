"""Scholarship / fee-waiver scheme model — the dataset currency of FeeFix.

Schemes are curated as structured data (never scraped blobs of text) so the
eligibility rules are machine-evaluable, verifiable, and explainable.
"""

from __future__ import annotations

from datetime import date as dt_date  # aliased: the Deadline field is itself named "date"

from pydantic import BaseModel, Field

from backend.models.student import Category, CourseLevel, Gender


class Benefit(BaseModel):
    type: str = Field(description="scholarship | fee_waiver | grant")
    amount_annual_inr: int = Field(
        ge=0, description="Representative annual benefit in INR (indicative)"
    )
    amount_display: str = Field(description="Human-readable benefit range")
    details: str = ""


class Deadline(BaseModel):
    date: dt_date | None = Field(default=None, description="Application deadline")
    rolling: bool = Field(default=False, description="Accepts applications year-round")
    label: str = ""


class Eligibility(BaseModel):
    """Machine-evaluable eligibility rules for a scheme.

    A field left ``None`` means the scheme does not restrict on that
    dimension, and the corresponding rule is skipped by the engine.
    """

    domicile_states: list[str] | None = None  # None → all India
    categories: list[Category] | None = None
    max_family_income: int | None = None
    genders: list[Gender] | None = None
    minority_only: bool = False
    minority_communities: list[str] | None = None
    disability_required: bool = False
    course_levels: list[CourseLevel] | None = None
    min_marks_percent: float | None = None
    single_girl_child_required: bool = False
    special_conditions: list[str] = Field(default_factory=list)


class Application(BaseModel):
    mode: str = "online"
    portal: str = ""
    url: str = ""
    steps: list[str] = Field(default_factory=list)


class Scheme(BaseModel):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9\-]*$")
    name: str
    provider: str
    level: str = Field(description="state | central")
    summary: str
    benefit: Benefit
    deadline: Deadline
    eligibility: Eligibility
    documents: list[str] = Field(default_factory=list)
    application: Application
    official_url: str
    last_verified: dt_date
    verification_status: str = Field(description="verified | pending_review | stale")
    tags: list[str] = Field(default_factory=list)
    notes: str = ""

    @property
    def is_all_india(self) -> bool:
        return self.level == "central"
