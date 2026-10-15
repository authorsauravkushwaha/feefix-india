"""Student profile model — the input to the FeeFix matching engine.

The profile intentionally collects only the attributes that drive
eligibility decisions for Indian scholarship and fee-waiver schemes.
Every field maps to at least one real scheme requirement in the dataset.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field, field_validator

from backend.services.limits import MAX_NAME_LEN


class Gender(str, Enum):
    male = "male"
    female = "female"
    other = "other"
    prefer_not_to_say = "prefer_not_to_say"


class Category(str, Enum):
    """Reservation categories used by Indian scholarship schemes.

    OBC-A / OBC-B (West Bengal sub-classes) are normalised to ``obc`` by the
    API layer because scheme rules only distinguish OBC as a whole.
    """

    general = "general"
    sc = "sc"
    st = "st"
    obc = "obc"


class CourseLevel(str, Enum):
    school = "school"  # class VI–X
    higher_secondary = "higher_secondary"  # class XI–XII
    iti = "iti"  # industrial training institutes
    diploma = "diploma"  # polytechnic / technical diploma
    ug = "ug"  # undergraduate (incl. MBBS, B.Tech, BA…)
    pg = "pg"  # postgraduate (MA, M.Sc, M.Tech, MBA…)
    phd = "phd"


MINORITY_COMMUNITIES = [
    "muslim",
    "christian",
    "sikh",
    "buddhist",
    "jain",
    "parsee",
]

INDIAN_STATES = [
    "Andaman and Nicobar Islands", "Andhra Pradesh", "Arunachal Pradesh", "Assam",
    "Bihar", "Chandigarh", "Chhattisgarh",
    "Dadra and Nagar Haveli and Daman and Diu", "Delhi", "Goa", "Gujarat",
    "Haryana", "Himachal Pradesh",
    "Jammu and Kashmir", "Jharkhand", "Karnataka", "Kerala", "Ladakh",
    "Lakshadweep", "Madhya Pradesh", "Maharashtra", "Manipur", "Meghalaya",
    "Mizoram", "Nagaland", "Odisha", "Puducherry", "Punjab", "Rajasthan",
    "Sikkim", "Tamil Nadu", "Telangana", "Tripura", "Uttar Pradesh",
    "Uttarakhand", "West Bengal",
]


class StudentProfile(BaseModel):
    """Everything FeeFix needs to decide *which schemes fit this student*.

    Fields left ``None`` are treated as *unknown* (not disqualifying) by the
    engine; the match explanation then marks them as assumptions.
    """

    name: str | None = Field(default=None, max_length=MAX_NAME_LEN, description="Optional display name")
    domicile_state: str = Field(default="West Bengal", max_length=64)
    category: Category = Category.general
    annual_family_income: int | None = Field(
        default=None, ge=0, description="Annual family income in INR"
    )
    course_level: CourseLevel = CourseLevel.ug
    gender: Gender = Gender.prefer_not_to_say
    is_minority: bool = False
    minority_community: str | None = Field(default=None, max_length=32)
    has_disability: bool = False
    last_exam_percentage: float | None = Field(
        default=None, ge=0, le=100,
        description="Aggregate percentage in the last qualifying exam",
    )
    is_single_girl_child: bool = False

    @field_validator("domicile_state")
    @classmethod
    def _clean_state(cls, v: str) -> str:
        """Bound and tidy the domicile; never mis-assign an unrecognised state.

        A student from a state/UT outside the list keeps their value — it simply
        won't satisfy a *state-restricted* scheme (correct behaviour) while still
        matching all-India schemes. Forcing a default here would wrongly surface
        West-Bengal-only schemes to, say, a Puducherry applicant.
        """
        v = (v or "").strip()
        return v or "West Bengal"

    @field_validator("minority_community")
    @classmethod
    def _known_community(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip().lower()
        return v if v in MINORITY_COMMUNITIES else None

    @property
    def is_female(self) -> bool:
        return self.gender == Gender.female
