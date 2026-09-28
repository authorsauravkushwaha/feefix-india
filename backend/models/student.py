"""Student profile model — the input to the FeeFix matching engine.

The profile intentionally collects only the attributes that drive
eligibility decisions for Indian scholarship and fee-waiver schemes.
Every field maps to at least one real scheme requirement in the dataset.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


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
    "Andhra Pradesh", "Arunachal Pradesh", "Assam", "Bihar", "Chhattisgarh",
    "Delhi", "Goa", "Gujarat", "Haryana", "Himachal Pradesh",
    "Jammu and Kashmir", "Jharkhand", "Karnataka", "Kerala",
    "Madhya Pradesh", "Maharashtra", "Manipur", "Meghalaya", "Mizoram",
    "Nagaland", "Odisha", "Punjab", "Rajasthan", "Sikkim", "Tamil Nadu",
    "Telangana", "Tripura", "Uttar Pradesh", "Uttarakhand", "West Bengal",
]


class StudentProfile(BaseModel):
    """Everything FeeFix needs to decide *which schemes fit this student*.

    Fields left ``None`` are treated as *unknown* (not disqualifying) by the
    engine; the match explanation then marks them as assumptions.
    """

    name: str | None = Field(default=None, description="Optional display name")
    domicile_state: str = Field(default="West Bengal")
    category: Category = Category.general
    annual_family_income: int | None = Field(
        default=None, ge=0, description="Annual family income in INR"
    )
    course_level: CourseLevel = CourseLevel.ug
    gender: Gender = Gender.prefer_not_to_say
    is_minority: bool = False
    minority_community: str | None = None
    has_disability: bool = False
    last_exam_percentage: float | None = Field(
        default=None, ge=0, le=100,
        description="Aggregate percentage in the last qualifying exam",
    )
    is_single_girl_child: bool = False

    @property
    def is_female(self) -> bool:
        return self.gender == Gender.female
