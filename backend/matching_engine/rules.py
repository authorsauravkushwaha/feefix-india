"""Rule primitives for the eligibility engine.

Every rule produces one of three states::

    pass     — the student's data satisfies the scheme requirement
    fail     — the student's data clearly violates the requirement
    unknown  — the student has not supplied the data needed to decide

A scheme is a MATCH when no rule fails (unknowns become *assumptions* the
student should verify). A scheme is a NEAR MISS when exactly one rule fails —
surface these to students as "you are one requirement away" opportunities.

Each result also carries ``params`` — the slot values used to re-render the
explanation in any supported language (see backend/services/i18n_rules.py).
This keeps the engine language-neutral while always defaulting to English.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from backend.models.scheme import Scheme
from backend.models.student import Gender, StudentProfile

PASS, FAIL, UNKNOWN = "pass", "fail", "unknown"


def _inr(n: int) -> str:
    """Format INR in Indian digit grouping (₹2,50,000)."""
    s = str(int(n))
    if len(s) <= 3:
        return f"₹{s}"
    last3, rest = s[-3:], s[:-3]
    groups = []
    while len(rest) > 2:
        groups.insert(0, rest[-2:])
        rest = rest[:-2]
    if rest:
        groups.insert(0, rest)
    return f"₹{','.join(groups)},{last3}"


@dataclass
class RuleResult:
    rule: str           # machine id, e.g. "income"
    status: str         # pass | fail | unknown
    requirement: str    # what the scheme demands, in plain words
    detail: str         # the verdict for this student, in plain words (en)
    params: dict = field(default_factory=dict)  # slots for i18n re-rendering


@dataclass
class RuleSet:
    """The outcome of evaluating every applicable rule of one scheme."""

    results: list[RuleResult] = field(default_factory=list)

    @property
    def failures(self) -> list[RuleResult]:
        return [r for r in self.results if r.status == FAIL]

    @property
    def passed(self) -> list[RuleResult]:
        return [r for r in self.results if r.status == PASS]

    @property
    def unknowns(self) -> list[RuleResult]:
        return [r for r in self.results if r.status == UNKNOWN]

    @property
    def is_match(self) -> bool:
        return not self.failures

    @property
    def is_near_miss(self) -> bool:
        return len(self.failures) == 1

    @property
    def clarity(self) -> float:
        """Share of applicable rules that are confirmed satisfied (0..1)."""
        if not self.results:
            return 1.0
        return len(self.passed) / len(self.results)


def evaluate_rules(profile: StudentProfile, scheme: Scheme) -> RuleSet:
    """Run every rule implied by the scheme's eligibility definition."""
    e = scheme.eligibility
    rules = RuleSet()

    # --- Domicile / state ------------------------------------------------
    if e.domicile_states:
        states = ", ".join(e.domicile_states)
        requirement = f"Domicile of {states}"
        if not profile.domicile_state:
            rules.results.append(RuleResult(
                "state", UNKNOWN, requirement,
                "Domicile state not provided — assumed ok.",
                params={"states": states, "student": ""},
            ))
        elif profile.domicile_state in e.domicile_states:
            rules.results.append(RuleResult(
                "state", PASS, requirement,
                f"Your domicile state ({profile.domicile_state}) satisfies the "
                f"{states} domicile requirement.",
                params={"states": states, "student": profile.domicile_state},
            ))
        else:
            rules.results.append(RuleResult(
                "state", FAIL, requirement,
                f"This scheme is limited to domiciles of {states}; your state "
                f"is {profile.domicile_state}.",
                params={"states": states, "student": profile.domicile_state},
            ))

    # --- Reservation category ---------------------------------------------
    if e.categories:
        cats = ", ".join(c.value.upper() for c in e.categories)
        requirement = f"Category must be one of {cats}"
        params = {"cats": cats, "student": profile.category.value.upper()}
        if profile.category in e.categories:
            rules.results.append(RuleResult(
                "category", PASS, requirement,
                f"Your category ({profile.category.value.upper()}) is eligible.",
                params=params,
            ))
        else:
            rules.results.append(RuleResult(
                "category", FAIL, requirement,
                f"Requires category {cats}; you selected "
                f"{profile.category.value.upper()}.",
                params=params,
            ))

    # --- Family income -----------------------------------------------------
    if e.max_family_income is not None:
        cap = _inr(e.max_family_income)
        requirement = f"Annual family income up to {cap}"
        if profile.annual_family_income is None:
            rules.results.append(RuleResult(
                "income", UNKNOWN, requirement,
                f"Income not provided — the scheme caps family income at {cap}/year.",
                params={"cap": cap, "income": ""},
            ))
        elif profile.annual_family_income <= e.max_family_income:
            rules.results.append(RuleResult(
                "income", PASS, requirement,
                f"Your family income ({_inr(profile.annual_family_income)}) is "
                f"within the {cap} limit.",
                params={"cap": cap, "income": _inr(profile.annual_family_income)},
            ))
        else:
            rules.results.append(RuleResult(
                "income", FAIL, requirement,
                f"Your family income ({_inr(profile.annual_family_income)}) is "
                f"above the {cap} limit.",
                params={"cap": cap, "income": _inr(profile.annual_family_income)},
            ))

    # --- Gender -------------------------------------------------------------
    if e.genders:
        allowed = [g.value.replace("_", " ") for g in e.genders]
        if Gender.prefer_not_to_say in e.genders or set(Gender) <= set(e.genders):
            # Scheme treats gender as unrestricted — do not surface a rule.
            pass
        else:
            allowed_str = ", ".join(allowed)
            requirement = f"Open to {allowed_str} applicants"
            params = {"allowed": allowed_str}
            if profile.gender == Gender.prefer_not_to_say:
                rules.results.append(RuleResult(
                    "gender", UNKNOWN, requirement,
                    "Gender not shared — this scheme is gender-restricted.",
                    params={**params, "student": ""},
                ))
            elif profile.gender in e.genders:
                rules.results.append(RuleResult(
                    "gender", PASS, requirement,
                    "Your gender matches the scheme's requirement.",
                    params={**params, "student": profile.gender.value},
                ))
            else:
                rules.results.append(RuleResult(
                    "gender", FAIL, requirement,
                    f"This scheme is open to {allowed_str} applicants only.",
                    params={**params, "student": profile.gender.value},
                ))

    # --- Minority community -------------------------------------------------
    if e.minority_only:
        communities = (
            " / ".join(c.title() for c in e.minority_communities)
            if e.minority_communities else "notified minority"
        )
        requirement = f"Belong to a notified minority community ({communities})"
        if profile.is_minority:
            if (
                e.minority_communities
                and profile.minority_community
                and profile.minority_community.lower() not in e.minority_communities
            ):
                rules.results.append(RuleResult(
                    "minority", FAIL, requirement,
                    f"{profile.minority_community.title()} is not in the scheme's "
                    f"eligible community list.",
                    params={"communities": communities,
                            "student": profile.minority_community.title()},
                ))
            else:
                rules.results.append(RuleResult(
                    "minority", PASS, requirement,
                    "You belong to a minority community covered by the scheme.",
                    params={"communities": communities, "student": ""},
                ))
        else:
            rules.results.append(RuleResult(
                "minority", FAIL, requirement,
                "You indicated you are not from a notified minority community.",
                params={"communities": communities, "student": ""},
            ))

    # --- Disability ----------------------------------------------------------
    if e.disability_required:
        requirement = "Person with benchmark disability (40%+ disability certificate)"
        if profile.has_disability:
            rules.results.append(RuleResult(
                "disability", PASS, requirement,
                "Your disability status satisfies this requirement.",
            ))
        else:
            rules.results.append(RuleResult(
                "disability", FAIL, requirement,
                "This scheme is exclusively for students with benchmark "
                "disability.",
            ))

    # --- Course level --------------------------------------------------------
    if e.course_levels:
        levels = ", ".join(l.value.replace("_", " ") for l in e.course_levels)
        student_level = profile.course_level.value.replace("_", " ")
        requirement = f"Enrolled in one of: {levels}"
        params = {"levels": levels, "student": student_level}
        if profile.course_level in e.course_levels:
            rules.results.append(RuleResult(
                "course", PASS, requirement,
                f"Your course level ({student_level}) "
                "is covered.",
                params=params,
            ))
        else:
            rules.results.append(RuleResult(
                "course", FAIL, requirement,
                f"Covers {levels}; you selected "
                f"{student_level}.",
                params=params,
            ))

    # --- Merit (marks) --------------------------------------------------------
    if e.min_marks_percent is not None:
        cutoff = f"{e.min_marks_percent:.0f}%"
        requirement = f"At least {cutoff} in the last qualifying exam"
        if profile.last_exam_percentage is None:
            rules.results.append(RuleResult(
                "marks", UNKNOWN, requirement,
                "Marks not provided — verify you meet the merit cut-off.",
                params={"cutoff": cutoff, "student": ""},
            ))
        elif profile.last_exam_percentage >= e.min_marks_percent:
            rules.results.append(RuleResult(
                "marks", PASS, requirement,
                f"Your {profile.last_exam_percentage:.1f}% clears the "
                f"{cutoff} merit cut-off.",
                params={"cutoff": cutoff,
                        "student": f"{profile.last_exam_percentage:.1f}%"},
            ))
        else:
            rules.results.append(RuleResult(
                "marks", FAIL, requirement,
                f"Needs ≥{cutoff} in the last exam; you "
                f"reported {profile.last_exam_percentage:.1f}%.",
                params={"cutoff": cutoff,
                        "student": f"{profile.last_exam_percentage:.1f}%"},
            ))

    # --- Single girl child ------------------------------------------------------
    if e.single_girl_child_required:
        requirement = "Only / single girl child of the family"
        if profile.is_single_girl_child and profile.is_female:
            rules.results.append(RuleResult(
                "single_girl_child", PASS, requirement,
                "You qualify as a single girl child applicant.",
            ))
        else:
            rules.results.append(RuleResult(
                "single_girl_child", FAIL, requirement,
                "Requires the applicant to be the family's only girl child.",
            ))

    return rules
