"""Eligibility engine — runs the rule set across the whole scheme dataset.

Design goals:

* **Explainable** — every match carries the satisfied rules ("why you match")
  and every unknown becomes an explicit assumption.
* **Forgiving on data gaps** — missing profile answers never auto-disqualify;
  they lower the *clarity score* instead.
* **Near-miss aware** — a scheme failing exactly one rule is surfaced as an
  "almost there" opportunity with the single blocking requirement named.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from backend.matching_engine.rules import RuleResult, RuleSet, evaluate_rules
from backend.models.scheme import Scheme
from backend.models.student import StudentProfile


@dataclass
class SchemeEvaluation:
    scheme: Scheme
    rules: RuleSet = field(default_factory=RuleSet)

    @property
    def matched(self) -> bool:
        return self.rules.is_match

    @property
    def near_miss(self) -> bool:
        return not self.matched and self.rules.is_near_miss

    @property
    def clarity(self) -> float:
        return self.rules.clarity

    @property
    def why_matched(self) -> list[str]:
        return [r.detail for r in self.rules.passed]

    @property
    def assumptions(self) -> list[RuleResult]:
        return self.rules.unknowns

    @property
    def blockers(self) -> list[RuleResult]:
        return self.rules.failures


@dataclass
class MatchReport:
    matches: list[SchemeEvaluation]
    near_misses: list[SchemeEvaluation]
    evaluated: int


class EligibilityEngine:
    """Compares one student profile against the full scheme catalogue."""

    def __init__(self, schemes: list[Scheme]):
        self.schemes = schemes

    def evaluate_scheme(
        self, profile: StudentProfile, scheme: Scheme
    ) -> SchemeEvaluation:
        return SchemeEvaluation(scheme=scheme, rules=evaluate_rules(profile, scheme))

    def match(self, profile: StudentProfile) -> MatchReport:
        matches: list[SchemeEvaluation] = []
        near_misses: list[SchemeEvaluation] = []
        for scheme in self.schemes:
            evaluation = self.evaluate_scheme(profile, scheme)
            if evaluation.matched:
                matches.append(evaluation)
            elif evaluation.near_miss:
                near_misses.append(evaluation)
        return MatchReport(
            matches=matches, near_misses=near_misses, evaluated=len(self.schemes)
        )
