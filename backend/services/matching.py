"""Matching service — orchestrates engine + ranker + tracker into API payloads."""

from __future__ import annotations

from datetime import date

from backend.matching_engine.engine import EligibilityEngine
from backend.matching_engine.ranker import RankedMatch, RankingEngine
from backend.models.scheme import Scheme
from backend.models.student import StudentProfile
from backend.services.coach import gap_advice_for
from backend.services.dataset import DatasetService
from backend.services.i18n_rules import localize_report


def _deadline_payload(scheme: Scheme, days_left: int | None, expired: bool) -> dict:
    d = scheme.deadline
    return {
        "date": d.date.isoformat() if d.date else None,
        "rolling": d.rolling,
        "label": d.label,
        "days_left": days_left,
        "expired": expired,
    }


def scheme_to_public(scheme: Scheme) -> dict:
    e = scheme.eligibility
    return {
        "id": scheme.id,
        "name": scheme.name,
        "provider": scheme.provider,
        "level": scheme.level,
        "summary": scheme.summary,
        "benefit": scheme.benefit.model_dump(),
        "deadline": _deadline_payload(scheme, None, False),
        "eligibility": {
            "domicile_states": e.domicile_states,
            "categories": [c.value for c in e.categories] if e.categories else None,
            "max_family_income": e.max_family_income,
            "genders": [g.value for g in e.genders] if e.genders else None,
            "minority_only": e.minority_only,
            "minority_communities": e.minority_communities,
            "disability_required": e.disability_required,
            "course_levels": [c.value for c in e.course_levels]
            if e.course_levels
            else None,
            "min_marks_percent": e.min_marks_percent,
            "single_girl_child_required": e.single_girl_child_required,
            "special_conditions": e.special_conditions,
        },
        "documents": scheme.documents,
        "application": scheme.application.model_dump(),
        "official_url": scheme.official_url,
        "last_verified": scheme.last_verified.isoformat(),
        "verification_status": scheme.verification_status,
        "tags": scheme.tags,
        "notes": scheme.notes,
    }


def ranked_to_public(r: RankedMatch) -> dict:
    payload = scheme_to_public(r.scheme)
    payload.update(
        {
            "deadline": _deadline_payload(r.scheme, r.days_left, r.expired),
            "score": r.score,
            "badges": r.badges,
            "why_matched": r.evaluation.why_matched,
            "assumptions": [
                {"rule": a.rule, "requirement": a.requirement, "detail": a.detail}
                for a in r.evaluation.assumptions
            ],
            "clarity": round(r.evaluation.clarity, 3),
        }
    )
    return payload


def match_profile(
    profile: StudentProfile,
    dataset: DatasetService,
    today: date | None = None,
    lang: str = "en",
) -> dict:
    """Full pipeline: profile → rules → ranking → explainable payload.

    ``lang`` localizes every generated explanation (why-you-match reasons,
    assumptions, blockers) through the Phase-4 language templates.
    """
    engine = EligibilityEngine(dataset.schemes)
    report = engine.match(profile)
    report = localize_report(report, lang)
    ranked = RankingEngine(today=today).rank(report.matches)

    near_misses = []
    for ev in report.near_misses:
        blocker = ev.blockers[0]
        payload = scheme_to_public(ev.scheme)
        payload.update(
            {
                "failed_rule": {
                    "rule": blocker.rule,
                    "requirement": blocker.requirement,
                    "detail": blocker.detail,
                },
                "satisfied_rules": [r.detail for r in ev.rules.passed],
                "gap_advice": gap_advice_for(blocker, ev.scheme),
            }
        )
        near_misses.append(payload)

    return {
        "profile_echo": profile.model_dump(mode="json"),
        "evaluated_schemes": report.evaluated,
        "match_count": len(ranked),
        "open_match_count": sum(1 for r in ranked if not r.expired),
        "total_indicative_annual_benefit_inr": sum(
            r.scheme.benefit.amount_annual_inr for r in ranked if not r.expired
        ),
        "matches": [ranked_to_public(r) for r in ranked],
        "near_misses": near_misses,
        "ranked_matches": ranked,  # internal — consumed by reminders/serializer
    }


def strip_internal(result: dict) -> dict:
    """Drop non-serialisable internals before sending over the wire."""
    out = dict(result)
    out.pop("ranked_matches", None)
    return out
