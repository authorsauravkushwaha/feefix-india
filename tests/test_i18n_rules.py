"""Phase 4 language layer — localized rule explanations."""

from __future__ import annotations

import re

import pytest

from backend.services.i18n_rules import render_rule
from backend.matching_engine import EligibilityEngine
from backend.matching_engine.rules import FAIL, PASS, UNKNOWN
from backend.models.student import (
    Category,
    CourseLevel,
    Gender,
    StudentProfile,
)
from backend.services.matching import match_profile

BN_RE = re.compile(r"[ঀ-৿]")
HI_RE = re.compile(r"[ऀ-ॿ]")

PROFILE = {
    "domicile_state": "West Bengal",
    "category": Category.general,
    "annual_family_income": 200_000,
    "course_level": CourseLevel.ug,
    "gender": Gender.female,
    "is_minority": True,
    "minority_community": "muslim",
    "last_exam_percentage": 82,
}


def test_bn_templates_cover_all_rule_states(dataset):
    from backend.services.i18n_rules import _templates

    tpls = _templates("bn")
    engine = EligibilityEngine(dataset.schemes)
    report = engine.match(StudentProfile(**PROFILE))
    for ev in report.matches + report.near_misses:
        for r in ev.rules.results:
            assert f"{r.rule}.{r.status}" in tpls, f"missing bn template for {r.rule}.{r.status}"


def test_bn_explanations_contain_bengali(dataset):
    result = match_profile(StudentProfile(**PROFILE), dataset, lang="bn")
    reasons = [r for m in result["matches"] for r in m["why_matched"]]
    assert reasons and any(BN_RE.search(r) for r in reasons)


def test_hi_explanations_contain_devanagari(dataset):
    result = match_profile(StudentProfile(**PROFILE), dataset, lang="hi")
    reasons = [r for m in result["matches"] for r in m["why_matched"]]
    assert reasons and any(HI_RE.search(r) for r in reasons)


def test_english_default_unchanged(dataset):
    result = match_profile(StudentProfile(**PROFILE), dataset)
    sv = next(m for m in result["matches"] if m["id"] == "sv-mcm-wb")
    assert any("West Bengal" in r for r in sv["why_matched"])


def test_unknown_is_assumption_in_bengali(dataset):
    profile = StudentProfile(**{**PROFILE, "last_exam_percentage": None})
    result = match_profile(profile, dataset, lang="bn")
    sv = next(m for m in result["matches"] if m["id"] == "sv-mcm-wb")
    assert sv["assumptions"] and BN_RE.search(sv["assumptions"][0]["detail"])


def test_near_miss_blocker_localized(dataset):
    profile = StudentProfile(**{**PROFILE, "annual_family_income": 260_000})
    result = match_profile(profile, dataset, lang="bn")
    near = next(n for n in result["near_misses"] if n["id"] == "sv-mcm-wb")
    assert BN_RE.search(near["failed_rule"]["detail"])
    assert near["gap_advice"]  # coaching stays English (documented — rule DSL layer)


def test_render_rule_fallback_safety():
    from backend.matching_engine.rules import RuleResult

    r = RuleResult("state", PASS, "req", "english detail", params={"student": "WB", "states": "WB"})
    assert render_rule(r, "xx") == "english detail"
    assert render_rule(r, "en") == "english detail"
    out = render_rule(r, "bn")
    assert BN_RE.search(out) and "WB" in out
