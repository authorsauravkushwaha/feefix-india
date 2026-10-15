"""Phase 4 language layer — localized rule explanations."""

from __future__ import annotations

import json
import re
from pathlib import Path

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


def test_tamil_explanations(dataset):
    import re

    result = match_profile(StudentProfile(**PROFILE), dataset, lang="ta")
    reasons = [r for m in result["matches"] for r in m["why_matched"]]
    assert reasons and any(re.search(r"[஀-௿]", r) for r in reasons)


def test_all_explanation_languages_cover_same_keys():
    import json
    from pathlib import Path

    root = Path("language/regional_support/explanations")
    en_keys = set(json.loads((root / "en.json").read_text(encoding="utf-8")))
    for lang in ("bn", "hi", "ta"):
        lang_keys = set(json.loads((root / f"{lang}.json").read_text(encoding="utf-8")))
        assert lang_keys == en_keys, f"{lang} missing: {en_keys - lang_keys}"


# ---------------------------------------------------------------------------
# The UI dictionary is a SEPARATE i18n layer from the rule-explanation
# templates above, and it had no parity test at all. That is why Hindi was
# missing 44 of 126 keys — the whole dashboard, every badge, the explore
# filters, the footer disclaimer and all five matcher help strings — without
# anything reporting it. Students saw a half-translated app: the questions in
# Hindi, the answers' labels in English.
#
# app.js falls back to English (`State.dict[key] || State.fallback?.[key] ||
# key`), so a gap degrades silently rather than breaking. A silent degradation
# is exactly what a test has to catch, because nobody files a bug for "the
# badge said Closed instead of बंद".
# ---------------------------------------------------------------------------
UI_DICT_ROOT = Path("language/regional_support")


def _ui_dict(lang: str) -> dict:
    return json.loads((UI_DICT_ROOT / f"{lang}.json").read_text(encoding="utf-8"))


def test_all_ui_dictionary_languages_cover_same_keys():
    en_keys = set(_ui_dict("en"))
    for lang in ("bn", "hi", "ta"):
        lang_keys = set(_ui_dict(lang))
        assert lang_keys == en_keys, (
            f"{lang}.json missing {len(en_keys - lang_keys)} UI key(s): "
            f"{sorted(en_keys - lang_keys)[:10]}…"
        )


def test_ui_dictionary_placeholders_survive_translation():
    """A translated string must keep every interpolation slot.

    Dropping `{n}` from `scheme.days_left` renders a literal "{n} days left" or
    a bare number with no unit — a visible bug in every language but English,
    which is precisely why it survives review.
    """
    en = _ui_dict("en")
    slot = re.compile(r"\{[a-zA-Z_]+\}")
    for lang in ("bn", "hi", "ta"):
        d = _ui_dict(lang)
        for key, english in en.items():
            assert set(slot.findall(english)) == set(slot.findall(d[key])), (
                f"{lang}.{key}: placeholder set differs from English "
                f"({english!r} vs {d[key]!r})"
            )


def test_ui_dictionary_translations_are_actually_translated():
    """Guards against a "translation" that is just the English string copied in.

    Filling a parity gap by copying English makes the test above pass while
    delivering nothing to the student. Only checked for scripts that differ from
    Latin, so it cannot false-positive on a legitimately shared token.
    """
    en = _ui_dict("en")
    for lang, script in (("bn", r"[\u0980-\u09FF]"), ("hi", r"[\u0900-\u097F]"),
                         ("ta", r"[\u0B80-\u0BFF]")):
        d = _ui_dict(lang)
        copied = []
        for key, english in en.items():
            value = d[key]
            # Skip strings that are pure punctuation, a dash, an emoji or a brand.
            if not re.search(r"[A-Za-z]{3}", english):
                continue
            if value.strip() == english.strip() and not re.search(script, value):
                copied.append(key)
        # Allow a small number of genuinely shared tokens (e.g. "WhatsApp",
        # "FeeFix", "SVMCM") but not a wholesale copy.
        assert len(copied) <= 6, (
            f"{lang}.json has {len(copied)} untranslated English strings: {copied[:10]}"
        )
