"""Engine behaviour: matches, explanations, near-misses, unknowns."""

from __future__ import annotations

from backend.matching_engine import EligibilityEngine
from backend.models.student import (
    Category,
    CourseLevel,
    Gender,
    StudentProfile,
)


def _ids(evaluations):
    return {e.scheme.id for e in evaluations}


class TestMatches:
    def test_aikyashree_matched_for_wb_minority(self, dataset, wb_female_minority_ug):
        report = EligibilityEngine(dataset.schemes).match(wb_female_minority_ug)
        assert "aikyashree-wb" in _ids(report.matches)

    def test_minors_excluded_from_aikyashree(self, dataset, wb_female_minority_ug):
        profile = wb_female_minority_ug.model_copy(update={"is_minority": False})
        engine = EligibilityEngine(dataset.schemes)
        evaluation = engine.evaluate_scheme(profile, dataset.get("aikyashree-wb"))
        assert not evaluation.matched
        assert evaluation.blockers[0].rule == "minority"

    def test_income_cap_blocks_scheme(self, dataset, wb_female_minority_ug):
        rich = wb_female_minority_ug.model_copy(update={"annual_family_income": 900_000})
        engine = EligibilityEngine(dataset.schemes)
        evaluation = engine.evaluate_scheme(rich, dataset.get("sv-mcm-wb"))
        assert not evaluation.matched
        assert any(b.rule == "income" for b in evaluation.blockers)

    def test_wrong_state_blocks_state_scheme(self, dataset, wb_female_minority_ug):
        outsider = wb_female_minority_ug.model_copy(update={"domicile_state": "Bihar"})
        engine = EligibilityEngine(dataset.schemes)
        evaluation = engine.evaluate_scheme(outsider, dataset.get("sv-mcm-wb"))
        assert not evaluation.matched
        assert evaluation.blockers[0].rule == "state"

    def test_central_schemes_ignore_state(self, dataset, wb_female_minority_ug):
        outsider = wb_female_minority_ug.model_copy(update={"domicile_state": "Bihar"})
        report = EligibilityEngine(dataset.schemes).match(outsider)
        assert "nsp-central-sector" in _ids(report.matches)
        assert "sv-mcm-wb" not in _ids(report.matches)

    def test_merit_cutoff(self, dataset, wb_female_minority_ug):
        low = wb_female_minority_ug.model_copy(update={"last_exam_percentage": 60})
        engine = EligibilityEngine(dataset.schemes)
        evaluation = engine.evaluate_scheme(low, dataset.get("sv-mcm-wb"))
        assert not evaluation.matched
        assert evaluation.blockers[0].rule == "marks"

    def test_sc_schoolboy_gets_oasis(self, dataset, wb_sc_schoolboy):
        report = EligibilityEngine(dataset.schemes).match(wb_sc_schoolboy)
        assert "oasis-sc-st-wb" in _ids(report.matches)
        assert "oasis-pre-sc-wb" in _ids(report.matches)


class TestExplanations:
    def test_every_match_explains_why(self, dataset, wb_female_minority_ug):
        report = EligibilityEngine(dataset.schemes).match(wb_female_minority_ug)
        for evaluation in report.matches:
            assert evaluation.why_matched, f"{evaluation.scheme.id} has no explanation"
            for reason in evaluation.why_matched:
                assert len(reason) > 12  # real sentence, not a token

    def test_explanation_mentions_state_for_state_scheme(self, dataset, wb_female_minority_ug):
        engine = EligibilityEngine(dataset.schemes)
        evaluation = engine.evaluate_scheme(wb_female_minority_ug, dataset.get("sv-mcm-wb"))
        assert any("West Bengal" in r for r in evaluation.why_matched)

    def test_unknown_marks_becomes_assumption_not_failure(self, dataset):
        profile = StudentProfile(
            domicile_state="West Bengal",
            category=Category.general,
            annual_family_income=200_000,
            course_level=CourseLevel.ug,
            gender=Gender.female,
            last_exam_percentage=None,  # <-- unknown
        )
        engine = EligibilityEngine(dataset.schemes)
        evaluation = engine.evaluate_scheme(profile, dataset.get("sv-mcm-wb"))
        assert evaluation.matched
        assert any(a.rule == "marks" for a in evaluation.assumptions)
        assert evaluation.clarity < 1.0

    def test_missing_income_is_assumption(self, dataset):
        profile = StudentProfile(annual_family_income=None)
        engine = EligibilityEngine(dataset.schemes)
        evaluation = engine.evaluate_scheme(profile, dataset.get("oasis-sc-st-wb"))
        if evaluation.matched:
            assert any(a.rule == "income" for a in evaluation.assumptions)


class TestNearMisses:
    def test_exactly_one_failure_is_near_miss(self, dataset):
        # Everything perfect for SVMCM except income slightly over the cap.
        profile = StudentProfile(
            domicile_state="West Bengal",
            category=Category.general,
            annual_family_income=260_000,  # cap is 250_000
            course_level=CourseLevel.ug,
            gender=Gender.female,
            last_exam_percentage=80,
        )
        engine = EligibilityEngine(dataset.schemes)
        report = engine.match(profile)
        ids = _ids(report.near_misses)
        assert "sv-mcm-wb" in ids

    def test_two_failures_is_not_near_miss(self, dataset):
        profile = StudentProfile(
            domicile_state="Bihar",  # wrong state
            category=Category.general,
            annual_family_income=900_000,  # over income
            course_level=CourseLevel.ug,
            last_exam_percentage=50,  # under merit
        )
        engine = EligibilityEngine(dataset.schemes)
        report = engine.match(profile)
        assert "sv-mcm-wb" not in _ids(report.near_misses)
        assert "sv-mcm-wb" not in _ids(report.matches)
