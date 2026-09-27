"""Data-layer guarantees: validity, uniqueness, verification hygiene."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.services.dataset import DATA_DIR

PAST = "1970-01-01"


@pytest.fixture(scope="module")
def schemes(dataset):
    return dataset.schemes


def test_scheme_ids_unique(schemes):
    ids = [s.id for s in schemes]
    assert len(ids) == len(set(ids))


def test_at_least_15_schemes_in_phase_1(schemes):
    assert len(schemes) >= 15


def test_every_scheme_has_official_url_and_verification(schemes):
    for s in schemes:
        assert s.official_url.startswith("https://"), s.id
        assert s.application.url.startswith("https://"), s.id
        assert s.verification_status in {"verified", "pending_review", "stale"}
        assert s.last_verified.isoformat() > PAST


def test_every_scheme_has_documents_and_steps(schemes):
    for s in schemes:
        assert s.documents, f"{s.id} has no document list"
        assert s.application.steps, f"{s.id} has no application steps"


def test_deadline_either_date_or_rolling(schemes):
    for s in schemes:
        assert (s.deadline.date is not None) or s.deadline.rolling, s.id


def test_benefit_display_matches_amount(schemes):
    for s in schemes:
        assert s.benefit.amount_annual_inr >= 0
        assert s.benefit.amount_display.strip() != ""


def test_manifest_covers_every_scheme(schemes):
    manifest = json.loads((DATA_DIR / "verification" / "manifest.json").read_text())
    recorded = {r["scheme_id"] for r in manifest["records"]}
    assert recorded == {s.id for s in schemes}
    for record in manifest["records"]:
        assert record["source"].startswith("https://")


def test_phase_states_present(schemes):
    states = set()
    for s in schemes:
        if s.eligibility.domicile_states:
            states.update(s.eligibility.domicile_states)
    # Phase 1 = West Bengal · Phase 2 = Bihar + Odisha
    # Phase 5 = Uttar Pradesh + Maharashtra + Jharkhand + Tamil Nadu
    for state in ("West Bengal", "Bihar", "Odisha", "Uttar Pradesh",
                  "Maharashtra", "Jharkhand", "Tamil Nadu"):
        assert state in states


def test_scheme_files_are_valid_json():
    for path in sorted(Path(DATA_DIR / "schemes").glob("*.json")):
        json.loads(path.read_text(encoding="utf-8"))


def test_uttar_pradesh_profile_matches(dataset):
    from backend.services.matching import match_profile
    from backend.models.student import (
        Category, CourseLevel, Gender, StudentProfile,
    )

    profile = StudentProfile(
        domicile_state="Uttar Pradesh",
        category=Category.obc,
        annual_family_income=150_000,
        course_level=CourseLevel.ug,
        gender=Gender.female,
        last_exam_percentage=78,
    )
    result = match_profile(profile, dataset)
    ids = {m["id"] for m in result["matches"]}
    assert "up-postmatric-obc-general" in ids
    assert "kanya-sumangala-up" in ids
    # SC/ST line correctly excluded for an OBC student
    assert "up-postmatric-scst" not in ids


def test_up_schoolgirl_prematric(dataset):
    from backend.services.matching import match_profile
    from backend.models.student import (
        Category, CourseLevel, Gender, StudentProfile,
    )

    profile = StudentProfile(
        domicile_state="Uttar Pradesh",
        category=Category.sc,
        annual_family_income=90_000,
        course_level=CourseLevel.school,
        gender=Gender.female,
    )
    ids = {m["id"] for m in match_profile(profile, dataset)["matches"]}
    assert "up-prematric" in ids
    assert "kanya-sumangala-up" in ids


def _match_ids(dataset, **kw):
    from backend.services.matching import match_profile
    from backend.models.student import StudentProfile

    return {m["id"] for m in match_profile(StudentProfile(**kw), dataset)["matches"]}


def test_maharashtra_profiles(dataset):
    from backend.models.student import Category, CourseLevel, Gender

    sc = _match_ids(dataset, domicile_state="Maharashtra", category=Category.sc,
                    annual_family_income=180_000, course_level=CourseLevel.ug,
                    gender=Gender.male, last_exam_percentage=70)
    assert "mahadbt-postmatric-sc" in sc and "mahadbt-freeship-sc" in sc
    assert "mahadbt-postmatric-obc" not in sc

    ebc = _match_ids(dataset, domicile_state="Maharashtra", category=Category.general,
                     annual_family_income=600_000, course_level=CourseLevel.ug,
                     gender=Gender.female, last_exam_percentage=88)
    assert "mahadbt-ebc-shahu" in ebc
    assert "mahadbt-postmatric-sc" not in ebc


def test_jharkhand_profiles(dataset):
    from backend.models.student import Category, CourseLevel, Gender

    st = _match_ids(dataset, domicile_state="Jharkhand", category=Category.st,
                    annual_family_income=200_000, course_level=CourseLevel.higher_secondary,
                    gender=Gender.female)
    assert "jharkhand-ekalyan-scst" in st
    assert "jharkhand-ekalyan-obc" not in st

    muslim = _match_ids(dataset, domicile_state="Jharkhand", category=Category.general,
                        annual_family_income=150_000, course_level=CourseLevel.ug,
                        gender=Gender.male, is_minority=True, minority_community="muslim")
    assert "jharkhand-ekalyan-minority" in muslim


def test_tamil_nadu_profiles(dataset):
    from backend.models.student import Category, CourseLevel, Gender

    girl = _match_ids(dataset, domicile_state="Tamil Nadu", category=Category.obc,
                      annual_family_income=180_000, course_level=CourseLevel.ug,
                      gender=Gender.female, last_exam_percentage=75)
    assert "tn-pudhumai-penn" in girl
    assert "tn-bcmbc-postmatric" in girl
    assert "tn-first-graduate" in girl  # income-free waiver
    assert "tn-postmatric-scst" not in girl
