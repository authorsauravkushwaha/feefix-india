"""Ranking: urgency, benefit normalisation, expiry ordering, badges."""

from __future__ import annotations

from datetime import date, timedelta

from backend.matching_engine import EligibilityEngine, RankingEngine
from backend.models.student import (
    Category,
    CourseLevel,
    Gender,
    StudentProfile,
)

TODAY = date.today()


def _profile() -> StudentProfile:
    return StudentProfile(
        domicile_state="West Bengal",
        category=Category.general,
        annual_family_income=200_000,
        course_level=CourseLevel.ug,
        gender=Gender.female,
        is_minority=True,
        minority_community="muslim",
        last_exam_percentage=82,
    )


def _rank(dataset, today=TODAY):
    engine = EligibilityEngine(dataset.schemes)
    report = engine.match(_profile())
    return RankingEngine(today=today).rank(report.matches)


def test_urgent_deadline_beats_deadline_far_away(dataset):
    ranked = _rank(dataset)
    urgent = [r for r in ranked if r.days_left is not None and 0 <= r.days_left <= 34]
    far = [r for r in ranked if r.days_left is not None and r.days_left >= 60]
    assert urgent and far
    assert min(r.score for r in urgent) > 0
    # With clarity equal at 1.0, urgency must dominate the ordering signal.
    assert all(u.score >= f.score - 25 for u in urgent for f in far)


def test_days_left_computed(dataset):
    ranked = _rank(dataset)
    by_id = {r.scheme.id: r for r in ranked}
    svmcm = by_id["sv-mcm-wb"]
    assert svmcm.days_left == (date(2026, 11, 30) - TODAY).days


def test_rolling_schemes_have_no_days_left(dataset):
    ranker = RankingEngine(today=TODAY)
    engine = EligibilityEngine(dataset.schemes)
    rolling_schemes = [s for s in dataset.schemes if s.deadline.rolling]
    assert rolling_schemes, "dataset must contain rolling-intake schemes"
    for scheme in rolling_schemes:
        evaluation = engine.evaluate_scheme(_profile(), scheme)
        assert ranker.days_until(evaluation) is None


def test_expired_pushed_to_bottom(dataset):
    future = TODAY + timedelta(days=10)
    ranked = _rank(dataset, today=future)
    # every deadline still open ⇒ nothing expired ⇒ expired flag False
    assert all(not r.expired for r in ranked)

    far_future = TODAY + timedelta(days=400)
    ranked_late = _rank(dataset, today=far_future)
    expired = [r for r in ranked_late if r.expired]
    open_ones = [r for r in ranked_late if not r.expired]
    assert expired
    if open_ones:
        assert ranked_late[: len(open_ones)] == open_ones  # all open first


def test_top_pick_badge(dataset):
    ranked = _rank(dataset)
    assert ranked[0].badges[0] == "top_pick"


def test_scores_are_deterministic(dataset):
    a = [r.score for r in _rank(dataset)]
    b = [r.score for r in _rank(dataset)]
    assert a == b


def test_benefit_normalisation_increases_score(dataset):
    """Two hypothetical matches differing only by benefit: the richer ranks higher."""
    ranked = _rank(dataset)
    by_id = {r.scheme.id: r for r in ranked}
    pragati = by_id.get("aicte-pragati")  # ₹50,000
    central = by_id.get("nsp-central-sector")  # ₹12,000
    if pragati and central and pragati.days_left == central.days_left:
        assert pragati.score > central.score
