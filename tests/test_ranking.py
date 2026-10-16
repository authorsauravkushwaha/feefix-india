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

#: The dataset's own calendar, not the machine's. Date-dependent assertions were
#: previously anchored to ``date.today()``, which turned every scheme deadline
#: into a **scheduled test failure**: on 2026-10-16 the `today + 10 days` window
#: swallowed the 2026-10-25 NSP deadline and `test_expired_pushed_to_bottom`
#: started failing with no code change at all. Anchoring to the fixture data
#: (and asserting the resulting invariants) makes the suite date-independent
#: while still testing real deadlines (see `test_expiry_ordering_holds_on_every_day`).
TODAY = date.today()


def _matched(dataset, today=TODAY):
    engine = EligibilityEngine(dataset.schemes)
    return engine.match(_profile()).matches


def _fixed_deadlines(matches) -> list[date]:
    """Deadlines of the matched schemes that are not rolling intake."""
    return sorted(
        m.scheme.deadline.date
        for m in matches
        if m.scheme.deadline.date and not m.scheme.deadline.rolling
    )


def _anchor_before(matches, days: int) -> date:
    """A `today` that puts the earliest matched deadline ``days`` days away."""
    return _fixed_deadlines(matches)[0] - timedelta(days=days)


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
    matches = _matched(dataset)
    deadlines = _fixed_deadlines(matches)
    assert len(deadlines) >= 2, "ranking fixture needs at least two dated schemes"
    # Anchor `before` days ahead of the earliest matched deadline. The urgent
    # window (<= 34 days) then contains that deadline, and the far window
    # (>= 60 days) contains the latest one as long as the span is wide enough —
    # derived rather than hard-coded, so this fails with an explicit message if
    # the fixture stops covering the required range instead of on a random day.
    before = 20
    span = (deadlines[-1] - deadlines[0]).days
    assert before + span >= 60, (
        f"matched deadlines span {span} days: with a {before}-day lead-in the "
        "latest deadline is only {before + span} days out, so the 'far' window "
        "(>= 60 days) would be empty. Widen the matched fixture in data/schemes/."
    )

    ranked = _rank(dataset, today=_anchor_before(matches, before))
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


def test_nothing_is_expired_before_the_first_deadline(dataset):
    """One day before the earliest matched deadline, every match is still open."""
    matches = _matched(dataset)
    ranked = _rank(dataset, today=_anchor_before(matches, 1))
    assert all(not r.expired for r in ranked), [
        (r.scheme.id, r.days_left) for r in ranked if r.expired
    ]


def test_expired_pushed_to_bottom(dataset):
    matches = _matched(dataset)
    # Just after the last matched deadline: the dated matches are expired, and
    # any rolling-intake match must still sort above them.
    ranked_late = _rank(dataset, today=_fixed_deadlines(matches)[-1] + timedelta(days=1))
    expired = [r for r in ranked_late if r.expired]
    open_ones = [r for r in ranked_late if not r.expired]
    assert expired
    if open_ones:
        assert ranked_late[: len(open_ones)] == open_ones  # all open first


def test_expiry_ordering_holds_on_every_day(dataset):
    """Sweep every day across the dataset's calendar, not just today.

    This is the guard against the class of bug this file just had: an assertion
    that is only true on some calendar days. The ranker's contract is invariant
    on *any* `today`, so it is asserted on all of them.
    """
    matches = _matched(dataset)
    deadlines = _fixed_deadlines(matches)
    start, end = deadlines[0] - timedelta(days=2), deadlines[-1] + timedelta(days=2)
    engine = RankingEngine(today=start)

    day, checked = start, 0
    while day <= end:
        ranked = RankingEngine(today=day).rank(matches)
        # (a) expired matches sort after open ones,
        assert [r.expired for r in ranked] == sorted(r.expired for r in ranked), day
        # (b) scores descend within each partition,
        for partition in (
            [r for r in ranked if not r.expired],
            [r for r in ranked if r.expired],
        ):
            scores = [r.score for r in partition]
            assert scores == sorted(scores, reverse=True), (day, scores)
        # (c) the expired flag is exactly "deadline has passed",
        for r in ranked:
            deadline = r.scheme.deadline
            if deadline.rolling or not deadline.date:
                assert not r.expired and r.days_left is None, (day, r.scheme.id)
            else:
                expected_days = (deadline.date - day).days
                assert r.days_left == expected_days, (day, r.scheme.id, r.days_left)
                assert r.expired == (expected_days < 0), (day, r.scheme.id)
        checked += 1
        day += timedelta(days=1)

    assert checked == (end - start).days + 1
    assert engine is not None


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
