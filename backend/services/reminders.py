"""Reminder center — turns matches + tracker state into *actions*.

A reminder is never a bare notification; it is a next step: what is closing,
which document to gather, which application to finish, which result to check.
"""

from __future__ import annotations

from datetime import date, datetime

from backend.matching_engine.ranker import RankedMatch
from backend.models.scheme import Scheme

CLOSING_SOON_DAYS = 30
DEADLINE_TYPES = ("deadline", "docs", "finish", "track", "result")


def _iso(d: date | None) -> str | None:
    return d.isoformat() if d else None


def build_reminders(
    ranked: list[RankedMatch],
    board: dict[str, dict],
    today: date | None = None,
) -> list[dict]:
    today = today or date.today()
    reminders: list[dict] = []

    ranked_by_id = {r.scheme.id: r for r in ranked}
    tracked_ids = set(board)

    for r in ranked:
        scheme = r.scheme
        entry = board.get(scheme.id)
        status = entry["status"] if entry else None
        days = r.days_left
        deadline = scheme.deadline.date

        # Un-tracked urgent matches: "you found it, now act" nudge.
        if status is None and days is not None and 0 <= days <= CLOSING_SOON_DAYS:
            reminders.append({
                "type": "deadline",
                "severity": "high" if days <= 14 else "medium",
                "scheme_id": scheme.id,
                "scheme_name": scheme.name,
                "due_date": _iso(deadline),
                "days_left": days,
                "message": (
                    f"{scheme.name} closes in {days} day{'s' if days != 1 else ''}. "
                    "Save it to your tracker and start the application today."
                ),
            })

        # Saved / planning with a live deadline.
        if status in ("saved", "planning") and not r.expired and days is not None:
            if days <= CLOSING_SOON_DAYS:
                reminders.append({
                    "type": "finish",
                    "severity": "high" if days <= 14 else "medium",
                    "scheme_id": scheme.id,
                    "scheme_name": scheme.name,
                    "due_date": _iso(deadline),
                    "days_left": days,
                    "message": (
                        f"You saved {scheme.name} — {days} day"
                        f"{'s' if days != 1 else ''} left to submit. "
                        "Complete the portal application and institute verification."
                    ),
                })
            if scheme.documents and days <= 45:
                reminders.append({
                    "type": "docs",
                    "severity": "medium",
                    "scheme_id": scheme.id,
                    "scheme_name": scheme.name,
                    "due_date": _iso(deadline),
                    "days_left": days,
                    "message": (
                        f"Gather documents for {scheme.name}: "
                        + ", ".join(scheme.documents[:3])
                        + ("…" if len(scheme.documents) > 3 else ".")
                    ),
                })

        # Applied but not closed — follow-up discipline.
        if status in ("applied", "under_review"):
            reminders.append({
                "type": "track",
                "severity": "low",
                "scheme_id": scheme.id,
                "scheme_name": scheme.name,
                "due_date": _iso(deadline),
                "days_left": days,
                "message": (
                    f"Track your {scheme.name} application status on "
                    f"{scheme.application.portal or 'the official portal'} and keep "
                    "the acknowledgement safe."
                ),
            })

        # Saving closed matches: protect the student from false hope.
        if status in ("saved", "planning") and r.expired:
            reminders.append({
                "type": "deadline",
                "severity": "low",
                "scheme_id": scheme.id,
                "scheme_name": scheme.name,
                "due_date": _iso(deadline),
                "days_left": days,
                "message": (
                    f"The current window for {scheme.name} has closed. Keep it "
                    "tracked — most schemes reopen in the next cycle."
                ),
            })

    # Saved schemes outside the current match set (profile changed).
    for scheme_id in tracked_ids - set(ranked_by_id):
        reminders.append({
            "type": "result",
            "severity": "low",
            "scheme_id": scheme_id,
            "scheme_name": scheme_id,
            "due_date": None,
            "days_left": None,
            "message": (
                "One of your tracked schemes no longer matches your current "
                "profile — re-run the matcher to review."
            ),
        })

    order = {"high": 0, "medium": 1, "low": 2}
    reminders.sort(
        key=lambda r: (
            order.get(r["severity"], 3),
            r["days_left"] if r["days_left"] is not None else 9999,
        )
    )
    return reminders


def next_deadline(schemes: list[Scheme], today: date | None = None) -> dict | None:
    """Smallest future deadline across a scheme set — used by dashboards."""
    today = today or date.today()
    candidates = [
        (s.deadline.date, s)
        for s in schemes
        if s.deadline.date and s.deadline.date >= today
    ]
    if not candidates:
        return None
    deadline, scheme = min(candidates, key=lambda x: x[0])
    return {
        "scheme_id": scheme.id,
        "scheme_name": scheme.name,
        "date": _iso(deadline),
        "days_left": (deadline - today).days,
    }
