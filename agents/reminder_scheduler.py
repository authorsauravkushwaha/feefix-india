"""Reminder Scheduler Agent — cron-friendly dispatcher.

Walks every session's profile + tracker board, rebuilds reminders, and
dispatches due ones through the notification router. Designed to run from cron
without a server process::

    0 9 * * *  /opt/feefix/.venv/bin/python -m agents.reminder_scheduler

Use ``--dry-run`` to inspect what would be sent, and ``--jump N`` to simulate
the day N days ahead (useful for testing urgent-deadline behaviour with real
catalogue dates).
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date, timedelta
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from backend.matching_engine.ranker import RankingEngine  # noqa: E402
from backend.matching_engine.engine import EligibilityEngine  # noqa: E402
from backend.models.student import StudentProfile  # noqa: E402
from backend.notifications import (  # noqa: E402
    ConsoleNotifier,
    NotificationRouter,
    WhatsAppOutboxNotifier,
)
from backend.services.dataset import DatasetService  # noqa: E402
from backend.services.reminders import build_reminders  # noqa: E402
from backend.services.tracker import STATUSES, TrackerStore  # noqa: E402


def run(dry_run: bool = False, jump_days: int = 0, limit: int | None = None) -> dict:
    today = date.today() + timedelta(days=jump_days)
    ds = DatasetService()
    ds.load()
    tracker = TrackerStore()
    router = NotificationRouter([ConsoleNotifier(), WhatsAppOutboxNotifier()])

    store_path = tracker.path
    boards = json.loads(store_path.read_text()) if store_path.exists() else {}

    summary = {"date": today.isoformat(), "sessions": 0, "reminders_built": 0, "dispatched": 0}
    for session_id, raw in boards.items():
        profile_dict = raw.get("__profile__", {}).get("profile")
        if not profile_dict:
            continue
        summary["sessions"] += 1
        profile = StudentProfile(**profile_dict)
        engine = EligibilityEngine(ds.schemes)
        report = engine.match(profile)
        ranked = RankingEngine(today=today).rank(report.matches)
        board = {k: v for k, v in raw.items() if k in STATUSES or k in ds._by_id}
        board = {k: v for k, v in board.items() if not k.startswith("__")}
        reminders = build_reminders(ranked, board, today=today)
        summary["reminders_built"] += len(reminders)
        due = [r for r in reminders if r["severity"] == "high"]
        if not due:
            continue
        if dry_run:
            print(f"[dry-run] {session_id}: would dispatch {len(due)} high-severity reminder(s)")
            for r in due:
                print(f"          - {r['message'][:110]}")
            summary["dispatched"] += len(due)
        else:
            receipts = router.dispatch_reminders(session_id, due)
            delivered = sum(1 for x in receipts if x.get("delivered"))
            summary["dispatched"] += min(delivered, len(due))
            print(f"{session_id}: dispatched {len(due)} high-severity reminder(s)")
    print(f"== Reminder scheduler == sessions: {summary['sessions']} · "
          f"built: {summary['reminders_built']} · dispatched: {summary['dispatched']}")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FeeFix reminder scheduler agent")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--jump", type=int, default=0, help="simulate N days ahead")
    args = parser.parse_args()
    run(dry_run=args.dry_run, jump_days=args.jump)
