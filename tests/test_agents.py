"""Agent automations: dataset verification agent + reminder scheduler."""

from __future__ import annotations

import json

import agents.reminder_scheduler as scheduler
from agents.verify_dataset import run as verify_run
from backend.services.tracker import STATUSES, TrackerStore


def test_dataset_agent_offline_is_healthy():
    code, report = verify_run(check_urls=False)
    assert code == 0
    assert report["schemes"] >= 20
    assert report["errors"] == []
    assert report["status"] in ("ok", "warn")


class TestReminderScheduler:
    def _seed(self, tmp_path):
        path = tmp_path / "tracker.json"
        board = {
            "sess-agent": {
                "__profile__": {"profile": {
                    "domicile_state": "West Bengal",
                    "category": "general",
                    "annual_family_income": 200000,
                    "course_level": "ug",
                    "gender": "female",
                    "is_minority": True,
                    "minority_community": "muslim",
                    "last_exam_percentage": 82,
                }},
                "aikyashree-wb": {"status": "saved", "updated_at": "2026-09-27T10:00:00+00:00"},
            }
        }
        path.write_text(json.dumps(board))
        return path

    def test_scheduler_builds_and_dispatches_dry(self, tmp_path, monkeypatch):
        store_path = self._seed(tmp_path)
        monkeypatch.setattr(scheduler, "TrackerStore", lambda: TrackerStore(store_path))
        summary = scheduler.run(dry_run=True, jump_days=0)
        assert summary["sessions"] == 1
        assert summary["reminders_built"] >= 1

    def test_scheduler_jump_simulates_future(self, tmp_path, monkeypatch):
        store_path = self._seed(tmp_path)
        monkeypatch.setattr(scheduler, "TrackerStore", lambda: TrackerStore(store_path))
        near = scheduler.run(dry_run=True, jump_days=0)
        future = scheduler.run(dry_run=True, jump_days=20)  # within the 30d urgency window
        assert future["sessions"] == near["sessions"] == 1

    def test_empty_store_noop(self, tmp_path, monkeypatch):
        path = tmp_path / "empty.json"
        monkeypatch.setattr(scheduler, "TrackerStore", lambda: TrackerStore(path))
        summary = scheduler.run(dry_run=True)
        assert summary["sessions"] == 0
        assert summary["dispatched"] == 0


def test_statuses_order_documented():
    assert STATUSES.index("saved") < STATUSES.index("applied")
    assert STATUSES[-2:] == ["approved", "rejected"]


def test_url_check_reports_unreachable_sources_instead_of_raising():
    """The scheduled liveness job must survive a hostile network.

    Verified against the real world during development: with every external host
    blocked, `--check-urls` reported each source as `url_unreachable` and exited
    0 — no traceback, no crash. A CI job that dies loudly when a portal is down
    is a job somebody disables, so the contract is "report, do not raise".
    """
    from agents.verify_dataset import check_url

    # RFC 2606 reserves .invalid: resolution fails immediately, offline or not.
    ok, detail = check_url("https://feefix-does-not-exist.invalid/apply", timeout=5)
    assert ok is False
    assert isinstance(detail, str) and detail, "an unreachable URL must say why"
    assert "Traceback" not in detail


def test_url_check_rejects_non_http_schemes():
    """A data:/file:/gopher: URL must never be fetched (scheme pin)."""
    from agents.verify_dataset import check_url

    for url in ("file:///etc/passwd", "gopher://example.com", "ftp://example.com/x"):
        ok, detail = check_url(url, timeout=5)
        assert ok is False, f"{url} was fetched"
        assert "scheme" in detail.lower() or "unsupported" in detail.lower(), detail
