"""Application tracker — the student journey, persisted.

Status pipeline::

    saved → planning → applied → under_review → approved | rejected

Storage is a small JSON document keyed by an anonymous session id (the web
client generates one and keeps it in localStorage). Swapping this store for
Postgres later does not change the service contract.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path

STATUSES = [
    "saved",
    "planning",
    "applied",
    "under_review",
    "approved",
    "rejected",
]

RUNTIME_DIR = Path(__file__).resolve().parents[2] / "runtime"


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class TrackerStore:
    def __init__(self, path: Path | None = None):
        self.path = path or (RUNTIME_DIR / "tracker.json")
        self._lock = threading.Lock()
        self._data: dict[str, dict[str, dict]] = {}
        self._load()

    # -- persistence ---------------------------------------------------------
    def _load(self) -> None:
        if self.path.exists():
            try:
                self._data = json.loads(self.path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                self._data = {}

    def _persist(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
        tmp.replace(self.path)

    # -- public API -------------------------------------------------------------
    def set_status(
        self, session_id: str, scheme_id: str, status: str | None
    ) -> dict[str, dict]:
        """Set (or clear, status=None) the track status of a scheme."""
        with self._lock:
            board = self._data.setdefault(session_id, {})
            if status is None:
                board.pop(scheme_id, None)
            else:
                if status not in STATUSES:
                    raise ValueError(f"Invalid status: {status}")
                board[scheme_id] = {"status": status, "updated_at": _utcnow()}
            self._persist()
            return board

    def board(self, session_id: str) -> dict[str, dict]:
        with self._lock:
            return dict(self._data.get(session_id, {}))

    def save_profile(self, session_id: str, profile: dict, owner_id: str | None = None) -> None:
        """Persist a profile, stamping ownership on first write (write-once).

        Mirrors :meth:`SQLiteStore.save_profile`. Ownership lives under an
        ``__owner__`` key so the existing ``__``-prefix filtering keeps it out
        of tracker boards returned to clients.
        """
        with self._lock:
            board = self._data.setdefault(session_id, {})
            board["__profile__"] = {
                "profile": profile,
                "updated_at": _utcnow(),
            }
            if owner_id and not board.get("__owner__"):
                board["__owner__"] = owner_id
            self._persist()

    def claim_owner(self, session_id: str, owner_id: str | None) -> bool:
        if not owner_id:
            return False
        with self._lock:
            board = self._data.setdefault(session_id, {})
            existing = board.get("__owner__")
            if existing and existing != owner_id:
                return False
            board["__owner__"] = owner_id
            self._persist()
        return True

    def owner_of(self, session_id: str) -> str | None:
        with self._lock:
            return self._data.get(session_id, {}).get("__owner__")

    def has_data(self, session_id: str) -> bool:
        with self._lock:
            board = self._data.get(session_id, {})
            return bool(board.get("__profile__")) or any(
                not k.startswith("__") for k in board
            )

    def load_profile(self, session_id: str) -> dict | None:
        with self._lock:
            entry = self._data.get(session_id, {}).get("__profile__")
            return entry["profile"] if entry else None

    @staticmethod
    def scheme_entries(board: dict[str, dict]) -> dict[str, dict]:
        """Strip internal keys (like __profile__) from a board."""
        return {k: v for k, v in board.items() if not k.startswith("__")}
