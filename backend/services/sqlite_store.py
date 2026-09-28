"""SQLite-backed application store — same contract as the JSON TrackerStore.

Replaces the runtime JSON file with the hardened engine from
``backend.services.db`` (WAL mode, foreign keys, busy-timeout). All methods
are parameterized; nothing is ever string-interpolated into SQL.

Ownership: a session (the anonymous wizard session the web client carries)
can be *bound* to a user account on login — that is how a returning user
gets "their data is already there". Unbound sessions behave exactly like
before (privacy-by-design anonymous usage).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from backend.services import db
from backend.services.tracker import STATUSES

# Static protocol compatibility with backend.services.tracker.TrackerStore
scheme_entries = staticmethod(
    lambda board: {k: v for k, v in board.items() if not k.startswith("__")}
)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class SQLiteStore:
    def __init__(self, _path=None) -> None:
        # _path accepted for constructor-parity with the JSON store; the DB
        # location is governed by FEEFIX_DB.
        self.conn = db.get_connection()

    # -- tracker statuses ----------------------------------------------------
    def set_status(self, session_id: str, scheme_id: str, status: str | None) -> dict[str, dict]:
        with db._lock:
            if status is None:
                self.conn.execute(
                    "DELETE FROM tracker WHERE session_id=? AND scheme_id=?",
                    (session_id, scheme_id),
                )
            else:
                if status not in STATUSES:
                    raise ValueError(f"Invalid status: {status}")
                self.conn.execute(
                    "INSERT INTO tracker (session_id, scheme_id, status, updated_at)"
                    " VALUES (?,?,?,?)"
                    " ON CONFLICT(session_id, scheme_id) DO UPDATE SET"
                    "   status=excluded.status, updated_at=excluded.updated_at",
                    (session_id, scheme_id, status, _utcnow()),
                )
            self.conn.commit()
        return self.board(session_id)

    def board(self, session_id: str) -> dict[str, dict]:
        rows = self.conn.execute(
            "SELECT scheme_id, status, updated_at FROM tracker WHERE session_id=?",
            (session_id,),
        ).fetchall()
        return {
            r["scheme_id"]: {"status": r["status"], "updated_at": r["updated_at"]}
            for r in rows
        }

    # -- profiles --------------------------------------------------------------
    def save_profile(self, session_id: str, profile: dict) -> None:
        with db._lock:
            self.conn.execute(
                "INSERT INTO profiles (session_id, user_id, profile, updated_at)"
                " VALUES (?,?,?,?)"
                " ON CONFLICT(session_id) DO UPDATE SET"
                "   profile=excluded.profile, updated_at=excluded.updated_at",
                (session_id, None, json.dumps(profile), _utcnow()),
            )
            self.conn.commit()

    def load_profile(self, session_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT profile FROM profiles WHERE session_id=?", (session_id,)
        ).fetchone()
        return json.loads(row["profile"]) if row else None

    # -- ownership ---------------------------------------------------------------
    def bind_owner(self, session_id: str, user_id: str) -> None:
        """Attach an anonymous session's data to an account (login merge point)."""
        with db._lock:
            self.conn.execute(
                "INSERT INTO profiles (session_id, user_id, profile, updated_at)"
                " VALUES (?,?,?,?)"
                " ON CONFLICT(session_id) DO UPDATE SET user_id=excluded.user_id",
                (session_id, user_id, "{}", _utcnow()),
            )
            self.conn.commit()
        db.audit(user_id, "session.bind_owner", session_id)

    def owner_of(self, session_id: str) -> str | None:
        row = self.conn.execute(
            "SELECT user_id FROM profiles WHERE session_id=?", (session_id,)
        ).fetchone()
        return row["user_id"] if row and row["user_id"] else None

    def session_for_user(self, user_id: str) -> str | None:
        """The user's canonical session (most recently updated)."""
        row = self.conn.execute(
            "SELECT session_id FROM profiles WHERE user_id=?"
            " ORDER BY updated_at DESC LIMIT 1",
            (user_id,),
        ).fetchone()
        return row["session_id"] if row else None

    def export_user_data(self, user_id: str) -> dict:
        """Full data export for portability (user's own data, encrypted in transit)."""
        sessions = {
            sid: {
                "profile": self.load_profile(sid),
                "tracker": self.board(sid),
            }
            for (sid,) in [
                (r["session_id"],)
                for r in self.conn.execute(
                    "SELECT session_id FROM profiles WHERE user_id=?", (user_id,)
                ).fetchall()
            ]
        }
        events = [
            dict(r)
            for r in self.conn.execute(
                "SELECT session_id, scheme_id, type, occurred_at, context"
                " FROM outcome_events WHERE session_id IN"
                " (SELECT session_id FROM profiles WHERE user_id=?)",
                (user_id,),
            ).fetchall()
        ]
        return {"user_id": user_id, "sessions": sessions, "outcome_events": events}
