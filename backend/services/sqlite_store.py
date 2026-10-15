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
    def save_profile(self, session_id: str, profile: dict, owner_id: str | None = None) -> None:
        """Persist a profile, stamping the caller's ownership on first write.

        THIS WAS THE ROOT CAUSE OF THE ACCOUNT-TAKEOVER BUG. The old signature
        inserted ``user_id=None`` unconditionally, so a *signed-in* student's
        data was written as though it were anonymous. ``owner_of`` then reported
        no owner, the authorisation gate correctly allowed anyone through (an
        unowned session is public by design), and any other authenticated user
        could call ``link-session`` to claim it — reading the victim's profile
        and locking the victim out of their own data with a 403.

        ``COALESCE(profiles.user_id, excluded.user_id)`` sets the owner on the
        first write and can never *change* it afterwards, so ownership is
        write-once at this layer too.
        """
        with db._lock:
            self.conn.execute(
                "INSERT INTO profiles (session_id, user_id, profile, updated_at)"
                " VALUES (?,?,?,?)"
                " ON CONFLICT(session_id) DO UPDATE SET"
                "   profile=excluded.profile, updated_at=excluded.updated_at,"
                "   user_id=COALESCE(profiles.user_id, excluded.user_id)",
                (session_id, owner_id, json.dumps(profile), _utcnow()),
            )
            self.conn.commit()

    def claim_owner(self, session_id: str, owner_id: str | None) -> bool:
        """Stamp ownership on an unowned session without writing profile data.

        Needed for tracker-only sessions: a signed-in student who saves a scheme
        before ever filling the wizard has tracker rows but no profile row, and
        without this their session would still look anonymous to the gate.
        Returns False (and audits) rather than transferring an existing owner.
        """
        if not owner_id:
            return False
        with db._lock:
            existing = self.conn.execute(
                "SELECT user_id FROM profiles WHERE session_id=?", (session_id,)
            ).fetchone()
            if existing is not None and existing["user_id"] and existing["user_id"] != owner_id:
                db.audit(owner_id, "session.claim_refused",
                         f"session={session_id} owner={existing['user_id']}")
                return False
            if existing is None:
                self.conn.execute(
                    "INSERT INTO profiles (session_id, user_id, profile, updated_at)"
                    " VALUES (?,?,?,?)",
                    (session_id, owner_id, "{}", _utcnow()),
                )
            else:
                self.conn.execute(
                    "UPDATE profiles SET user_id=COALESCE(user_id, ?) WHERE session_id=?",
                    (owner_id, session_id),
                )
            self.conn.commit()
        return True

    def load_profile(self, session_id: str) -> dict | None:
        row = self.conn.execute(
            "SELECT profile FROM profiles WHERE session_id=?", (session_id,)
        ).fetchone()
        return json.loads(row["profile"]) if row else None

    # -- ownership ---------------------------------------------------------------
    def bind_owner(self, session_id: str, user_id: str) -> bool:
        """Attach an anonymous session's data to an account (login merge point).

        Ownership is **write-once**. The previous implementation used
        ``ON CONFLICT(session_id) DO UPDATE SET user_id=excluded.user_id``,
        which overwrote an existing owner — so any authenticated caller could
        claim somebody else's session by naming its id, read their profile, and
        leave the real owner with a 403 on their own data. The route layer now
        refuses that case before getting here (:func:`authz.authorize_bind`);
        this is the second, independent gate, because a store that silently
        permits an ownership transfer will eventually be called by something
        that forgot to check.

        Returns True when the binding was applied, False when it was refused.
        """
        with db._lock:
            existing = self.conn.execute(
                "SELECT user_id FROM profiles WHERE session_id=?", (session_id,)
            ).fetchone()
            if existing is not None and existing["user_id"] and existing["user_id"] != user_id:
                db.audit(user_id, "session.bind_owner_refused",
                         f"session={session_id} owner={existing['user_id']}")
                return False
            if existing is None:
                self.conn.execute(
                    "INSERT INTO profiles (session_id, user_id, profile, updated_at)"
                    " VALUES (?,?,?,?)",
                    (session_id, user_id, "{}", _utcnow()),
                )
            else:
                self.conn.execute(
                    "UPDATE profiles SET user_id=? WHERE session_id=?",
                    (user_id, session_id),
                )
            self.conn.commit()
        db.audit(user_id, "session.bind_owner", session_id)
        return True

    def has_data(self, session_id: str) -> bool:
        """Does this session hold anything worth owning?

        Used by ``authz.authorize_bind(allow_claim=False)`` deployments to stop
        an account claiming an id that has never been used — the pre-claiming
        half of the takeover, where an attacker binds a session id *before* its
        real owner writes to it.
        """
        row = self.conn.execute(
            "SELECT profile FROM profiles WHERE session_id=?", (session_id,)
        ).fetchone()
        if row is not None and (row["profile"] or "").strip() not in ("", "{}"):
            return True
        tracked = self.conn.execute(
            "SELECT 1 FROM tracker WHERE session_id=? LIMIT 1", (session_id,)
        ).fetchone()
        return tracked is not None

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
