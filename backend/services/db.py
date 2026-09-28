"""FeeFix database engine — SQLite (WAL mode), zero-cost, zero-ops, production-hardened.

Why SQLite: it is the same database engine that powers most mobile apps and
is ACID, crash-safe and free. For scale-out, the store contract stays
SQL-shaped so the migration path to Postgres is a connection-string change
(documented in docs/deploy).

Integrity primitives (the *I* in CIA):
  * ``PRAGMA journal_mode=WAL``       — crash-safe concurrent reads
  * ``PRAGMA foreign_keys=ON``        — referential integrity enforced by the engine
  * additive ``PRAGMA user_version`` migrations — schema changes are versioned
  * every statement is parameterized — string-built SQL never occurs here
"""

from __future__ import annotations

import os
import sqlite3
import threading
from pathlib import Path

RUNTIME_DIR = Path(__file__).resolve().parents[2] / "runtime"
DEFAULT_DB = RUNTIME_DIR / "feefix.db"

SCHEMA_VERSION = 1

_lock = threading.RLock()
_conn: sqlite3.Connection | None = None


def _connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def get_connection() -> sqlite3.Connection:
    """Process-wide connection (thread-guarded). DB path via FEEFIX_DB env."""
    global _conn
    with _lock:
        if _conn is None:
            target = Path(os.environ.get("FEEFIX_DB", str(DEFAULT_DB)))
            _conn = _connect(target)
            migrate(_conn)
        return _conn


def reset_for_tests(path: Path) -> None:
    """Point the engine at a fresh database path (tests)."""
    global _conn
    with _lock:
        if _conn is not None:
            _conn.close()
        os.environ["FEEFIX_DB"] = str(path)
        _conn = _connect(path)
        migrate(_conn)


# -- migrations --------------------------------------------------------------
# Additive only. Bump SCHEMA_VERSION and append a migration.

_MIGRATIONS = {
    1: [
        """CREATE TABLE IF NOT EXISTS users (
            id            TEXT PRIMARY KEY,
            email         TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            name          TEXT,
            created_at    TEXT NOT NULL,
            updated_at    TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS auth_sessions (
            token_hash TEXT PRIMARY KEY,
            user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            last_seen  TEXT NOT NULL,
            client     TEXT
        )""",
        "CREATE INDEX IF NOT EXISTS idx_auth_sessions_user ON auth_sessions(user_id)",
        """CREATE TABLE IF NOT EXISTS profiles (
            session_id TEXT PRIMARY KEY,
            user_id    TEXT REFERENCES users(id) ON DELETE SET NULL,
            profile    TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )""",
        "CREATE INDEX IF NOT EXISTS idx_profiles_user ON profiles(user_id)",
        """CREATE TABLE IF NOT EXISTS tracker (
            session_id TEXT NOT NULL,
            scheme_id  TEXT NOT NULL,
            status     TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (session_id, scheme_id)
        )""",
        "CREATE INDEX IF NOT EXISTS idx_tracker_session ON tracker(session_id)",
        """CREATE TABLE IF NOT EXISTS outcome_events (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            scheme_id  TEXT NOT NULL,
            type       TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            context    TEXT
        )""",
        "CREATE INDEX IF NOT EXISTS idx_events_session ON outcome_events(session_id)",
        "CREATE INDEX IF NOT EXISTS idx_events_scheme ON outcome_events(scheme_id)",
        """CREATE TABLE IF NOT EXISTS audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            actor       TEXT,
            action      TEXT NOT NULL,
            detail      TEXT,
            occurred_at TEXT NOT NULL
        )""",
    ],
}


def migrate(conn: sqlite3.Connection | None = None) -> None:
    conn = conn or get_connection()
    with _lock:
        current = conn.execute("PRAGMA user_version").fetchone()[0]
        for version in range(current + 1, SCHEMA_VERSION + 1):
            for statement in _MIGRATIONS[version]:
                conn.execute(statement)
            conn.execute(f"PRAGMA user_version={version}")
        conn.commit()


def audit(actor: str | None, action: str, detail: str | None = None) -> None:
    """Append-only security audit trail (integrity pillar)."""
    from datetime import datetime, timezone

    conn = get_connection()
    with _lock:
        conn.execute(
            "INSERT INTO audit_log (actor, action, detail, occurred_at) VALUES (?,?,?,?)",
            (
                actor,
                action,
                detail,
                datetime.now(timezone.utc).isoformat(timespec="seconds"),
            ),
        )
        conn.commit()
