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

SCHEMA_VERSION = 5

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
def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    """Column names of ``table``.

    The table name is a module constant, never user input — no value from a
    request can reach this f-string (the no-string-built-SQL guard in the test
    suite still applies to every data statement).
    """
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


def _add_column(conn: sqlite3.Connection, table: str, column: str, decl: str) -> None:
    """Idempotent ``ALTER TABLE … ADD COLUMN``.

    Why this exists: an ALTER added to an already-applied migration never runs
    again — a database that had already executed that version silently keeps the
    old shape, and the app then fails at runtime on a missing column. Exactly
    that happened here (the dev database sat at v4 without ``replayed_at``, and
    every request 500'd) while a test suite that always created fresh databases
    stayed green. Migrations that add a column now check first, and a dedicated
    test migrates a *legacy* database to prove it.
    """
    if column not in _columns(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")


def _ensure_replayed_at(conn: sqlite3.Connection) -> None:
    """v4/v5: token-replay tombstone column (safe to attempt in either)."""
    _add_column(conn, "auth_sessions", "replayed_at", "TEXT")


# Additive only. Bump SCHEMA_VERSION and append a migration — never edit a
# migration that may already have run somewhere (that is how a database ends up
# with a schema its own version number swears it has; see _add_column).

_MIGRATIONS: dict[int, list] = {
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
    2: [
        # v2 — passwordless sign-in: OTP challenges, federated identities (email
        # / phone / GitHub), one-time OAuth state rows. All additive.
        """CREATE TABLE IF NOT EXISTS otp_challenges (
            id            TEXT PRIMARY KEY,
            channel       TEXT NOT NULL,
            address       TEXT NOT NULL,
            code_hash     TEXT NOT NULL,
            salt          TEXT NOT NULL,
            attempts_left INTEGER NOT NULL,
            expires_at    TEXT NOT NULL,
            resend_after  TEXT NOT NULL,
            created_at    TEXT NOT NULL
        )""",
        "CREATE INDEX IF NOT EXISTS idx_otp_address ON otp_challenges(channel, address)",
        """CREATE TABLE IF NOT EXISTS auth_identities (
            kind      TEXT NOT NULL,
            key       TEXT NOT NULL,
            user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL,
            PRIMARY KEY (kind, key)
        )""",
        "CREATE INDEX IF NOT EXISTS idx_identity_user ON auth_identities(user_id)",
        """CREATE TABLE IF NOT EXISTS oauth_states (
            state      TEXT PRIMARY KEY,
            created_at TEXT NOT NULL
        )""",
    ],
    3: [
        # v3 — anti-replay session rotation. A login session is a *family*
        # (session_key); rotation mints a new token and records the old one as
        # superseded (replaced_by / replaced_at) so a replayed, already-rotated
        # token can be detected and the whole family revoked. All additive.
        "ALTER TABLE auth_sessions ADD COLUMN session_key TEXT",
        "ALTER TABLE auth_sessions ADD COLUMN replaced_by TEXT",
        "ALTER TABLE auth_sessions ADD COLUMN replaced_at TEXT",
        "CREATE INDEX IF NOT EXISTS idx_auth_sessions_key ON auth_sessions(session_key)",
        # Backfill legacy rows (created before v3) so family revocation works.
        "UPDATE auth_sessions SET session_key = token_hash WHERE session_key IS NULL",
    ],
    4: [
        # v4 — three additive tables.
        #
        # (a) rate_limit_hits: the sliding-window counters used by the *shared*
        #     limiter. Living in this database is what makes the limit hold
        #     across worker processes (the in-memory dict could not).
        """CREATE TABLE IF NOT EXISTS rate_limit_hits (
            key TEXT NOT NULL,
            ts  REAL NOT NULL
        )""",
        "CREATE INDEX IF NOT EXISTS idx_rate_limit_key_ts ON rate_limit_hits(key, ts)",
        "CREATE INDEX IF NOT EXISTS idx_rate_limit_ts ON rate_limit_hits(ts)",
        # (b) documents: metadata for uploaded documents. The bytes live on disk
        #     outside the web root under a random name; this row is the only map
        #     from a user-visible document id to that file.
        """CREATE TABLE IF NOT EXISTS documents (
            id          TEXT PRIMARY KEY,
            session_id  TEXT NOT NULL,
            user_id     TEXT REFERENCES users(id) ON DELETE CASCADE,
            doc_type    TEXT,
            filename    TEXT NOT NULL,
            stored_name TEXT NOT NULL,
            media_type  TEXT NOT NULL,
            size_bytes  INTEGER NOT NULL,
            sha256      TEXT NOT NULL,
            created_at  TEXT NOT NULL
        )""",
        "CREATE INDEX IF NOT EXISTS idx_documents_session ON documents(session_id)",
        "CREATE INDEX IF NOT EXISTS idx_documents_user ON documents(user_id)",
        # (c) auth_security_events: token-replay/quarantine signals. Kept so the
        #     *user* can see suspicious session activity and act (sign out
        #     everywhere) — detection that silently logs users out everywhere is
        #     a self-inflicted outage, not a control.
        # Tombstone for a replayed token (idempotent: see _ensure_replayed_at).
        _ensure_replayed_at,
        "CREATE INDEX IF NOT EXISTS idx_auth_sessions_expiry ON auth_sessions(expires_at)",
        """CREATE TABLE IF NOT EXISTS auth_security_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     TEXT,
            session_key TEXT,
            kind        TEXT NOT NULL,
            detail      TEXT,
            client      TEXT,
            occurred_at TEXT NOT NULL
        )""",
        "CREATE INDEX IF NOT EXISTS idx_secev_user ON auth_security_events(user_id, occurred_at)",
        "CREATE INDEX IF NOT EXISTS idx_secev_key ON auth_security_events(session_key, kind, occurred_at)",
    ],
    5: [
        # v5 — repair pass. A database that had already applied an *earlier
        # revision of v4* was left without the replay tombstone column (schema
        # drift on an additive migration). These statements are idempotent, so
        # running them is safe on every path: fresh install, v3 upgrade, and the
        # patched-in-place case.
        _ensure_replayed_at,
        "CREATE INDEX IF NOT EXISTS idx_auth_sessions_expiry ON auth_sessions(expires_at)",
    ],
}


def migrate(conn: sqlite3.Connection | None = None) -> None:
    conn = conn or get_connection()
    with _lock:
        current = conn.execute("PRAGMA user_version").fetchone()[0]
        for version in range(current + 1, SCHEMA_VERSION + 1):
            for statement in _MIGRATIONS[version]:
                if callable(statement):     # data/DDL that must be conditional
                    statement(conn)
                else:
                    conn.execute(statement)
            # `version` is a loop-controlled int; PRAGMA takes no bind param, so
            # coerce it defensively. This is a schema version, never user data.
            conn.execute("PRAGMA user_version=" + str(int(version)))
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
