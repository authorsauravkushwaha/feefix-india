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

SCHEMA_VERSION = 3

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
        # v3 — the hardening pass. All additive: existing rows keep working and
        # every new column is nullable or defaulted, so an old client/process
        # reading this schema cannot fail.
        #
        # absolute_expires_at: caps the rolling idle window. Without it a stolen
        #   token used once a month never expires.
        # client_fp: SHA-256 of the creating user agent. A token replayed from a
        #   different client is revoked. A digest, never the raw UA (PII).
        "ALTER TABLE auth_sessions ADD COLUMN absolute_expires_at TEXT",
        "ALTER TABLE auth_sessions ADD COLUMN client_fp TEXT",
        # locked_until: credential-stuffing lockout, set only when failures on
        #   one account arrive from several distinct IPs (see services/auth.py).
        "ALTER TABLE users ADD COLUMN locked_until TEXT",
        "ALTER TABLE users ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0",
        # Lockout evidence. Rows are swept on a time window, so this table
        # cannot grow without bound.
        """CREATE TABLE IF NOT EXISTS login_failures (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            ip_hash     TEXT NOT NULL,
            occurred_at TEXT NOT NULL
        )""",
        "CREATE INDEX IF NOT EXISTS idx_login_failures_user ON login_failures(user_id, occurred_at)",
        # Chat conversations are keyed on a client-supplied id. Ownership is
        # recorded so one caller cannot resume another's conversation by naming
        # its id — the same IDOR shape as session_id, one level up.
        """CREATE TABLE IF NOT EXISTS chat_sessions (
            chat_id    TEXT PRIMARY KEY,
            owner_id   TEXT,
            owner_fp   TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_seen  TEXT NOT NULL
        )""",
        "CREATE INDEX IF NOT EXISTS idx_chat_sessions_seen ON chat_sessions(last_seen)",
    ],
}


def migrate(conn: sqlite3.Connection | None = None) -> None:
    """Apply pending migrations, in order, exactly once each.

    ``PRAGMA user_version`` is the ledger. Additive-only is a rule, not a
    preference: a destructive migration would silently delete student records,
    and there is no rollback path on a free-tier SQLite deployment.

    ``ALTER TABLE … ADD COLUMN`` is idempotent-tolerant on purpose. If a
    previous run was killed between the ALTER and the version bump, the column
    already exists; treating that as fatal would make the service unbootable,
    which is a self-inflicted denial of service.
    """
    conn = conn or get_connection()
    with _lock:
        current = conn.execute("PRAGMA user_version").fetchone()[0]
        for version in range(current + 1, SCHEMA_VERSION + 1):
            for statement in _MIGRATIONS[version]:
                try:
                    conn.execute(statement)
                except sqlite3.OperationalError as exc:
                    if "duplicate column name" in str(exc).lower():
                        continue
                    raise
            # ``PRAGMA user_version`` takes a literal, not a bind parameter —
            # this is the one place in the codebase that interpolates into SQL,
            # and the value is an int from a hard-coded range() above.
            conn.execute(f"PRAGMA user_version={int(version)}")
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
