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

import logging
import os
import re
import sqlite3
import threading
import time
from pathlib import Path

RUNTIME_DIR = Path(__file__).resolve().parents[2] / "runtime"
DEFAULT_DB = RUNTIME_DIR / "feefix.db"

SCHEMA_VERSION = 5

_lock = threading.RLock()
_conn: sqlite3.Connection | None = None

log = logging.getLogger("feefix.db")

#: Seconds any statement may wait for a lock held by another connection.
#: Installed *before* the first statement (see ``_connect``).
BUSY_TIMEOUT_S = float(os.environ.get("FEEFIX_DB_BUSY_TIMEOUT", "30") or 30)


def _switch_to_wal(conn: sqlite3.Connection, attempts: int = 6) -> None:
    """Put the database in WAL mode, waiting out a concurrent opener.

    Found by CI's flake-watch gate (and reproduced locally, ~1 run in 6 with
    eight concurrent openers): switching the journal mode needs a brief
    exclusive moment, and a peer that is opening the same **brand-new** file can
    hold it — raising ``database is locked``. In production that is a
    crash-looping deploy (two instances starting together against a fresh
    volume), not a flaky test. The busy handler now covers this call, and the
    switch additionally retries with a short backoff.
    """
    last_error: Exception | None = None
    for attempt in range(attempts):
        try:
            mode = str(conn.execute("PRAGMA journal_mode=WAL").fetchone()[0]).lower()
            if mode == "wal":
                return
            last_error = sqlite3.OperationalError(f"journal_mode is {mode!r}, not 'wal'")
        except sqlite3.OperationalError as exc:
            last_error = exc
            if "locked" not in str(exc).lower() and "busy" not in str(exc).lower():
                raise
        time.sleep(0.05 * (attempt + 1))
    # Some filesystems (network mounts, for example) cannot do WAL at all. That
    # is a degraded mode, not a reason to refuse to serve — say so loudly, and
    # never let the *reporting* of it become a second failure.
    try:
        where = conn.execute("PRAGMA database_list").fetchone()[2]
    except sqlite3.Error:  # pragma: no cover - reporting must not raise
        where = "<unknown>"
    log.warning("[db] could not enable WAL on %s: %s", where, last_error)


def _connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    # `timeout` installs SQLite's busy handler *before* any statement runs, so
    # the very first pragma waits for a concurrent writer instead of failing
    # instantly with "database is locked".
    conn = sqlite3.connect(str(path), check_same_thread=False, timeout=BUSY_TIMEOUT_S)
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout={int(BUSY_TIMEOUT_S * 1000)}")
    _switch_to_wal(conn)
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
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
        # v4 — replay handling that cannot log a user out of every device.
        # `fingerprint` records the client identity that created the session, so
        # a late same-device request can be told apart from a stolen-token
        # replay; `replay_strikes` counts replay observations per family and
        # only escalates to family revocation past a threshold. All additive.
        "ALTER TABLE auth_sessions ADD COLUMN fingerprint TEXT",
        "ALTER TABLE auth_sessions ADD COLUMN replay_strikes INTEGER NOT NULL DEFAULT 0",
    ],
    5: [
        # v5 — wired uploads: the hardened upload gate finally has a caller, so
        # its metadata needs a home. Stored bytes never live in the database;
        # this is metadata + ownership only. All additive.
        """CREATE TABLE IF NOT EXISTS uploads (
            id            TEXT PRIMARY KEY,
            session_id    TEXT NOT NULL,
            user_id       TEXT REFERENCES users(id) ON DELETE SET NULL,
            original_name TEXT,
            stored_name   TEXT NOT NULL,
            content_type  TEXT,
            kind          TEXT NOT NULL,
            size_bytes    INTEGER NOT NULL,
            sha256        TEXT NOT NULL,
            created_at    TEXT NOT NULL
        )""",
        "CREATE INDEX IF NOT EXISTS idx_uploads_session ON uploads(session_id)",
        "CREATE INDEX IF NOT EXISTS idx_uploads_user ON uploads(user_id)",
        # Long-form application notes. A legitimately large free-text field
        # (20 KB default) is exactly the input a one-size-fits-all body cap used
        # to reject — its own endpoint carries its own, larger body policy.
        """CREATE TABLE IF NOT EXISTS session_notes (
            session_id TEXT PRIMARY KEY,
            notes      TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )""",
    ],
}


# ``ALTER TABLE <t> ADD COLUMN <c> ...`` — the one DDL form SQLite cannot make
# conditional, so we check the live schema before running it. Identifiers come
# from ``_MIGRATIONS`` (module constants), never from a request.
_ALTER_ADD_COLUMN = re.compile(
    r"^\s*ALTER\s+TABLE\s+([A-Za-z_][A-Za-z0-9_]*)\s+ADD\s+COLUMN\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.IGNORECASE,
)


def _apply(conn: sqlite3.Connection, statement: str) -> None:
    """Run one migration statement, never failing because it already ran.

    Two situations used to be fatal and both are normal in production:

    * **Two instances booting at once** (Render scales out, or ``--workers 2``
      starts both at the same time). Without an up-front write lock both read
      ``user_version`` and race through the same ``ALTER TABLE`` — the loser
      died with *duplicate column name* and the deploy crash-looped.
    * **A half-applied migration** from an earlier crash. SQLite's legacy
      autocommit applied DDL statement-by-statement, so a DB could end up with
      the column added but ``user_version`` not bumped, poisoning every later
      boot. Checking the live schema heals that database instead of bricking it.
    """
    match = _ALTER_ADD_COLUMN.match(statement)
    if match:
        table, column = match.group(1), match.group(2)
        # `table` is a validated identifier from our own migration table.
        existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
        if column in existing:
            return
    conn.execute(statement)


def migrate(conn: sqlite3.Connection | None = None) -> None:
    """Apply pending migrations atomically and safely under concurrency."""
    conn = conn or get_connection()
    with _lock:
        # BEGIN IMMEDIATE takes the write lock *before* reading user_version, so
        # a second process waits here instead of running the same DDL behind us.
        # SQLite has no advisory locks; this is the equivalent for boot-time DDL.
        if conn.in_transaction:  # pragma: no cover - defensive
            conn.commit()
        conn.execute("BEGIN IMMEDIATE")
        try:
            current = conn.execute("PRAGMA user_version").fetchone()[0]
            for version in range(current + 1, SCHEMA_VERSION + 1):
                for statement in _MIGRATIONS[version]:
                    _apply(conn, statement)
                # `version` is a loop-controlled int; PRAGMA takes no bind param,
                # so coerce it defensively. A schema version, never user data.
                conn.execute("PRAGMA user_version=" + str(int(version)))
            conn.commit()
        except Exception:
            conn.rollback()
            raise


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
