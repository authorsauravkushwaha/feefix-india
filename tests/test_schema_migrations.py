"""Schema migrations must survive real deployments: concurrency, crashes, reruns.

These are the failure modes that only appear when more than one thing happens at
once, which is exactly what a single-process test suite never sees:

* two Render instances (or ``--workers 2``) booting simultaneously against one
  database — the loser used to die with ``duplicate column name`` and the deploy
  crash-looped;
* a database where an earlier crash applied part of a migration (SQLite's legacy
  autocommit ran DDL statement-by-statement) — the next boot must heal it rather
  than brick;
* a failing migration must roll back completely, not leave half a schema behind.

The distributed rate-limit suite caught the first one end to end; this file
pins the mechanism so it cannot come back.
"""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from backend.services import db as dbmod

REPO = Path(__file__).resolve().parents[1]


def _fresh_conn(path: Path) -> sqlite3.Connection:
    return dbmod._connect(path)


def _user_version(conn: sqlite3.Connection) -> int:
    return int(conn.execute("PRAGMA user_version").fetchone()[0])


def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


# --------------------------------------------------------------------------- #
# concurrency: the boot race
# --------------------------------------------------------------------------- #
def test_many_processes_migrating_one_new_database_all_succeed(tmp_path):
    """Eight processes booting on an empty DB: all must exit 0 (no crash loop).

    CI's flake-watch gate caught a real one here: one process in eight died with
    ``sqlite3.OperationalError: database is locked`` at the *journal-mode*
    switch, because the busy handler was installed after it (reproduced locally
    at roughly 1 run in 6). In production that is a crash-looping deploy when
    two instances start together against a fresh volume.
    """
    target = tmp_path / "shared.db"
    script = textwrap.dedent(
        """
        import os, sys
        os.environ["FEEFIX_DB"] = sys.argv[1]
        from backend.services import db
        db.migrate()
        print(db.get_connection().execute("PRAGMA user_version").fetchone()[0])
        """
    )
    env = {**os.environ, "FEEFIX_AI_BACKEND": "ngram"}
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", script, str(target)],
            cwd=REPO,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(8)
    ]
    failures = []
    for proc in procs:
        out, err = proc.communicate(timeout=120)
        if proc.returncode != 0:
            failures.append(f"rc={proc.returncode}\n{err[-1500:]}")

    assert not failures, "concurrent migration crashed:\n" + "\n".join(failures)

    conn = _fresh_conn(target)
    assert _user_version(conn) == dbmod.SCHEMA_VERSION
    assert "session_key" in _columns(conn, "auth_sessions")
    conn.close()


def test_migrate_is_idempotent_across_connections(tmp_path):
    """Re-running migrations on a current database is a no-op, not an error."""
    target = tmp_path / "again.db"
    first = _fresh_conn(target)
    dbmod.migrate(first)
    version = _user_version(first)
    columns = _columns(first, "auth_sessions")
    first.close()

    second = _fresh_conn(target)
    dbmod.migrate(second)  # must not raise "duplicate column name"
    assert _user_version(second) == version == dbmod.SCHEMA_VERSION
    assert _columns(second, "auth_sessions") == columns
    second.close()


# --------------------------------------------------------------------------- #
# crash recovery: half-applied migrations
# --------------------------------------------------------------------------- #
def test_half_applied_migration_self_heals(tmp_path):
    """Column added but version not bumped (an old crash) must not brick boot."""
    target = tmp_path / "poisoned.db"
    conn = _fresh_conn(target)
    dbmod.migrate(conn)
    conn.close()

    # Reproduce the poisoned state: everything applied, version rolled back.
    conn = _fresh_conn(target)
    conn.execute("PRAGMA user_version=2")
    conn.commit()
    assert _user_version(conn) == 2

    dbmod.migrate(conn)  # the ALTER TABLEs are skipped, not re-run
    assert _user_version(conn) == dbmod.SCHEMA_VERSION
    assert "replaced_by" in _columns(conn, "auth_sessions")
    conn.close()


def test_failing_migration_rolls_back_completely(tmp_path, monkeypatch):
    """DDL is transactional here: a broken migration leaves no half schema."""
    target = tmp_path / "atomic.db"
    conn = _fresh_conn(target)
    dbmod.migrate(conn)
    before = _user_version(conn)

    monkeypatch.setattr(dbmod, "SCHEMA_VERSION", before + 1)
    monkeypatch.setitem(
        dbmod._MIGRATIONS,
        before + 1,
        [
            "CREATE TABLE migration_probe (id INTEGER PRIMARY KEY)",
            "THIS STATEMENT IS NOT VALID SQL",
        ],
    )
    with pytest.raises(sqlite3.OperationalError):
        dbmod.migrate(conn)

    assert _user_version(conn) == before, "version bumped despite failure"
    tables = {
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    assert "migration_probe" not in tables, "partial migration was committed"
    assert conn.in_transaction is False
    conn.close()


def test_alter_helper_skips_existing_columns_and_runs_new_ones(tmp_path):
    """The guard is precise: skip what exists, still apply what does not."""
    conn = _fresh_conn(tmp_path / "guard.db")
    dbmod.migrate(conn)

    dbmod._apply(conn, "ALTER TABLE auth_sessions ADD COLUMN session_key TEXT")  # no-op
    assert "session_key" in _columns(conn, "auth_sessions")

    dbmod._apply(conn, "ALTER TABLE auth_sessions ADD COLUMN probe_col TEXT")
    assert "probe_col" in _columns(conn, "auth_sessions")
    conn.close()


def test_schema_version_matches_the_migration_table():
    """A version bump without statements (or vice versa) would loop or skip."""
    assert set(dbmod._MIGRATIONS) == set(range(1, dbmod.SCHEMA_VERSION + 1))
    for version, statements in dbmod._MIGRATIONS.items():
        assert statements, f"migration {version} is empty"


# --------------------------------------------------------------------------- #
# locking: a concurrent opener must wait, not crash
# --------------------------------------------------------------------------- #
def _rollback_journal_database(path: Path) -> None:
    """A small, non-WAL database — the state a brand-new deploy is in."""
    import sqlite3 as raw_sqlite

    conn = raw_sqlite.connect(str(path))
    conn.execute("CREATE TABLE seed (x INTEGER)")
    conn.execute("INSERT INTO seed VALUES (1)")
    conn.commit()
    assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() != "wal"
    conn.close()


#: Opens the database and holds an EXCLUSIVE lock until it is killed.
#: A subprocess (not a thread) because sqlite3 connections are thread-affine,
#: and not a Timer because the lock must be released from a *different* process
#: while the parent is blocked inside connect().
_LOCK_HOLDER = """
import sqlite3, sys, time
conn = sqlite3.connect(sys.argv[1], isolation_level=None)
conn.execute("BEGIN EXCLUSIVE")
print("locked", flush=True)
time.sleep(float(sys.argv[2]))
conn.rollback()
"""


def test_connect_raises_without_a_busy_handler(tmp_path):
    """The pre-fix behaviour, pinned: no handler → instant "database is locked"."""
    import sqlite3 as raw_sqlite

    target = tmp_path / "no-handler.db"
    _rollback_journal_database(target)

    holder = raw_sqlite.connect(str(target), isolation_level=None)
    holder.execute("BEGIN EXCLUSIVE")
    original = dbmod.BUSY_TIMEOUT_S
    dbmod.BUSY_TIMEOUT_S = 0.0
    try:
        with pytest.raises(sqlite3.OperationalError, match="locked|busy"):
            dbmod._connect(target)
    finally:
        dbmod.BUSY_TIMEOUT_S = original
        holder.rollback()
        holder.close()


def test_connect_waits_for_the_journal_mode_switch_instead_of_raising(tmp_path):
    """Deterministic version of the race that crashed a CI worker.

    A peer process holds an EXCLUSIVE lock on a fresh, non-WAL database — the
    exact state CI hit — and opening it must *wait* for the lock and then come
    up in WAL mode. Before the fix this raised immediately, which in production
    is a crash-looping deploy when two instances start together against a new
    volume.
    """
    import time

    target = tmp_path / "contended.db"
    _rollback_journal_database(target)

    holder = subprocess.Popen(
        [sys.executable, "-c", _LOCK_HOLDER, str(target), "1.5"],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert holder.stdout.readline().strip() == "locked", "holder did not take the lock"
        started = time.time()
        latecomer = dbmod._connect(target)  # must wait, not raise
        waited = time.time() - started
    finally:
        holder.wait(timeout=30)

    assert waited >= 0.3, f"did not wait for the lock (returned in {waited:.2f}s)"
    assert latecomer.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    assert latecomer.execute("SELECT count(*) FROM seed").fetchone()[0] == 1
    latecomer.close()


def test_wal_is_enabled_and_the_busy_timeout_is_configurable(tmp_path, monkeypatch):
    """The durability/behaviour guarantees the fix must not have softened."""
    conn = _fresh_conn(tmp_path / "wal.db")
    assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
    # The handler is installed up front with the configured value.
    assert conn.execute("PRAGMA busy_timeout").fetchone()[0] == int(
        dbmod.BUSY_TIMEOUT_S * 1000
    )
    conn.close()


def test_the_journal_mode_switch_retries_before_giving_up(tmp_path):
    """A transient lock is retried; a permanent failure is reported, not hidden."""
    calls = {"n": 0}
    real_connect = dbmod.sqlite3.connect

    class _Flaky:
        """Wraps a connection, refusing the WAL switch twice."""

        def __init__(self, inner):
            self._inner = inner

        def execute(self, sql, *args):
            if "journal_mode=WAL" in sql.replace(" ", ""):
                calls["n"] += 1
                if calls["n"] <= 2:
                    raise dbmod.sqlite3.OperationalError("database is locked")
            return self._inner.execute(sql, *args)

        def __getattr__(self, item):
            return getattr(self._inner, item)

    conn = real_connect(str(tmp_path / "retry.db"))
    try:
        dbmod._switch_to_wal(_Flaky(conn))
        assert calls["n"] == 3, f"expected two retries then success, saw {calls['n']}"
    finally:
        conn.close()
