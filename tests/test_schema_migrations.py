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
    """Four processes booting on an empty DB: all must exit 0 (no crash loop)."""
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
        for _ in range(4)
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
