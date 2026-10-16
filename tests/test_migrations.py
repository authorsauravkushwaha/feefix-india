"""Schema migrations against databases that already exist.

The test suite creates a fresh database per test, which is exactly why it did
not notice this: a *running* deployment's database was already at schema v4, so
a later-added ``ALTER TABLE … ADD COLUMN`` never executed, and every request
500'd on a missing column while 300+ tests stayed green. Fresh-database tests
cannot see schema drift on an existing database, so these tests build one.

* a v3 database upgrades to the current version and works;
* a database stuck at an earlier revision of v4 (the real failure) is repaired;
* migrations are idempotent — running them twice changes nothing;
* the app boots and serves against a legacy database.
"""

from __future__ import annotations

import sqlite3

import pytest
from fastapi.testclient import TestClient

from backend.services import db


def _build_legacy(path, version: int) -> sqlite3.Connection:
    """Create a database as of ``version`` by replaying the migration list."""
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    for applied in range(1, version + 1):
        for statement in db._MIGRATIONS[applied]:
            if callable(statement):
                statement(conn)
            else:
                conn.execute(statement)
        conn.execute(f"PRAGMA user_version={applied}")
    conn.commit()
    return conn


@pytest.mark.parametrize("legacy_version", [1, 2, 3, 4])
def test_legacy_database_upgrades_to_the_current_schema(tmp_path, legacy_version):
    path = tmp_path / f"legacy-v{legacy_version}.db"
    conn = _build_legacy(path, legacy_version)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == legacy_version
    conn.close()

    db.reset_for_tests(path)          # opens + migrates
    migrated = db.get_connection()
    assert migrated.execute("PRAGMA user_version").fetchone()[0] == db.SCHEMA_VERSION
    for table, column in (
        ("auth_sessions", "replayed_at"),
        ("auth_sessions", "session_key"),
        ("rate_limit_hits", "key"),
        ("documents", "sha256"),
        ("auth_security_events", "kind"),
    ):
        assert column in db._columns(migrated, table), f"{table}.{column} missing after upgrade"


def test_a_database_left_at_an_earlier_v4_revision_is_repaired(tmp_path):
    """The exact state that broke a running server while tests stayed green."""
    path = tmp_path / "half-migrated.db"
    conn = _build_legacy(path, 4)
    conn.execute("ALTER TABLE auth_sessions DROP COLUMN replayed_at")
    conn.execute("PRAGMA user_version=4")
    conn.commit()
    assert "replayed_at" not in db._columns(conn, "auth_sessions")
    conn.close()

    db.reset_for_tests(path)
    assert "replayed_at" in db._columns(db.get_connection(), "auth_sessions")


def test_migrations_are_idempotent(tmp_path):
    path = tmp_path / "idempotent.db"
    db.reset_for_tests(path)
    conn = db.get_connection()
    before = {table: sorted(db._columns(conn, table))
              for table in ("auth_sessions", "users", "documents", "rate_limit_hits")}
    db.migrate(conn)   # a second run must not raise or change anything
    db.migrate(conn)
    after = {table: sorted(db._columns(conn, table)) for table in before}
    assert before == after


def test_app_serves_requests_against_a_legacy_database(tmp_path, monkeypatch):
    """Boot the real app on a v3 database: the drift must be invisible."""
    from backend.main import create_app

    path = tmp_path / "legacy-app.db"
    conn = _build_legacy(path, 3)
    conn.close()
    monkeypatch.setenv("FEEFIX_DB", str(path))
    db.reset_for_tests(path)

    client = TestClient(create_app())
    assert client.get("/api/health").status_code == 200
    token = client.post(
        "/api/auth/register", json={"email": "legacy@example.com", "password": "S3cure!Pass"}
    ).json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/auth/me", headers=headers).status_code == 200
    # The replay-tombstone column must be usable on the upgraded database.
    assert client.get("/api/auth/security-events", headers=headers).status_code == 200


def test_schema_version_is_documented_in_the_migration_table():
    assert db.SCHEMA_VERSION == max(db._MIGRATIONS)
    for version in range(1, db.SCHEMA_VERSION + 1):
        assert db._MIGRATIONS[version], f"migration {version} is empty"
