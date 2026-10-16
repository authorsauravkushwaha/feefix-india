"""The rate limiter under the topology the old suite could not see.

The old limiter kept a Python dict per process. Every test passed because every
test was single-process — the bug (limits multiply by N workers, and an attacker
spreads requests across replicas) was structurally invisible to the suite.

These tests run the limiter in **several real OS processes** against one shared
store and assert the aggregate limit still holds. They also assert the inverse
for the deliberately non-shared in-memory store, so if anyone switches the
default back to it, that regression is caught here instead of in production.
"""

from __future__ import annotations

import multiprocessing as mp
import time

import pytest

from backend.services import db, ratelimit

WORKERS = 4
ATTEMPTS_PER_WORKER = 30


def _hammer(backend: str, db_path: str, queue: mp.Queue, attempts: int) -> None:
    """Child process: fire auth attempts and report how many were admitted."""
    import os

    os.environ["FEEFIX_DB"] = db_path
    os.environ["FEEFIX_RATE_LIMIT_BACKEND"] = backend

    from backend.services import ratelimit as rl

    allowed = 0
    for _ in range(attempts):
        if rl.check_auth("203.0.113.7", "student@example.com"):
            allowed += 1
    queue.put(allowed)


def _run_workers(backend: str, db_path: str) -> int:
    ctx = mp.get_context("spawn")  # spawn = a genuinely fresh interpreter
    queue: mp.Queue = ctx.Queue()
    procs = [
        ctx.Process(target=_hammer, args=(backend, db_path, queue, ATTEMPTS_PER_WORKER))
        for _ in range(WORKERS)
    ]
    for proc in procs:
        proc.start()
    for proc in procs:
        proc.join(timeout=120)
        assert proc.exitcode == 0, f"worker exited with {proc.exitcode}"
    return sum(queue.get(timeout=30) for _ in procs)


@pytest.mark.slow
def test_shared_store_enforces_one_limit_across_processes(tmp_path, monkeypatch):
    """4 processes, 120 attempts, 10 allowed — the limit is NOT multiplied."""
    db_path = str(tmp_path / "shared.db")
    db.reset_for_tests(tmp_path / "shared.db")
    monkeypatch.setenv("FEEFIX_RATE_LIMIT_BACKEND", "sqlite")
    ratelimit.use_store(ratelimit.SQLiteStore())
    ratelimit.reset()

    total_allowed = _run_workers("sqlite", db_path)

    limit = ratelimit.AUTH_LIMIT[0]
    assert total_allowed == limit, (
        f"{WORKERS} workers admitted {total_allowed} attempts against a limit of {limit} "
        "— the store is not actually shared"
    )


@pytest.mark.slow
def test_memory_store_multiplies_the_limit_by_worker_count(tmp_path, monkeypatch):
    """Documents the failure mode the default was changed to avoid.

    This is not "expected behaviour to keep" — it is the reason the shared store
    is the default. If someone flips the default back, the test above fails and
    this one explains why.
    """
    db_path = str(tmp_path / "per-process.db")
    db.reset_for_tests(tmp_path / "per-process.db")
    monkeypatch.setenv("FEEFIX_RATE_LIMIT_BACKEND", "memory")

    total_allowed = _run_workers("memory", db_path)

    limit = ratelimit.AUTH_LIMIT[0]
    assert total_allowed == limit * WORKERS, (
        "the in-memory store unexpectedly shared state (or WORKERS changed): "
        f"got {total_allowed}, expected {limit * WORKERS}"
    )


def test_default_backend_is_shared(tmp_path, monkeypatch):
    db.reset_for_tests(tmp_path / "default.db")
    monkeypatch.delenv("FEEFIX_RATE_LIMIT_BACKEND", raising=False)
    monkeypatch.delenv("FEEFIX_REDIS_URL", raising=False)
    store = ratelimit.SQLiteStore()
    assert store.shared is True
    assert store.name == "sqlite"
    assert ratelimit._select_store().shared is True


def test_topology_warning_when_memory_store_meets_multiple_workers(monkeypatch, tmp_path):
    db.reset_for_tests(tmp_path / "warn.db")
    monkeypatch.setenv("FEEFIX_WEB_CONCURRENCY", "4")
    ratelimit.use_store(ratelimit.MemoryStore())
    warnings = ratelimit.topology_warnings()
    assert warnings and "4" in warnings[0] and "memory" in warnings[0]

    ratelimit.use_store(ratelimit.SQLiteStore())
    monkeypatch.delenv("FEEFIX_WEB_CONCURRENCY", raising=False)
    assert ratelimit.topology_warnings() == []
    ratelimit.use_store(ratelimit.SQLiteStore())


def test_retry_after_is_reported_from_the_shared_store(tmp_path):
    db.reset_for_tests(tmp_path / "retry.db")
    ratelimit.use_store(ratelimit.SQLiteStore())
    ratelimit.reset()
    ip = "198.51.100.4"
    for _ in range(ratelimit.AUTH_LIMIT[0]):
        assert ratelimit.check_auth(ip, "a@b.co")
    assert not ratelimit.check_auth(ip, "a@b.co")
    # A Retry-After hint derived from the *oldest* hit, computed in the store.
    assert 1 <= ratelimit.retry_after(ip, "auth:a@b.co") <= ratelimit.AUTH_LIMIT[1]


def test_spoofed_forwarded_for_cannot_evade_the_limiter(monkeypatch):
    """Only the rightmost XFF entries (appended by our own proxies) are trusted."""
    class _Req:
        headers = {"x-forwarded-for": "1.1.1.1, 2.2.2.2, 203.0.113.9"}
        client = type("C", (), {"host": "10.0.0.1"})()

    monkeypatch.delenv("FEEFIX_TRUST_PROXY", raising=False)
    monkeypatch.delenv("FEEFIX_TRUSTED_PROXY_COUNT", raising=False)
    # No trusted proxy configured → the header is ignored entirely.
    assert ratelimit.client_ip(_Req()) == "10.0.0.1"

    monkeypatch.setenv("FEEFIX_TRUSTED_PROXY_COUNT", "2")
    # Two trusted proxies ⇒ the real client is the second entry from the right;
    # a client-forged leftmost entry is not used.
    assert ratelimit.client_ip(_Req()) == "2.2.2.2"


def test_store_outage_degrades_loudly_and_can_fail_closed(monkeypatch, tmp_path):
    db.reset_for_tests(tmp_path / "outage.db")

    class _Broken(ratelimit.SQLiteStore):
        def hit(self, *a, **k):  # noqa: D102 - deliberate failure
            raise RuntimeError("store unreachable")

    monkeypatch.delenv("FEEFIX_RATELIMIT_FAIL_MODE", raising=False)
    ratelimit.use_store(_Broken())
    assert ratelimit.check_global("9.9.9.9") is True  # availability first…
    assert ratelimit.describe()["degraded_events"] >= 1  # …but never silently

    monkeypatch.setenv("FEEFIX_RATELIMIT_FAIL_MODE", "closed")
    assert ratelimit.check_global("9.9.9.9") is False  # …or refuse, if configured
    ratelimit.reset()
    ratelimit.use_store(ratelimit.SQLiteStore())


def test_counter_table_stays_bounded(tmp_path):
    """The DoS shield must not become a DoS vector (works for both stores)."""
    db.reset_for_tests(tmp_path / "bounded.db")
    memory = ratelimit.MemoryStore(max_keys=200)
    for index in range(500):
        memory.hit(f"k{index}", 5, 60, time.monotonic())
    assert memory.tracked() <= 200

    shared = ratelimit.SQLiteStore(max_keys=200)
    ratelimit.use_store(shared)
    ratelimit.reset()
    for index in range(300):
        shared.hit(f"k{index}", 5, 60, time.monotonic())
    assert shared.tracked() <= 250  # prunes to half the cap when it overflows
    ratelimit.reset()
    ratelimit.use_store(ratelimit.SQLiteStore())
