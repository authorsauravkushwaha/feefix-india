"""The multi-instance rate limiter — the path that had no coverage at all.

`RedisStore` is what a load-balanced deployment runs on, and until now it was
completely untested: the SQLite store covered "several processes on one host",
and the Redis branch was only exercised by a human reading it.

These tests drive the real Lua script through a fake Redis server (``fakeredis``
implements server-side Lua), so what is verified is the code that will actually
run against a real Redis: atomic prune→count→insert, the sliding window, the
retry hint, key expiry, and the prefix used for cleanup. Also covered: the
selection logic (auto/sqlite/redis/memory), the fallback when a configured Redis
is unreachable, and the fail-open/fail-closed behaviour on a store outage.
"""

from __future__ import annotations

import pytest

from backend.services import db, ratelimit

fakeredis = pytest.importorskip("fakeredis")


@pytest.fixture()
def redis_store(monkeypatch):
    """A RedisStore wired to an in-process fake Redis server."""
    client = fakeredis.FakeStrictRedis()
    monkeypatch.setattr(ratelimit.redis, "Redis", type("R", (), {"from_url": staticmethod(lambda *a, **k: client)}), raising=False)
    store = ratelimit.RedisStore("redis://fake:6379/0")
    yield store, client
    ratelimit.use_store(ratelimit.SQLiteStore())


def test_namespace_is_declared_and_matching(redis_store):
    assert ratelimit.redis.__name__ == "redis"
    assert isinstance(ratelimit._KEY_PREFIX, str) and ratelimit._KEY_PREFIX


def test_enforces_the_limit_atomically(redis_store):
    store, _client = redis_store
    allowed = 0
    for _ in range(25):
        ok, _retry = store.hit("1.2.3.4|global", 10, 60, 1000.0)
        allowed += bool(ok)
    assert allowed == 10, "the Lua script must admit exactly the limit"


def test_window_slides_with_time(redis_store):
    store, _client = redis_store
    for _ in range(10):
        assert store.hit("ip|auth:x", 10, 60, 1000.0)[0] is True
    assert store.hit("ip|auth:x", 10, 60, 1005.0)[0] is False   # still inside the window
    assert store.hit("ip|auth:x", 10, 60, 1061.0)[0] is True    # oldest hit aged out


def test_retry_hint_counts_down_with_the_window(redis_store):
    store, _client = redis_store
    for _ in range(5):
        store.hit("ip|global", 5, 60, 2000.0)
    retry = store.retry_after("ip|global", 60, 2000.0)
    assert 1 <= retry <= 61
    # A minute later the window is clear and there is nothing to wait for.
    assert store.retry_after("ip|global", 60, 2070.0) == 1


def test_buckets_are_isolated_per_key(redis_store):
    store, _client = redis_store
    for _ in range(10):
        store.hit("ipA|auth:x", 10, 60, 1000.0)
    assert store.hit("ipA|auth:x", 10, 60, 1000.0)[0] is False
    assert store.hit("ipB|auth:x", 10, 60, 1000.0)[0] is True
    assert store.hit("ipA|global", 10, 60, 1000.0)[0] is True


def test_keys_carry_a_ttl_so_redis_cannot_fill_up(redis_store):
    store, client = redis_store
    store.hit("ip|global", 5, 60, 1000.0)
    key = ratelimit._KEY_PREFIX + "ip|global"
    assert client.ttl(key) > 0, "a counter without an expiry is an unbounded key space"


def test_tracked_and_reset_use_the_prefix(redis_store):
    store, client = redis_store
    for index in range(20):
        store.hit(f"ip{index}|global", 5, 60, 1000.0)
    assert store.tracked() == 20
    store.reset()
    assert store.tracked() == 0
    # Unrelated keys are not ours to delete.
    client.set("someone-elses-key", "1")
    store.hit("ip|global", 5, 60, 1000.0)
    store.reset()
    assert client.get("someone-elses-key") == b"1"


def test_shared_flag_and_health_report(redis_store, monkeypatch):
    store, _client = redis_store
    assert store.shared is True
    monkeypatch.setenv("FEEFIX_RATE_LIMIT_BACKEND", "redis")
    ratelimit.use_store(store)
    report = ratelimit.describe()
    assert report["backend"] == "redis"
    assert report["shared_across_processes"] is True
    assert report["tracked_keys"] >= 0


# ------------------------------------------------------------------ selection
def test_redis_url_selects_the_redis_store(monkeypatch):
    client = fakeredis.FakeStrictRedis()
    monkeypatch.setenv("FEEFIX_REDIS_URL", "redis://fake:6379/0")
    monkeypatch.setattr(
        ratelimit.redis, "Redis",
        type("R", (), {"from_url": staticmethod(lambda *a, **k: client)}), raising=False,
    )
    store = ratelimit._select_store()
    assert isinstance(store, ratelimit.RedisStore)


def test_explicit_backend_selection(monkeypatch):
    monkeypatch.delenv("FEEFIX_REDIS_URL", raising=False)
    monkeypatch.setenv("FEEFIX_RATE_LIMIT_BACKEND", "memory")
    assert isinstance(ratelimit._select_store(), ratelimit.MemoryStore)
    monkeypatch.setenv("FEEFIX_RATE_LIMIT_BACKEND", "sqlite")
    assert isinstance(ratelimit._select_store(), ratelimit.SQLiteStore)
    monkeypatch.setenv("FEEFIX_RATE_LIMIT_BACKEND", "auto")
    assert isinstance(ratelimit._select_store(), ratelimit.SQLiteStore)


def test_unreachable_redis_falls_back_to_the_shared_store(monkeypatch, tmp_path):
    """A configured-but-down Redis must not take the service down or fail open."""
    db.reset_for_tests(tmp_path / "fallback.db")
    monkeypatch.setenv("FEEFIX_REDIS_URL", "redis://127.0.0.1:1/0")
    monkeypatch.setenv("FEEFIX_RATE_LIMIT_BACKEND", "auto")

    def explode(*_args, **_kwargs):
        raise ConnectionError("redis is down")

    monkeypatch.setattr(
        ratelimit.redis, "Redis",
        type("R", (), {"from_url": staticmethod(explode)}), raising=False,
    )
    store = ratelimit._select_store()
    assert isinstance(store, ratelimit.SQLiteStore), "must degrade to the shared SQLite store"
    assert store.shared is True


def test_redis_store_failure_is_counted_and_can_fail_closed(monkeypatch, tmp_path):
    db.reset_for_tests(tmp_path / "redis-outage.db")

    class _Broken(ratelimit.RedisStore):
        def __init__(self):  # noqa: D107 - no connection needed
            self.name = "redis"
            self.shared = True

        def hit(self, *_args, **_kwargs):
            raise ConnectionError("connection reset")

    monkeypatch.delenv("FEEFIX_RATELIMIT_FAIL_MODE", raising=False)
    ratelimit.use_store(_Broken())
    assert ratelimit.check_global("9.9.9.9") is True          # availability first
    assert ratelimit.describe()["degraded_events"] >= 1        # but never silently
    monkeypatch.setenv("FEEFIX_RATELIMIT_FAIL_MODE", "closed")
    assert ratelimit.check_global("9.9.9.9") is False          # or refuse, if configured
    ratelimit.reset()
    ratelimit.use_store(ratelimit.SQLiteStore())


def test_end_to_end_limiter_over_redis(client, monkeypatch, tmp_path):
    """The real middleware path, with counters in Redis instead of SQLite."""
    client_store = fakeredis.FakeStrictRedis()
    monkeypatch.setattr(
        ratelimit.redis, "Redis",
        type("R", (), {"from_url": staticmethod(lambda *a, **k: client_store)}), raising=False,
    )
    store = ratelimit.RedisStore("redis://fake:6379/0")
    ratelimit.use_store(store)
    try:
        for _ in range(ratelimit.AUTH_LIMIT[0]):
            assert client.post(
                "/api/auth/login", json={"email": "redis@example.com", "password": "nope-nope"}
            ).status_code == 401
        blocked = client.post(
            "/api/auth/login", json={"email": "redis@example.com", "password": "nope-nope"}
        )
        assert blocked.status_code == 429
        assert int(blocked.headers["Retry-After"]) >= 1
        assert blocked.headers["X-RateLimit-Scope"] == "auth"
        assert "redis@example.com" not in str(dict(blocked.headers)), (
            "the identifier must not be echoed into response headers"
        )
    finally:
        ratelimit.use_store(ratelimit.SQLiteStore())
