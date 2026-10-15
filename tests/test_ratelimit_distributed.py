"""Rate limiting under horizontal scaling — the hole the old suite could not see.

The previous limiter kept its counters in a per-process dict. With ``--workers 2``
or two Render instances, every worker keeps its own window, so the effective
limit is silently multiplied by the number of workers and an attacker just
spreads requests. A single-process test suite can never observe that.

These tests therefore do three things:

1. **Reproduce the failure mode** (two ``MemoryBackend`` instances each allow a
   full quota) so the vulnerability is pinned by a test rather than described,
2. **Prove the fix** — two stores sharing one Redis see *one* counter set, and a
   real two-worker ``uvicorn`` deployment answers 429 exactly at the shared
   limit,
3. **Cover the operational edges** — fail-open vs fail-closed when Redis dies,
   the boot-time topology warning, and what ``/api/health`` reports.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from backend.services import ratelimit

REPO = Path(__file__).resolve().parents[1]

fakeredis = pytest.importorskip("fakeredis", reason="fakeredis is a test-only extra")


# --------------------------------------------------------------------------- #
# fixtures / helpers
# --------------------------------------------------------------------------- #
@pytest.fixture()
def fake_redis_server():
    """A real TCP server speaking RESP, backed by in-process fake Redis."""
    server = fakeredis.TcpFakeServer(("127.0.0.1", 0))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.05)
    yield server
    server.shutdown()
    thread.join(timeout=5)


def _url(server) -> str:
    return f"redis://127.0.0.1:{server.server_address[1]}/0"


def _redis_backend(url: str) -> ratelimit.RedisBackend:
    return ratelimit.RedisBackend(ratelimit._make_redis_client(url), url)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


# --------------------------------------------------------------------------- #
# 1) the vulnerability, pinned
# --------------------------------------------------------------------------- #
def test_per_process_store_multiplies_the_limit_across_workers():
    """Two independent in-process stores each hand out a full quota (×N limit)."""
    limit, window = 3, 60
    worker_a, worker_b = ratelimit.MemoryBackend(), ratelimit.MemoryBackend()
    allowed = 0
    for _ in range(limit):
        allowed += worker_a.allow("global", "1.2.3.4", limit, window)[0]
        allowed += worker_b.allow("global", "1.2.3.4", limit, window)[0]
    assert allowed == 2 * limit, (
        "expected the documented per-process multiplication; if this changed, "
        "the distributed tests below are no longer testing the real failure mode"
    )


def test_shared_store_does_not_multiply_the_limit(fake_redis_server):
    """The same scenario against a shared store: exactly one quota in total."""
    limit, window = 3, 60
    url = _url(fake_redis_server)
    instance_a, instance_b = _redis_backend(url), _redis_backend(url)
    allowed = 0
    for _ in range(limit):
        allowed += instance_a.allow("global", "1.2.3.4", limit, window)[0]
        allowed += instance_b.allow("global", "1.2.3.4", limit, window)[0]
    assert allowed == limit, "a shared store must enforce one quota, not one per instance"


# --------------------------------------------------------------------------- #
# 2) app-level: two app instances, one Redis
# --------------------------------------------------------------------------- #
def test_two_app_instances_share_the_same_counter_set(fake_redis_server, monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    from backend.services import db

    monkeypatch.setenv("FEEFIX_REDIS_URL", _url(fake_redis_server))
    monkeypatch.setenv("FEEFIX_RATELIMIT_BACKEND", "redis")
    monkeypatch.setenv("FEEFIX_RL_GLOBAL_LIMIT", "5")
    monkeypatch.setenv("FEEFIX_RL_GLOBAL_WINDOW", "60")
    # Rate-limit policy is read at import time, so patch the module values too.
    monkeypatch.setattr(ratelimit, "DEFAULT_LIMIT", (5, 60))

    from backend.main import create_app

    db.reset_for_tests(tmp_path / "shared.db")
    ratelimit.configure(force=True)
    try:
        instance_a = TestClient(create_app())
        instance_b = TestClient(create_app())

        codes = []
        for i in range(10):
            client = instance_a if i % 2 == 0 else instance_b
            codes.append(client.get("/api/schemes").status_code)

        assert codes.count(200) == 5, (
            f"shared limiter should allow exactly 5 across both instances, got {codes}"
        )
        assert codes.count(429) == 5
    finally:
        ratelimit.configure(ratelimit.MemoryBackend(), force=True)


def test_rate_limit_headers_and_status_are_exposed(fake_redis_server, monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    from backend.services import db

    monkeypatch.setenv("FEEFIX_REDIS_URL", _url(fake_redis_server))
    monkeypatch.setattr(ratelimit, "DEFAULT_LIMIT", (2, 60))
    from backend.main import create_app

    db.reset_for_tests(tmp_path / "status.db")
    ratelimit.configure(force=True)
    try:
        client = TestClient(create_app())
        health = client.get("/api/health").json()          # hit 1 of 2
        assert health["rate_limit"]["backend"] == "redis"
        assert health["rate_limit"]["distributed"] is True
        assert health["rate_limit_warning"] is None
        assert health["docs_enabled"] is True

        assert client.get("/api/schemes").status_code == 200   # hit 2 of 2
        denied = client.get("/api/schemes")                     # over the limit
        assert denied.status_code == 429
        assert int(denied.headers["Retry-After"]) >= 1
        assert denied.json()["scope"] == "global"
    finally:
        ratelimit.configure(ratelimit.MemoryBackend(), force=True)


# --------------------------------------------------------------------------- #
# 3) failure semantics
# --------------------------------------------------------------------------- #
class _BrokenClient:
    """Stands in for an unreachable Redis."""

    def pipeline(self, transaction=True):
        raise ConnectionError("redis is down")

    def zrange(self, *a, **k):
        raise ConnectionError("redis is down")

    def zrem(self, *a, **k):
        raise ConnectionError("redis is down")

    def ping(self):
        raise ConnectionError("redis is down")


@pytest.fixture()
def _broken_backend(monkeypatch):
    monkeypatch.setattr(ratelimit, "FAIL_CLOSED_BUCKETS", ("auth",))
    monkeypatch.setattr(ratelimit, "FAIL_MODE", "")
    return ratelimit.RedisBackend(_BrokenClient(), "redis://broken")


def test_store_outage_is_fail_closed_for_auth(_broken_backend):
    allowed, _retry = _broken_backend.allow("auth", "1.1.1.1:user@example.com", 10, 300)
    assert allowed is False, "brute-force attempts must not get a free pass while the store is down"


def test_store_outage_is_fail_open_for_interactive_traffic(_broken_backend):
    allowed, _retry = _broken_backend.allow("global", "1.1.1.1", 1000, 60)
    assert allowed is True, "an outage must not take the whole product down"


def test_global_fail_mode_override(monkeypatch):
    monkeypatch.setattr(ratelimit, "FAIL_MODE", "closed")
    backend = ratelimit.RedisBackend(_BrokenClient(), "redis://broken")
    assert backend.allow("global", "ip", 10, 60)[0] is False
    monkeypatch.setattr(ratelimit, "FAIL_MODE", "open")
    backend = ratelimit.RedisBackend(_BrokenClient(), "redis://broken")
    assert backend.allow("auth", "ip", 10, 60)[0] is True


def test_redis_retry_after_reflects_the_oldest_hit(fake_redis_server):
    url = _url(fake_redis_server)
    backend = _redis_backend(url)
    backend.allow("global", "9.9.9.9", 100, 60)
    assert backend.retry_after("global", "9.9.9.9") >= 1


# --------------------------------------------------------------------------- #
# 4) configuration & topology awareness
# --------------------------------------------------------------------------- #
def test_boot_warns_loudly_when_scaled_without_a_shared_store(monkeypatch, caplog):
    monkeypatch.delenv("FEEFIX_REDIS_URL", raising=False)
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.setenv("WEB_CONCURRENCY", "4")
    ratelimit.configure(ratelimit.MemoryBackend(), force=True)
    warning = ratelimit.warn_if_not_distributed()
    assert warning and "FEEFIX_REDIS_URL" in warning
    assert ratelimit.status()["distributed"] is False
    assert ratelimit.status()["workers"] == 4
    assert "FEEFIX_REDIS_URL" in ratelimit.status()["recommendation"]


def test_single_process_deployment_is_not_warned(monkeypatch):
    monkeypatch.delenv("WEB_CONCURRENCY", raising=False)
    monkeypatch.delenv("UVICORN_WORKERS", raising=False)
    monkeypatch.delenv("FEEFIX_INSTANCES", raising=False)
    ratelimit.configure(ratelimit.MemoryBackend(), force=True)
    assert ratelimit.warn_if_not_distributed() is None


def test_redis_backend_requested_without_url_raises(monkeypatch):
    monkeypatch.delenv("FEEFIX_REDIS_URL", raising=False)
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.setenv("FEEFIX_RATELIMIT_BACKEND", "redis")
    # An explicit redis choice with no URL is a configuration error, not a
    # silent downgrade to per-process counters.
    with pytest.raises(RuntimeError) as exc:
        ratelimit.configure(None, force=True)
    assert "FEEFIX_REDIS_URL" in str(exc.value)


def test_backend_selection_auto_uses_redis_when_url_is_set(fake_redis_server, monkeypatch):
    monkeypatch.setenv("FEEFIX_REDIS_URL", _url(fake_redis_server))
    monkeypatch.delenv("FEEFIX_RATELIMIT_BACKEND", raising=False)
    store = ratelimit.configure(None, force=True)
    try:
        assert store.name == "redis"
        assert store.distributed is True
    finally:
        ratelimit.configure(ratelimit.MemoryBackend(), force=True)


def test_expensive_paths_get_their_own_bucket():
    assert ratelimit.bucket_for_path("/api/ask").startswith("exp:")
    assert ratelimit.bucket_for_path("/api/uploads/abc").startswith("exp:")
    assert ratelimit.bucket_for_path("/api/schemes") == "global"


# --------------------------------------------------------------------------- #
# 5) end to end: two real worker processes, one shared counter set
# --------------------------------------------------------------------------- #
def _wait_for_health(port: int, timeout_s: float = 60.0, log_path: Path | None = None) -> None:
    import httpx

    deadline = time.time() + timeout_s
    last_error: Exception | None = None
    while time.time() < deadline:
        try:
            r = httpx.get(f"http://127.0.0.1:{port}/api/health", timeout=3)
            if r.status_code == 200:
                return
        except Exception as exc:  # noqa: BLE001 - server still booting
            last_error = exc
        time.sleep(0.4)
    tail = ""
    if log_path and log_path.exists():
        tail = "\n--- server log ---\n" + log_path.read_text()[-2000:]
    raise AssertionError(f"uvicorn did not become healthy on port {port}: {last_error}{tail}")


class _Instance:
    """One deployment instance: its own process, its own port, its own memory."""

    def __init__(self, port: int, env: dict, tmp_path: Path) -> None:
        self.port = port
        # A log file (not a pipe) so a crashed worker can be diagnosed instead
        # of deadlocking on a full pipe buffer.
        self.log_path = tmp_path / f"instance-{port}.log"
        self._log = open(self.log_path, "w")  # noqa: SIM115 - closed in stop()
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "backend.main:app",
             "--host", "127.0.0.1", "--port", str(port)],
            cwd=REPO, env=env, stdout=self._log, stderr=subprocess.STDOUT, text=True,
        )

    def get(self, path: str, timeout: float = 15.0) -> int:
        import httpx

        return httpx.get(f"http://127.0.0.1:{self.port}{path}", timeout=timeout).status_code

    def stop(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=15)
        except subprocess.TimeoutExpired:  # pragma: no cover
            self.proc.kill()
        self._log.close()


def _two_instances(
    tmp_path: Path, env_overrides: dict, limit: int = 6
) -> tuple[_Instance, _Instance]:
    """Boot two independent instances (the two-Render-instance scenario)."""
    env = dict(os.environ)
    env.update(
        {
            "FEEFIX_DB": str(tmp_path / "instances.db"),
            "FEEFIX_AI_BACKEND": "ngram",
            "FEEFIX_RL_GLOBAL_LIMIT": str(limit),
            "FEEFIX_RL_GLOBAL_WINDOW": "60",
            "WEB_CONCURRENCY": "1",
            **env_overrides,
        }
    )
    a = _Instance(_free_port(), env, tmp_path)
    b = _Instance(_free_port(), env, tmp_path)
    _wait_for_health(a.port, log_path=a.log_path)
    _wait_for_health(b.port, log_path=b.log_path)
    return a, b


def _hammer(instance: _Instance, n: int) -> list[int]:
    return [instance.get("/api/schemes") for _ in range(n)]


@pytest.mark.slow
def test_two_instances_with_redis_enforce_one_shared_limit(fake_redis_server, tmp_path):
    """Two separate deployment instances, one Redis: one limit between them."""
    limit = 6
    a, b = _two_instances(tmp_path, {"FEEFIX_REDIS_URL": _url(fake_redis_server)}, limit=limit)
    try:
        # Clear the readiness probes so the assertion is about the shared quota.
        ratelimit._make_redis_client(_url(fake_redis_server)).flushall()
        codes = _hammer(a, limit) + _hammer(b, limit)
    finally:
        a.stop()
        b.stop()
    allowed = codes.count(200)
    assert allowed == limit, (
        f"shared limiter must allow exactly {limit} across both instances: {codes}"
    )


@pytest.mark.slow
def test_two_instances_without_redis_multiply_the_limit(tmp_path):
    """Negative control: per-instance counters really do multiply the limit.

    This is the exact production failure the fix removes — kept as a test so the
    behaviour is observed rather than assumed, and so a regression to
    per-process state fails loudly here.
    """
    limit = 6
    a, b = _two_instances(tmp_path, {"FEEFIX_RATELIMIT_BACKEND": "memory"}, limit=limit)
    try:
        # Each instance spent one hit on its readiness probe (nothing is shared
        # between separate processes), so each has limit-1 left to hand out.
        codes = _hammer(a, limit) + _hammer(b, limit)
    finally:
        a.stop()
        b.stop()
    allowed = codes.count(200)
    assert allowed == 2 * (limit - 1), (
        "per-instance counters should let each instance hand out its own quota "
        f"(the documented xN bug); got {allowed} successes: {codes}"
    )
    assert allowed > limit, "the vulnerable configuration must exceed the intended limit"


# --------------------------------------------------------------------------- #
# 6) client identity behind a proxy: the header must not be a bypass
# --------------------------------------------------------------------------- #
class _FakeRequest:
    def __init__(self, headers: dict, client_host: str = "203.0.113.9") -> None:
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.client = type("C", (), {"host": client_host})()


def test_forwarded_header_is_ignored_without_a_trusted_proxy(monkeypatch):
    """Default: X-Forwarded-For is attacker-controlled noise, so ignore it."""
    monkeypatch.delenv("FEEFIX_TRUST_PROXY", raising=False)
    spoofed = _FakeRequest({"x-forwarded-for": "1.2.3.4"})
    assert ratelimit.client_ip(spoofed) == "203.0.113.9"


def test_rotating_the_forwarded_header_cannot_buy_new_buckets(monkeypatch):
    """The real finding: leftmost XFF made every request a fresh bucket.

    A client sets ``X-Forwarded-For: <random>``; the proxy appends the address
    it actually saw. Reading the *leftmost* value trusted the client's fake
    value and let it rotate buckets forever; the rightmost entry is the hop we
    trust.
    """
    monkeypatch.setenv("FEEFIX_TRUST_PROXY", "1")
    real = "198.51.100.7"
    seen = set()
    for fake in ("1.1.1.1", "2.2.2.2", "3.3.3.3", "9.9.9.9"):
        request = _FakeRequest({"x-forwarded-for": f"{fake}, {real}"})
        seen.add(ratelimit.client_ip(request))
    assert seen == {real}, f"spoofable client identity: {seen}"


def test_forwarded_chain_single_hop(monkeypatch):
    monkeypatch.setenv("FEEFIX_TRUST_PROXY", "1")
    assert ratelimit.client_ip(_FakeRequest({"x-forwarded-for": " 1.2.3.4 "})) == "1.2.3.4"
    assert ratelimit.client_ip(_FakeRequest({})) == "203.0.113.9"
