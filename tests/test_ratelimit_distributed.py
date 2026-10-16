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
import sqlite3
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


#: Ports handed out in this process. The OS reuses an ephemeral port as soon as
#: the socket that held it is closed, so two back-to-back calls could return the
#: *same* number: the second instance then failed to bind, the health probe hit
#: the first instance and passed, and "two instances" silently became one — the
#: per-instance assertions in this file would fail intermittently. Distinct
#: numbers in-process, and the caller retries if an outside process wins the race.
_used_ports: set[int] = set()


def _free_port() -> int:
    for _ in range(64):
        with socket.socket() as sock:
            # No SO_REUSEADDR: we want a port the kernel is not handing out
            # elsewhere, not one it is willing to share.
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
            sock.bind(("127.0.0.1", 0))
            port = int(sock.getsockname()[1])
        if port not in _used_ports:
            _used_ports.add(port)
            return port
    raise RuntimeError("could not find a free port")


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
def test_boot_refuses_a_scaled_in_process_limiter(monkeypatch):
    """A warning that keeps serving is the bypass. Scaled memory counters must not boot."""
    monkeypatch.delenv("FEEFIX_REDIS_URL", raising=False)
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.setenv("WEB_CONCURRENCY", "4")
    ratelimit.configure(ratelimit.MemoryBackend(), force=True)
    info = ratelimit.status()
    assert info["distributed"] is False
    assert info["workers"] == 4
    assert "FEEFIX_REDIS_URL" in (info["recommendation"] or "")
    with pytest.raises(RuntimeError) as exc:
        ratelimit.warn_if_not_distributed()
    assert "FEEFIX_REDIS_URL" in str(exc.value) or "per-process" in str(exc.value)


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


def test_redis_retry_after_is_time_remaining_not_age(fake_redis_server):
    """allow() used to return how old the oldest hit was, so Retry-After was inverted."""
    backend = _redis_backend(_url(fake_redis_server))
    window = 60
    assert backend.allow("global", "8.8.8.8", 1, window) == (True, 0.0)
    allowed, retry = backend.allow("global", "8.8.8.8", 1, window)
    assert allowed is False
    assert retry >= window - 5, f"retry_after should be ~{window}s remaining, got {retry}"


def test_two_processes_share_one_sqlite_window(tmp_path):
    """The multi-worker case, without Redis: two processes, one file, one quota."""
    path = tmp_path / "shared.ratelimit.db"
    script = (
        "import sys\n"
        f"sys.path.insert(0, {str(REPO)!r})\n"
        "from backend.services.ratelimit import SqliteBackend\n"
        f"store = SqliteBackend({str(path)!r})\n"
        "ok = sum(store.allow('global', '1.2.3.4', 3, 60)[0] for _ in range(3))\n"
        "print(ok)\n"
    )
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(2)
    ]
    outputs = []
    for proc in procs:
        out, err = proc.communicate(timeout=30)
        assert proc.returncode == 0, err
        outputs.append(int(out.strip()))
    assert sum(outputs) == 3, f"shared file must enforce one quota, got {outputs}"


def _hold_a_read_lock(path: Path, seconds: float) -> subprocess.Popen:
    """Start a peer process that holds a read transaction, and wait for it.

    Blocking until the peer reports the lock is held removes the timing lottery
    from the test: by the time the worker boots, the lock is definitely there.
    """
    script = (
        "import sqlite3, sys, time\n"
        f"conn = sqlite3.connect({str(path)!r}, isolation_level=None)\n"
        "conn.execute('CREATE TABLE IF NOT EXISTS seed (x)')\n"
        "conn.execute('BEGIN')\n"
        "conn.execute('SELECT * FROM seed').fetchall()\n"
        "print('locked', flush=True)\n"
        f"time.sleep({seconds!r})\n"
        "conn.execute('COMMIT')\n"
    )
    holder = subprocess.Popen(
        [sys.executable, "-c", script], stdout=subprocess.PIPE, text=True
    )
    assert holder.stdout is not None
    assert holder.stdout.readline().strip() == "locked", "the peer never took the lock"
    return holder


def test_a_lost_journal_mode_race_never_kills_a_worker(tmp_path):
    """The boot crash CI's flake-watch caught: losing the WAL race is not fatal.

    Two workers starting together both try to move the same *fresh* database to
    WAL, and SQLite answers the loser of a journal-mode change with
    ``database is locked`` — without consulting the busy handler, and without the
    caller being able to do anything about it. Escaping from ``_init`` means the
    worker never boots, so a performance setting takes the deployment down; CI
    caught it as ``flaky``, on a real (if unlucky) schedule.

    A peer process holding a read transaction makes the lock deterministic: the
    upgrade must fail, the store must come up anyway, and it must still enforce
    exactly one shared quota.
    """
    path = tmp_path / "raced.db"
    script = (
        "import sys\n"
        f"sys.path.insert(0, {str(REPO)!r})\n"
        "from backend.services.ratelimit import SqliteBackend\n"
        # Boot must not spend the default 30 s lock wait proving it cannot have
        # WAL: the upgrade gets its own, short budget.
        "SqliteBackend._WAL_BUSY_S = 0.05\n"
        f"store = SqliteBackend({str(path)!r})\n"
        "print(store.status()['journal_mode'])\n"
        "print(sum(store.allow('global', '1.2.3.4', 2, 60)[0] for _ in range(3)))\n"
    )
    holder = _hold_a_read_lock(path, 1.0)
    try:
        proc = subprocess.run(
            [sys.executable, "-c", script], capture_output=True, text=True, timeout=60
        )
    finally:
        holder.wait(timeout=10)
    assert proc.returncode == 0, f"the worker died instead of degrading:\n{proc.stderr[-1500:]}"
    mode, quota = proc.stdout.split()
    assert mode == "default", f"a held reader cannot have allowed WAL (got {mode!r})"
    assert quota == "2", f"the degraded store must still enforce one quota, got {quota}"


def test_the_wal_upgrade_waits_before_it_gives_up(monkeypatch, tmp_path):
    """Retry on a lock, keep going on anything else, and never raise on a lock."""
    backend = ratelimit.SqliteBackend(tmp_path / "retry.db")
    attempts = {"n": 0}

    class Cursor:
        def __init__(self, row):
            self._row = row

        def fetchone(self):
            return self._row

    class Flaky:
        """Loses the race twice, then gets the file."""

        def execute(self, sql, *args):
            if sql.strip().upper().startswith("PRAGMA JOURNAL_MODE"):
                attempts["n"] += 1
                if attempts["n"] <= 2:
                    raise sqlite3.OperationalError("database is locked")
                return Cursor(("wal",))
            raise AssertionError(f"unexpected statement: {sql}")

    monkeypatch.setattr(time, "sleep", lambda _s: None)
    assert backend._switch_to_wal(Flaky()) is True
    assert attempts["n"] == 3

    class Broken:
        def execute(self, sql, *args):
            raise sqlite3.OperationalError("disk I/O error")

    # ...but a real failure is not a flake, and must not be swallowed.
    with pytest.raises(sqlite3.OperationalError):
        backend._switch_to_wal(Broken())


def test_sqlite_status_reports_the_journal_mode(tmp_path):
    """A degraded store says so in /api/health instead of only in a log line."""
    healthy = ratelimit.SqliteBackend(tmp_path / "healthy.db")
    assert healthy.status()["journal_mode"] == "wal"

    store = ratelimit.SqliteBackend(tmp_path / "degraded.db")

    class Locked:
        def execute(self, sql, *args):
            raise sqlite3.OperationalError("database is locked")

    store._wal = store._switch_to_wal(Locked())
    assert store.status()["journal_mode"] == "default"
    assert store.status()["distributed"] is True  # the quota is still shared


def test_production_without_redis_uses_the_host_shared_store(monkeypatch, tmp_path):
    monkeypatch.setenv("FEEFIX_ENV", "production")
    monkeypatch.delenv("FEEFIX_REDIS_URL", raising=False)
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.delenv("FEEFIX_RATELIMIT_BACKEND", raising=False)
    monkeypatch.setenv("FEEFIX_RATELIMIT_DB", str(tmp_path / "rl.db"))
    monkeypatch.setenv("FEEFIX_INSTANCES", "1")
    try:
        store = ratelimit.configure(force=True)
        assert store.name == "sqlite"
        assert store.distributed is True
        assert store.multi_instance is False
        assert ratelimit.warn_if_not_distributed()  # honest: host-only, not silent
    finally:
        monkeypatch.delenv("FEEFIX_ENV", raising=False)
        ratelimit.configure(ratelimit.MemoryBackend(), force=True)


def test_multi_instance_without_redis_refuses_to_boot(monkeypatch, tmp_path):
    monkeypatch.setenv("FEEFIX_ENV", "production")
    monkeypatch.setenv("FEEFIX_INSTANCES", "2")
    monkeypatch.delenv("FEEFIX_REDIS_URL", raising=False)
    monkeypatch.setenv("FEEFIX_RATELIMIT_BACKEND", "sqlite")
    monkeypatch.setenv("FEEFIX_RATELIMIT_DB", str(tmp_path / "rl.db"))
    try:
        ratelimit.configure(force=True)
        with pytest.raises(RuntimeError) as exc:
            ratelimit.warn_if_not_distributed()
        assert "FEEFIX_REDIS_URL" in str(exc.value)
    finally:
        monkeypatch.delenv("FEEFIX_ENV", raising=False)
        monkeypatch.delenv("FEEFIX_INSTANCES", raising=False)
        ratelimit.configure(ratelimit.MemoryBackend(), force=True)


def test_expensive_paths_get_their_own_bucket():
    assert ratelimit.bucket_for_path("/api/ask").startswith("exp:")
    assert ratelimit.bucket_for_path("/api/uploads/abc").startswith("exp:")
    assert ratelimit.bucket_for_path("/api/schemes") == "global"


# --------------------------------------------------------------------------- #
# 5) end to end: two real worker processes, one shared counter set
# --------------------------------------------------------------------------- #
#: Generous by default: a cold CI runner importing FastAPI while a second
#: worker does the same can take far longer than a warm laptop. Tunable so a
#: slow environment can raise it without editing the test.
HEALTH_TIMEOUT_S = float(os.environ.get("FEEFIX_TEST_HEALTH_TIMEOUT", "120"))


def _wait_for_health(
    port: int,
    timeout_s: float | None = None,
    log_path: Path | None = None,
    proc: "subprocess.Popen | None" = None,
) -> None:
    import httpx

    deadline = time.time() + (timeout_s if timeout_s is not None else HEALTH_TIMEOUT_S)
    last_error: Exception | None = None
    while time.time() < deadline:
        # A worker that already exited will never serve: fail immediately with
        # the reason instead of burning the whole timeout on it.
        if proc is not None and proc.poll() is not None:
            last_error = RuntimeError(f"worker exited with code {proc.returncode}")
            break
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

    def __init__(self, env: dict, tmp_path: Path, *, name: str = "instance") -> None:
        self.env = env
        self.tmp_path = tmp_path
        self.name = name
        self.port = 0
        self.log_path = tmp_path / f"{name}.log"
        self.proc: subprocess.Popen | None = None
        self._log = None

    def start(self, *, attempts: int = 3) -> "_Instance":
        """Boot the worker, retrying on a *different* port if one is taken.

        Losing the bind race is not a test failure — it is an environment
        accident — so it is retried (with the child's output kept per attempt)
        instead of being reported as a broken rate limiter.
        """
        problems: list[str] = []
        for attempt in range(1, attempts + 1):
            self.port = _free_port()
            self.log_path = self.tmp_path / f"{self.name}-{self.port}.log"
            # A log file (not a pipe) so a crashed worker can be diagnosed
            # instead of deadlocking on a full pipe buffer.
            self._log = open(self.log_path, "w")  # noqa: SIM115 - closed in stop()
            self.proc = subprocess.Popen(
                [sys.executable, "-m", "uvicorn", "backend.main:app",
                 "--host", "127.0.0.1", "--port", str(self.port)],
                cwd=REPO, env=self.env, stdout=self._log, stderr=subprocess.STDOUT,
                text=True,
            )
            try:
                _wait_for_health(self.port, log_path=self.log_path, proc=self.proc)
                return self
            except AssertionError as exc:
                problems.append(f"attempt {attempt} (port {self.port}): {exc}")
                self.stop()
        raise AssertionError(
            f"{self.name} never became healthy:\n" + "\n".join(problems)
        )

    def get(self, path: str, timeout: float = 15.0) -> int:
        import httpx

        return httpx.get(f"http://127.0.0.1:{self.port}{path}", timeout=timeout).status_code

    def stop(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=15)
            except subprocess.TimeoutExpired:  # pragma: no cover
                self.proc.kill()
        if self._log is not None:
            self._log.close()
            self._log = None


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
    a = _Instance(env, tmp_path, name="instance-a").start()
    b = _Instance(env, tmp_path, name="instance-b").start()
    assert a.port != b.port, "two instances must not share a port"
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


# --------------------------------------------------------------------------- #
# 7) the harness itself: flaky infrastructure is a flaky gate
# --------------------------------------------------------------------------- #
def test_free_port_never_hands_out_the_same_port_twice():
    """The OS reuses an ephemeral port the instant its socket closes.

    Two back-to-back allocations could therefore return the same number; the
    second worker failed to bind, the health probe hit the *first* worker and
    reported success, and "two instances" silently became one — which makes the
    per-instance assertions in this file fail intermittently for reasons that
    have nothing to do with rate limiting.
    """
    ports = [_free_port() for _ in range(25)]
    assert len(set(ports)) == len(ports), f"duplicate port handed out: {ports}"


def test_health_probe_fails_fast_when_the_worker_has_already_exited(tmp_path):
    """A dead child must be reported immediately, not after the whole timeout."""
    proc = subprocess.Popen([sys.executable, "-c", "raise SystemExit(3)"])
    proc.wait(timeout=30)

    started = time.time()
    with pytest.raises(AssertionError) as excinfo:
        _wait_for_health(_free_port(), timeout_s=60, proc=proc)
    elapsed = time.time() - started

    assert elapsed < 15, f"waited {elapsed:.1f}s for a process that had already exited"
    assert "exited with code 3" in str(excinfo.value)


def test_instance_start_retries_on_a_fresh_port_and_reports_every_attempt(
    monkeypatch, tmp_path
):
    """Losing the bind race is an environment accident, not a broken limiter."""

    class _DeadProc:
        returncode = 1

        def poll(self) -> int:
            return 1

        def terminate(self) -> None:  # pragma: no cover - nothing to stop
            pass

        def wait(self, timeout: float | None = None) -> int:
            return 1

    attempts: list[int] = []

    def fake_popen(cmd, **kwargs):  # noqa: ANN001, ANN003 - mirrors Popen's shape
        attempts.append(int(cmd[cmd.index("--port") + 1]))
        return _DeadProc()

    monkeypatch.setattr(subprocess, "Popen", fake_popen)

    with pytest.raises(AssertionError) as excinfo:
        _Instance({"PATH": os.environ.get("PATH", "")}, tmp_path, name="dead").start(
            attempts=2
        )

    message = str(excinfo.value)
    assert "attempt 1" in message and "attempt 2" in message, message
    assert "exited with code 1" in message
    assert len(set(attempts)) == len(attempts), f"retried on the same port: {attempts}"
