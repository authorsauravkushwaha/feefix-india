#!/usr/bin/env python3
"""Offline API fuzzer — "no 5xx, no hang, no leak" as an executable claim.

The regression suite proves that the paths its author thought of behave; a
fuzzer probes the paths nobody thought of. Every route is hit with randomly
generated payloads — valid, malformed, oversized, hostile-encoded, wrong-typed,
wrong-method — and the run fails if the API ever:

* answers 5xx (an unhandled exception reached the user),
* takes longer than ``--timeout`` on a single request (a hang / algorithmic
  blow-up),
* echoes a stack trace, a file path or an internal class name back,
* crashes the process.

It is deterministic for a given ``--seed`` so a failure is reproducible, and it
is stdlib-only apart from the app's own dependencies. Run it in CI on a schedule
(a longer budget) and locally before a release::

    python -m scripts.fuzz_api --requests 500 --seed 1
    python -m scripts.fuzz_api --requests 5000 --seed 7 --timeout 3
"""

from __future__ import annotations

import argparse
import os
import random
import string
import sys
import time
from pathlib import Path
from urllib.parse import quote, urlencode

# Keep the fuzzer offline/deterministic — a model download would be a network
# dependency and a multi-second stall in the middle of a fuzz run.
os.environ.setdefault("FEEFIX_AI_BACKEND", "ngram")
os.environ.setdefault("FEEFIX_AI_ALLOW_DOWNLOAD", "0")

from fastapi.testclient import TestClient  # noqa: E402

from backend.main import create_app  # noqa: E402
from backend.services import db  # noqa: E402
from backend.services.limits import MAX_MESSAGE_LEN, MAX_SEARCH_LEN  # noqa: E402

#: Substrings that must never appear in a response body.
_LEAK_MARKERS = ("Traceback", "File \"", "sqlite3.", "argon2.", "line 1, in ")

_HOSTILE = [
    "<script>alert(1)</script>", "{{7*7}}", "${7*7}", "'; DROP TABLE users;--",
    '" OR 1=1--', "../../etc/passwd", "%00", "\x00\x01\x02", "🧑‍💻" * 40,
    "\\u0000", "NaN", "Infinity", "-1", "9" * 40, " " * 50, "\n\r\t",
    "۰۱۲۳", "๐๑๒", "صفر", "\U0001F600" * 30, "null", "true", "[]", "{}",
]


def _random_string(rng: random.Random, max_len: int = 60) -> str:
    alphabet = string.printable + "अআஅ௦" + "".join(_HOSTILE)
    return "".join(rng.choice(alphabet) for _ in range(rng.randint(0, max_len)))


def _random_value(rng: random.Random, depth: int = 0):
    choice = rng.randint(0, 9)
    if choice == 0:
        return _random_string(rng)
    if choice == 1:
        return rng.randint(-(10 ** rng.randint(1, 14)), 10 ** rng.randint(1, 14))
    if choice == 2:
        return rng.choice([True, False, None])
    if choice == 3:
        return rng.choice(_HOSTILE)
    if choice == 4 and depth < 2:
        return {_random_string(rng, 10): _random_value(rng, depth + 1) for _ in range(rng.randint(0, 3))}
    if choice == 5 and depth < 2:
        return [_random_value(rng, depth + 1) for _ in range(rng.randint(0, 3))]
    if choice == 6:
        return rng.random() * rng.choice([1, 1e6, 1e18, float("inf") if False else 1e9])
    if choice == 7:
        return {"profile": _random_value(rng, depth + 1)}
    return _random_string(rng, 200)


def _payload(rng: random.Random, shape: str) -> dict:
    """A plausible JSON body for a route, then randomly corrupted."""
    if shape == "profile":
        body = {
            "profile": {
                "domicile_state": rng.choice(["West Bengal", "Bihar", "", _random_string(rng, 8)]),
                "category": rng.choice(["general", "sc", "st", "obc", "alien", rng.randint(0, 5)]),
                "annual_family_income": rng.choice([0, 200000, -5, 10 ** 15, "much", None]),
                "course_level": rng.choice(["ug", "pg", "school", "wizarddrive", 3]),
            },
            "lang": rng.choice(["en", "bn", "hi", "ta", "xx", _random_string(rng, 4)]),
        }
    elif shape == "credentials":
        body = {"email": _random_string(rng, 30), "password": _random_string(rng, 300)}
    elif shape == "message":
        body = {"message": _random_string(rng, MAX_MESSAGE_LEN + 20), "chat_id": _random_string(rng, 70)}
    elif shape == "question":
        body = {"question": _random_string(rng, 1200), "session_id": _random_string(rng, 70)}
    elif shape == "event":
        body = {"session_id": _random_string(rng, 70), "scheme_id": _random_string(rng, 70),
                "type": rng.choice(["viewed", "applied", "nonsense", _random_string(rng, 10)])}
    else:
        body = _random_value(rng)
    if rng.random() < 0.35:  # corrupt the shape now and then
        return _random_value(rng) if rng.random() < 0.5 else {"unexpected": _random_value(rng)}
    return body  # type: ignore[return-value]


def _routes() -> list[tuple[str, str, str]]:
    """(method, path, body-shape) for every route worth fuzzing."""
    session = _random_session()
    return [
        ("GET", "/api/health", ""),
        ("GET", "/api/meta", ""),
        ("GET", "/api/stats", ""),
        ("GET", "/api/schemes", ""),
        ("GET", f"/api/schemes/{session}", ""),
        ("GET", f"/api/schemes/{session}", ""),
        ("POST", "/api/match", "profile"),
        ("GET", f"/api/match/{session}", ""),
        ("PUT", f"/api/students/{session}/profile", "profile"),
        ("GET", f"/api/students/{session}/profile", ""),
        ("PUT", f"/api/tracker/{session}/sv-mcm-wb", "track"),
        ("GET", f"/api/tracker/{session}", ""),
        ("GET", f"/api/students/{session}/reminders", ""),
        ("POST", f"/api/students/{session}/reminders/dispatch", "limit"),
        ("GET", f"/api/students/{session}/documents", ""),
        ("GET", f"/api/students/{session}/documents/{session}", ""),
        ("POST", "/api/auth/register", "credentials"),
        ("POST", "/api/auth/login", "credentials"),
        ("POST", "/api/auth/logout", ""),
        ("GET", "/api/auth/me", ""),
        ("POST", "/api/auth/link-session", "session"),
        ("GET", "/api/auth/export", ""),
        ("POST", "/api/auth/otp/request", "otp"),
        ("POST", "/api/auth/otp/verify", "otp_verify"),
        ("GET", "/api/auth/methods", ""),
        ("GET", "/api/search/semantic", "query"),
        ("POST", "/api/ask", "question"),
        ("POST", "/api/events", "event"),
        ("GET", f"/api/ml/rank/{session}", ""),
        ("POST", "/api/chat", "message"),
        ("GET", f"/api/i18n/{session}", ""),
    ]


def _random_session() -> str:
    return "fuzz-" + "".join(random.choice(string.ascii_lowercase + "../%00") for _ in range(14))


def _encode(path: str) -> str:
    """Percent-encode like a real client would.

    A raw non-ASCII path never reaches a server in the wild, and the test
    transport refuses to encode it — so fuzzing with raw Unicode would report
    transport errors instead of application behaviour.
    """
    return quote(path, safe="/?&=:-_.")


def fuzz(requests: int, seed: int, timeout: float, verbose: bool) -> int:
    rng = random.Random(seed)
    runtime = Path(os.environ.get("FEEFIX_FUZZ_RUNTIME", "runtime/fuzz"))
    runtime.mkdir(parents=True, exist_ok=True)
    os.environ["FEEFIX_DB"] = str(runtime / f"fuzz-{seed}.db")
    if Path(os.environ["FEEFIX_DB"]).exists():
        Path(os.environ["FEEFIX_DB"]).unlink()
    db.reset_for_tests(Path(os.environ["FEEFIX_DB"]))

    app = create_app()
    client = TestClient(app, raise_server_exceptions=False)
    routes = _routes()
    failures: list[str] = []
    slowest = (0.0, "")

    for index in range(requests):
        method, path, shape = routes[index % len(routes)] if index < len(routes) else rng.choice(routes)
        if rng.random() < 0.2:  # mutate the path too (traversal, overflow, ids)
            path = path.rsplit("/", 1)[0] + "/" + _random_session()
        kwargs: dict = {}
        if method in ("POST", "PUT", "PATCH"):
            if shape == "query" or (shape == "" and rng.random() < 0.5):
                kwargs["content"] = _random_string(rng, 200).encode()
                kwargs["headers"] = {"content-type": rng.choice(
                    ["application/json", "text/plain", "application/x-www-form-urlencoded"]
                )}
            else:
                body = _payload(rng, shape)
                if rng.random() < 0.1:  # hostile types: a list where a dict is required
                    body = _random_value(rng)
                kwargs["json"] = body
        if method == "GET" and shape == "query":
            query = urlencode({"q": _random_string(rng, MAX_SEARCH_LEN + 50),
                               "k": rng.choice([0, 5, 999, -3, "x"])})
            path = f"{path}?{query}"  # already encoded by urlencode
        if rng.random() < 0.15:  # random authorization attempts (headers are ASCII)
            junk = "".join(rng.choice(string.ascii_letters + string.digits + "_-.") for _ in range(48))
            kwargs["headers"] = {**(kwargs.get("headers") or {}), "authorization": f"Bearer {junk}"}

        started = time.perf_counter()
        try:
            response = client.request(method, _encode(path), **kwargs)
        except Exception as exc:  # noqa: BLE001 - the fuzzer's whole job
            failures.append(f"{method} {path} raised {exc.__class__.__name__}: {exc}")
            continue
        elapsed = time.perf_counter() - started
        if elapsed > slowest[0]:
            slowest = (elapsed, f"{method} {path}")

        if response.status_code >= 500:
            failures.append(f"{method} {path} → {response.status_code}: {response.text[:200]}")
        if elapsed > timeout:
            failures.append(f"{method} {path} took {elapsed:.1f}s (> {timeout}s)")
        body = response.text
        for marker in _LEAK_MARKERS:
            if marker in body:
                failures.append(f"{method} {path} leaked internals ({marker!r})")
        if verbose and index % 100 == 0:
            print(f"  [{index}] {method} {path} → {response.status_code} ({elapsed * 1000:.0f} ms)")

    print(f"fuzzed {requests} requests (seed={seed}) across {len(routes)} routes")
    print(f"slowest request: {slowest[1]} in {slowest[0] * 1000:.0f} ms")
    if failures:
        print(f"\n{len(failures)} failure(s):")
        for failure in failures[:25]:
            print(f"  ✗ {failure}")
        return 1
    print("  ✓ no 5xx, no hang, no leaked internals")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="FeeFix API fuzzer")
    parser.add_argument("--requests", type=int, default=300)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--timeout", type=float, default=5.0,
                        help="seconds before a single request counts as a hang")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)
    return fuzz(args.requests, args.seed, args.timeout, args.verbose)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
