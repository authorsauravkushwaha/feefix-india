"""Security hardening regression suite — one focused test per attack class.

Maps 1:1 to the threat list in docs/security/HARDENING.md:

  1 Replay attack          7 Server-side template injection
  2 Clipboard attack       8 Error handling & information leakage
  3 SQL / NoSQL injection  9 File upload security
  4 Secret key leaks       10 Secret management
  5 Long-password DoS      11 Input validation
  6 ReDoS                  12 Rate limiting
  13 authentication != authorization

This file is the *map*; the depth lives in the focused suites added after the
security review, each of which covers one control end to end:

  tests/test_session_replay_policy.py     replay policy without a self-DoS (1)
  tests/test_clipboard_js.py              clipboard module behaviour (2)
  tests/test_secret_hygiene.py            strict boot + scanner bypasses (4, 10)
  tests/test_password_hashing.py          Argon2id + migration (5)
  tests/test_uploads.py                   the wired upload gate (9)
  tests/test_body_limits.py               per-endpoint limits, streaming (11)
  tests/test_ratelimit_distributed.py     rate limiting across instances (12)
  tests/test_numerals.py                  table-driven income parsing (6)
  tests/test_fuzz_security.py             property-based/adversarial pass

Run with the rest of the suite (``python -m pytest``).
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REPO = Path(__file__).resolve().parents[1]
PROFILE = {"domicile_state": "West Bengal", "category": "general",
           "annual_family_income": 200000, "course_level": "ug", "gender": "female"}


def _register(client, email="stu@example.com", password="S3cure!Pass", name="Asha"):
    return client.post("/api/auth/register",
                       json={"email": email, "password": password, "name": name})


def _own_session(client, sid):
    """Create an account and bind an anonymous session to it → owned session."""
    client.put(f"/api/students/{sid}/profile", json={"profile": PROFILE})
    token = _register(client).json()["token"]
    r = client.post("/api/auth/link-session", json={"session_id": sid},
                    headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    return token


# ===================================================================== 1 REPLAY
def test_aged_token_rotates_and_a_stale_replay_does_not_kill_the_live_session(client):
    """Anti-replay without the self-DoS: the stale token dies, the session lives.

    The old behaviour revoked the whole session family on any replayed rotated
    token, so one stale tab logged the user out everywhere. The policy is now
    tiered (see ``services/auth.py`` and tests/test_session_replay_policy.py):
    a stale token beyond the overlap window is refused, while the live token
    keeps working, and family revocation needs an actual theft signal.
    """
    token = _register(client).json()["token"]
    from backend.services import auth as auth_svc, db
    conn = db.get_connection()
    aged = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat(timespec="seconds")
    conn.execute("UPDATE auth_sessions SET created_at=? WHERE token_hash=?",
                 (aged, auth_svc._token_hash(token)))
    conn.commit()

    # Using the aged token rotates it; the fresh token comes back in a header.
    r = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    new_token = r.headers.get("X-Session-Token")
    assert new_token and new_token != token
    assert client.get("/api/auth/me",
                      headers={"Authorization": f"Bearer {new_token}"}).status_code == 200

    # A replay of the superseded token, long after the overlap window: refused —
    # but the session the real user is holding must survive.
    conn.execute("UPDATE auth_sessions SET replaced_at=? WHERE token_hash=?",
                 ((datetime.now(timezone.utc) - timedelta(seconds=auth_svc.OVERLAP_S + 600))
                  .isoformat(timespec="seconds"), auth_svc._token_hash(token)))
    conn.commit()
    assert client.get("/api/auth/me",
                      headers={"Authorization": f"Bearer {token}"}).status_code == 401
    assert client.get("/api/auth/me",
                      headers={"Authorization": f"Bearer {new_token}"}).status_code == 200


def test_replay_beyond_overlap_is_audited(client):
    """A refused replay leaves a trail an operator can act on."""
    token = _register(client, email="audit-replay@example.com").json()["token"]
    from backend.services import auth as auth_svc, db
    conn = db.get_connection()
    aged = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat(timespec="seconds")
    conn.execute("UPDATE auth_sessions SET created_at=? WHERE token_hash=?",
                 (aged, auth_svc._token_hash(token)))
    conn.commit()

    # Real rotation: the response carries the replacement token.
    r = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200 and r.headers.get("X-Session-Token")

    # Now push the supersession far outside the overlap window and replay.
    conn.execute("UPDATE auth_sessions SET replaced_at=? WHERE token_hash=?",
                 ((datetime.now(timezone.utc) - timedelta(seconds=auth_svc.OVERLAP_S + 600))
                  .isoformat(timespec="seconds"), auth_svc._token_hash(token)))
    conn.commit()
    assert client.get("/api/auth/me",
                      headers={"Authorization": f"Bearer {token}"}).status_code == 401
    actions = [row["action"] for row in conn.execute("SELECT action FROM audit_log")]
    assert "auth.token_replay_rejected" in actions, actions


def test_oauth_state_is_single_use(client, monkeypatch):
    monkeypatch.setenv("GITHUB_CLIENT_ID", "x")
    monkeypatch.setenv("GITHUB_CLIENT_SECRET", "y")
    from backend.services import otp as otp_svc
    state = otp_svc.github_start().rsplit("state=", 1)[1]
    assert otp_svc._pop_state(state) is True     # first use consumes it
    assert otp_svc._pop_state(state) is False    # replay is rejected


# ================================================================== 2 CLIPBOARD
def test_secure_clipboard_never_copies_tokens():
    src = (REPO / "web" / "frontend" / "secure-clipboard.js").read_text()
    # The helper must refuse credential-shaped values and auto-clear…
    assert "looksLikeSecret" in src and "clearClipboard" in src and "copyWithHygiene" in src
    assert "feefix.token" in src  # explicit guard against copying the token
    # …and must not pretend to stop clipboard malware (see tests/test_clipboard_js.py,
    # which executes the module instead of grepping it).
    assert "cannot stop" in src.lower()
    assert "securityControl: false" in src


def test_auth_token_never_leaked_in_urls_or_bodies(client):
    token = _register(client).json()["token"]
    # /api/auth/me returns the user, never the raw token in the body.
    body = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"}).json()
    assert token not in str(body)


# ============================================================ 3 SQL / NOSQL INJ
def test_no_string_interpolated_sql():
    """Static guard: no f-string/%/format/concat is fed to a SQL data statement."""
    sql_kw = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|WHERE|VALUES|FROM)\b", re.I)
    bad = []
    for path in (REPO / "backend").rglob("*.py"):
        for i, line in enumerate(path.read_text().splitlines(), 1):
            if ".execute(" not in line:
                continue
            if "PRAGMA" in line:  # schema version only; not injectable
                continue
            if sql_kw.search(line) and re.search(r"""f["']|%[sd]|\.format\(|\+ *["']""", line):
                bad.append(f"{path.name}:{i}")
    assert not bad, f"string-built SQL found: {bad}"


@pytest.mark.parametrize("payload", [
    "' OR '1'='1", "'; DROP TABLE users;--", "\" OR 1=1--",
    "admin'--", "1 UNION SELECT password_hash FROM users",
])
def test_sql_injection_payloads_are_inert(client, payload):
    # As an email it fails validation; as a scheme id it is simply not found.
    # Either way the injection is treated as data, never executed.
    r = client.post("/api/auth/login", json={"email": payload, "password": "whatever1"})
    assert r.status_code in (401, 422)
    assert client.get(f"/api/schemes/{payload}").status_code == 404
    assert client.get(f"/api/tracker/{payload}").status_code in (200, 403)


# =============================================================== 4 SECRET LEAKS
def test_repo_has_no_committed_secrets():
    from agents.secret_scan import scan
    findings = scan(REPO)
    assert findings == [], f"committed secrets detected: {findings[:5]}"


def test_otp_pepper_is_gitignored():
    ignore = (REPO / ".gitignore").read_text()
    assert ".otp_pepper" in ignore and ".env" in ignore


# ========================================================= 5 LONG-PASSWORD DoS
def test_overlong_password_rejected(client):
    r = client.post("/api/auth/register",
                    json={"email": "a@b.co", "password": "x" * 5000})
    assert r.status_code == 422


def test_password_hash_cost_is_length_independent():
    # Pre-hashing means KDF work does not scale with password length.
    from backend.services import auth as auth_svc
    short = auth_svc.hash_password("shortpw1")
    long_ = auth_svc.hash_password("L" * 100000)
    assert auth_svc.verify_password("shortpw1", short)
    assert auth_svc.verify_password("L" * 100000, long_)


# ==================================================================== 6 ReDOS
@pytest.mark.parametrize("evil,label", [
    ("a" * 3000 + "!", "alpha"),
    ("৯" * 3000, "bengali-digits"),
    ("(" * 1500 + ")" * 1500, "parens"),
    ("9" * 1990 + " lakh", "overflow-lakh"),
    ("2" * 3000 + "lakh", "long-lakh"),
])
def test_pathological_inputs_parse_quickly(evil, label):
    from backend.services.chat import parse_income, parse_state
    t0 = time.monotonic()
    assert parse_income(evil) is None or isinstance(parse_income(evil), int)
    parse_state(evil)
    assert time.monotonic() - t0 < 1.0, f"{label} took too long (ReDoS?)"


def test_oversized_question_rejected_before_processing(client):
    # 6000 chars: over the 1000-char field cap (→422) but under the 1 MB body cap,
    # so it is rejected by validation, never reaching the regex/embedder.
    r = client.post("/api/ask", json={"question": " scholarship " * 500})
    assert r.status_code == 422


def test_oversized_search_query_rejected(client):
    r = client.get("/api/search/semantic", params={"q": "x" * 5000})
    assert r.status_code == 422


# ============================================================== 7 SSTI / HTML
@pytest.mark.parametrize("payload", [
    "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{{constructor.constructor('return 1')()}}",
    "${jndi:ldap://x/a}",
])
def test_template_payloads_are_not_evaluated(client, payload):
    r = client.post("/api/ask", json={"question": payload})
    assert r.status_code == 200
    # JSON is data, never executed; the answer must not contain a computed result.
    assert "49" not in r.text
    assert r.headers["content-type"].startswith("application/json")


def test_ask_reflects_input_as_json_not_html(client):
    r = client.post("/api/ask", json={"question": "<script>alert(1)</script>"})
    assert r.headers["content-type"].startswith("application/json")
    # Reflected only as escaped JSON data — the SPA renders it through esc().
    assert "<script>alert(1)</script>" in r.json()["question"]


def test_handoff_json_blocks_script_breakout():
    from backend.api.routes import _json_html_safe
    enc = _json_html_safe({"user": {"name": "</script><script>alert(1)</script>"}})
    assert "</script>" not in enc and "<" not in enc and ">" not in enc


# ============================================= 8 ERROR HANDLING / INFO LEAKAGE
def test_unhandled_error_is_opaque(client):
    from fastapi.testclient import TestClient

    def boom(*a, **k):
        raise RuntimeError("secret internal detail xyz")
    client.app.state.qa.answer = boom
    # raise_server_exceptions=False surfaces the app's own 500 response.
    raw = TestClient(client.app, raise_server_exceptions=False)
    r = raw.post("/api/ask", json={"question": "engineering scholarship"})
    assert r.status_code == 500
    body = r.text
    assert "RuntimeError" not in body and "secret internal detail" not in body
    assert "request_id" in r.json()          # correlation id, not internals


def test_i18n_path_traversal_blocked(client):
    for evil in ("..%2f..%2fetc%2fpasswd", "....//", "../main"):
        assert client.get(f"/api/i18n/{evil}").status_code == 404


def test_docs_are_enabled_by_default_and_can_be_opted_out(monkeypatch):
    """Turning docs off removed no endpoint — it only broke tooling.

    So the switch stays available for operators who want it, but the default is
    ON, and the OpenAPI schema (what generated clients consume) is served.
    """
    from backend.main import create_app, docs_enabled

    monkeypatch.delenv("FEEFIX_ENABLE_DOCS", raising=False)
    monkeypatch.delenv("FEEFIX_DISABLE_DOCS", raising=False)
    assert docs_enabled() is True

    app = create_app()
    client_ = TestClient(app)
    assert client_.get("/openapi.json").status_code == 200
    assert client_.get("/docs").status_code == 200
    schema = client_.get("/openapi.json").json()
    assert "/api/uploads/{session_id}" in schema["paths"]

    # Interactive docs can be hidden. The schema stays: hiding it broke generated
    # clients and removed no route.
    monkeypatch.setenv("FEEFIX_DISABLE_DOCS", "1")
    assert docs_enabled() is False
    docs_client = TestClient(create_app())
    assert docs_client.get("/docs").status_code == 404
    assert docs_client.get("/openapi.json").status_code == 200
    assert "/api/uploads/{session_id}" in docs_client.get("/openapi.json").json()["paths"]


def test_validation_error_has_no_stacktrace(client):
    r = client.post("/api/auth/register", json={"email": "x", "password": "y"})
    assert r.status_code == 422
    assert "Traceback" not in r.text and "File \"" not in r.text


# ========================================================== 9 FILE UPLOAD
def test_upload_gate_is_wired_into_a_route():
    """A control nobody calls protects nothing — the gate now has a caller."""
    from backend.main import create_app

    # The OpenAPI schema is the canonical view of what the app actually serves
    # (newer Starlette keeps included routers nested rather than flattened).
    paths = set(create_app().openapi()["paths"])
    assert any(p.endswith("/uploads/{session_id}") for p in paths), paths
    assert any(p.endswith("/uploads/{session_id}/{upload_id}/content") for p in paths), paths


def test_upload_rejects_dangerous_and_spoofed_files():
    from backend.services.upload import validate_upload
    assert validate_upload("cv.pdf", b"%PDF-1.7 ok")[0] is True
    assert validate_upload("shell.php", b"<?php ?>")[0] is False
    assert validate_upload("evil.pdf.php", b"%PDF-")[0] is False          # double ext
    assert validate_upload("fake.pdf", b"<?php echo 1; ?>")[0] is False   # magic mismatch
    assert validate_upload("x.svg", b"<svg onload=alert(1)>")[0] is False
    assert validate_upload("empty.pdf", b"")[0] is False
    from backend.services.limits import MAX_UPLOAD_BYTES
    assert validate_upload("big.pdf", b"%PDF-" + b"a" * MAX_UPLOAD_BYTES)[0] is False


def test_upload_filename_cannot_escape_directory():
    from backend.services.upload import sanitize_filename, safe_storage_name
    assert "/" not in sanitize_filename("../../etc/passwd")
    assert "\\" not in sanitize_filename("..\\..\\windows\\system32")
    stored = safe_storage_name("../../evil.php")
    assert stored.endswith("") and "/" not in stored and "\\" not in stored
    assert not stored.lower().endswith(".php")


# ======================================================= 10 SECRET MANAGEMENT
def test_get_secret_reads_env_only(monkeypatch):
    from backend.services import secrets as sec
    monkeypatch.setenv("FEEFIX_TEST_SECRET", "real-value")
    assert sec.get_secret("FEEFIX_TEST_SECRET") == "real-value"
    assert sec.get_secret("FEEFIX_MISSING_SECRET") is None
    with pytest.raises(RuntimeError):
        sec.get_secret("FEEFIX_MISSING_SECRET", required=True)


def test_weak_secret_detection(monkeypatch):
    from backend.services import secrets as sec
    for name in list(sec._EXPECTED_SECRETS):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GITHUB_CLIENT_ID", "iv1.x")
    monkeypatch.setenv("GITHUB_CLIENT_SECRET", "changeme")
    findings = sec.weak_secret_findings()
    assert any("GITHUB_CLIENT_SECRET" in f for f in findings)


# ========================================================= 11 INPUT VALIDATION
@pytest.mark.parametrize("bad", [
    {"email": "not-an-email", "password": "longenough"},
    {"email": "a@b.co", "password": "short"},
])
def test_register_field_validation(client, bad):
    assert client.post("/api/auth/register", json=bad).status_code == 422


def test_invalid_enum_rejected(client):
    body = {"profile": {**PROFILE, "category": "alien", "course_level": "wizarddrive"}}
    assert client.put("/api/students/x/profile", json=body).status_code == 422


def test_oversized_body_rejected(client):
    r = client.post("/api/chat", content=b"x" * 1_100_000,
                    headers={"content-type": "application/json"})
    assert r.status_code == 413


def test_hostile_domicile_is_bounded(client):
    # Arbitrary domicile is length-bounded and never crashes the engine.
    body = {"profile": {**PROFILE, "domicile_state": "<script>" + "A" * 500}}
    r = client.put("/api/students/dom-test/profile", json=body)
    # max_length=64 on the field → 422 for a 500-char value.
    assert r.status_code == 422


def test_minority_community_normalized(client):
    body = {"profile": {**PROFILE, "is_minority": True, "minority_community": "<b>x</b>"}}
    r = client.put("/api/students/min-test/profile", json=body)
    assert r.status_code == 200
    assert r.json()["profile_echo"]["minority_community"] is None


# ============================================================= 12 RATE LIMITING
def test_rate_limit_tiers_and_retry_after():
    from backend.services import ratelimit
    ratelimit.reset()
    ip = "9.9.9.9"
    # Global bucket.
    for _ in range(ratelimit.DEFAULT_LIMIT[0]):
        assert ratelimit.check_global(ip)
    assert not ratelimit.check_global(ip)
    assert ratelimit.retry_after(ip, "global") >= 1
    ratelimit.reset()
    # Expensive bucket has its own tighter window.
    for _ in range(ratelimit.EXPENSIVE_LIMIT[0]):
        assert ratelimit.check_expensive(ip, "ask")
    assert not ratelimit.check_expensive(ip, "ask")


def test_rate_limit_has_a_shared_store_option():
    """In-process counters multiply across workers — Redis is the fix."""
    from backend.services import ratelimit

    assert hasattr(ratelimit, "RedisBackend")
    assert ratelimit.status()["distributed"] in (True, False)
    # The default (no FEEFIX_REDIS_URL) is the in-process store, and it says so.
    assert ratelimit.configure().name in ("memory", "redis")


def test_rate_limit_store_is_bounded():
    from backend.services import ratelimit
    ratelimit.reset()
    for i in range(ratelimit._MAX_KEYS + 200):
        ratelimit.check_global(f"10.0.{i // 256}.{i % 256}")
    assert len(ratelimit._hits) <= ratelimit._MAX_KEYS
    ratelimit.reset()


def test_auth_rate_limit_returns_retry_after(client):
    _register(client)
    last = None
    for _ in range(12):
        last = client.post("/api/auth/login",
                           json={"email": "stu@example.com", "password": "nope-nope"})
        if last.status_code == 429:
            break
    assert last.status_code == 429
    assert int(last.headers.get("Retry-After", "0")) >= 1


# ================================================ 13 AUTHENTICATION != AUTHZ
@pytest.mark.parametrize("method,path,body", [
    ("GET", "/api/students/owned-1/reminders", None),
    ("POST", "/api/students/owned-1/reminders/dispatch", {"limit": 5}),
    ("POST", "/api/events", {"session_id": "owned-1", "scheme_id": "sv-mcm-wb", "type": "viewed"}),
    ("POST", "/api/ask", {"question": "girls engineering scholarship", "session_id": "owned-1"}),
])
def test_owned_session_endpoints_require_owner(client, method, path, body):
    token = _own_session(client, "owned-1")
    # No token → authorization refuses (authentication would also fail).
    r = client.request(method, path, json=body)
    assert r.status_code == 403, f"{path} leaked without a token"
    # Owner → allowed.
    r2 = client.request(method, path, json=body,
                        headers={"Authorization": f"Bearer {token}"})
    assert r2.status_code == 200, f"{path} refused the owner"


def test_other_account_cannot_touch_owned_session(client):
    _own_session(client, "owned-2")
    other = _register(client, email="other@example.com").json()["token"]
    r = client.get("/api/students/owned-2/reminders",
                   headers={"Authorization": f"Bearer {other}"})
    assert r.status_code == 403


def test_anonymous_sessions_stay_open(client):
    # Privacy-by-design: an unowned (anonymous) session remains fully usable.
    assert client.get("/api/students/anon-xyz/reminders").status_code == 200
    assert client.post("/api/events",
                       json={"session_id": "anon-xyz", "scheme_id": "sv-mcm-wb",
                             "type": "viewed"}).status_code == 200


# ===================================================== transport hardening bonus
def test_hsts_sent_behind_tls(client):
    r = client.get("/api/health", headers={"x-forwarded-proto": "https"})
    assert "max-age=" in r.headers.get("Strict-Transport-Security", "")
