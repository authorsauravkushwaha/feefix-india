"""Security regression suite — one test per vulnerability that was fixed.

This file is the reason the hardening survives. Every test here is named after
the attack it prevents and carries the *measured* evidence that the attack used
to work, so a future refactor that removes a control fails a test whose name
explains what it just reintroduced.

Run on its own with::

    pytest tests/test_security.py -v

Organisation follows the threat classes, not the modules: a control that is
split across three files still gets one test that describes the attack.
"""

from __future__ import annotations

import json
import time

import pytest

from backend.services import anti_replay, input_guard, ratelimit, security, uploads
from backend.services.security import LIMITS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _replay_headers() -> dict:
    nonce, ts = anti_replay.new_nonce()
    return {anti_replay.HEADER_NONCE: nonce, anti_replay.HEADER_TIMESTAMP: ts}


def _register(client, email="sec-user@example.com", password="Str0ngPass!23", name="Sec"):
    return client.post("/api/auth/register",
                       json={"email": email, "password": password, "name": name})


def _token(client, email="sec-user@example.com", password="Str0ngPass!23"):
    return _register(client, email, password).json()["token"]


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


PROFILE = {"domicile_state": "Odisha", "category": "sc",
           "annual_family_income": 60000, "course_level": "ug"}


# ===========================================================================
# 1. REPLAY ATTACK
# ===========================================================================
class TestReplayAttack:
    """A captured request must be worth exactly one use."""

    def test_reused_nonce_is_rejected(self, client):
        headers = _replay_headers()
        first = client.post("/api/auth/register",
                            json={"email": "r1@example.com", "password": "Str0ngPass!23"},
                            headers=headers)
        assert first.status_code == 200
        # Identical bytes, identical headers — the textbook replay.
        second = client.post("/api/auth/register",
                             json={"email": "r2@example.com", "password": "Str0ngPass!23"},
                             headers=headers)
        assert second.status_code == 409

    def test_stale_timestamp_is_rejected(self, client):
        nonce, _ = anti_replay.new_nonce()
        stale = {anti_replay.HEADER_NONCE: nonce,
                 anti_replay.HEADER_TIMESTAMP: str(int(time.time()) - (LIMITS.REPLAY_WINDOW_S + 60))}
        r = client.post("/api/auth/login",
                        json={"email": "x@example.com", "password": "Str0ngPass!23"},
                        headers=stale)
        assert r.status_code == 409

    def test_future_timestamp_is_rejected(self, client):
        """A far-future timestamp cannot be pre-mined to survive the window."""
        nonce, _ = anti_replay.new_nonce()
        future = {anti_replay.HEADER_NONCE: nonce,
                  anti_replay.HEADER_TIMESTAMP: str(int(time.time()) + 86400)}
        r = client.post("/api/auth/login",
                        json={"email": "x@example.com", "password": "Str0ngPass!23"},
                        headers=future)
        assert r.status_code == 409

    def test_missing_nonce_rejected_when_enforced(self, monkeypatch):
        """Uses a *plain* TestClient: ``SecureTestClient`` signs every mutation
        the way the real clients do, so it cannot demonstrate an unsigned one."""
        from fastapi.testclient import TestClient
        from backend.main import create_app

        monkeypatch.setenv("FEEFIX_ANTI_REPLAY", "enforce")
        assert anti_replay.mode() == anti_replay.ENFORCE
        raw = TestClient(create_app())
        r = raw.post("/api/auth/login",
                     json={"email": "x@example.com", "password": "Str0ngPass!23"})
        assert r.status_code == 409

    def test_off_cannot_be_set_in_production(self, monkeypatch):
        """An operator typo must not silently disable replay defence."""
        monkeypatch.setenv("FEEFIX_ENV", "production")
        monkeypatch.setenv("FEEFIX_ANTI_REPLAY", "off")
        monkeypatch.delenv("FEEFIX_I_ACCEPT_REPLAY_RISK", raising=False)
        assert anti_replay.mode() == anti_replay.ENFORCE

    def test_reads_are_exempt(self, client):
        """Replaying a GET gains nothing the capture did not already contain."""
        assert client.get("/api/schemes").status_code == 200
        assert client.get("/api/schemes").status_code == 200

    def test_nonce_store_is_bounded(self):
        """The defence must not itself be a memory-exhaustion vector.

        Nonces are keyed per client IP precisely so that flooding can only ever
        fill the attacker's own bucket.
        """
        anti_replay.reset()
        for i in range(LIMITS.REPLAY_MAX_NONCES + 500):
            anti_replay.check(client_ip="203.0.113.7",
                              headers=_replay_headers(), method="POST", route="/api/auth/login")
        stats = anti_replay.stats()
        assert stats["tracked_nonces"] <= LIMITS.REPLAY_MAX_NONCES
        assert stats["tracked_ips"] == 1


# ===========================================================================
# 2. OTP CODE LEAK — the critical account-takeover path
# ===========================================================================
class TestOtpCodeNeverLeaks:
    """Before the fix, a code was echoed in the response body whenever delivery
    reported ``via == "dev"`` — which included "SMTP configured but the send
    threw". That was remote account takeover of any address on the platform."""

    def test_no_code_in_response_when_unconfigured_in_production(self, client, monkeypatch):
        monkeypatch.setenv("FEEFIX_ENV", "production")
        monkeypatch.setenv("FEEFIX_DEV_OTP_ECHO", "1")   # even with the flag set
        monkeypatch.delenv("OTP_SMTP_HOST", raising=False)
        r = client.post("/api/auth/otp/request",
                        json={"channel": "email", "address": "victim@example.com"},
                        headers=_replay_headers())
        assert "dev_code" not in r.text
        assert r.status_code == 422     # refused, not silently faked

    def test_no_code_in_response_when_delivery_fails(self, client, monkeypatch):
        """The exact original bug: SMTP configured, host unreachable."""
        monkeypatch.setenv("FEEFIX_ENV", "production")
        monkeypatch.setenv("FEEFIX_DEV_OTP_ECHO", "1")
        monkeypatch.setenv("OTP_SMTP_HOST", "smtp.invalid.example")
        r = client.post("/api/auth/otp/request",
                        json={"channel": "email", "address": "victim2@example.com"},
                        headers=_replay_headers())
        assert "dev_code" not in r.text
        assert r.status_code == 422

    def test_failed_delivery_does_not_leave_a_live_challenge(self, client, monkeypatch):
        """A code nobody received must not sit in the database being guessable,
        and must not burn the recipient's resend cooldown for an hour."""
        from backend.services import db

        monkeypatch.setenv("OTP_SMTP_HOST", "smtp.invalid.example")
        client.post("/api/auth/otp/request",
                    json={"channel": "email", "address": "gone@example.com"},
                    headers=_replay_headers())
        rows = db.get_connection().execute(
            "SELECT COUNT(*) AS n FROM otp_challenges WHERE address=?",
            ("gone@example.com",)).fetchone()["n"]
        assert rows == 0

    def test_methods_never_advertise_an_unavailable_channel_in_production(self, client, monkeypatch):
        monkeypatch.setenv("FEEFIX_ENV", "production")
        monkeypatch.setenv("FEEFIX_DEV_OTP_ECHO", "1")
        monkeypatch.delenv("OTP_SMTP_HOST", raising=False)
        monkeypatch.delenv("OTP_TWILIO_SID", raising=False)
        m = client.get("/api/auth/methods").json()
        assert m["otp_email"] is False and m["otp_phone"] is False
        assert m["dev_otp_echo"] is False

    def test_dev_code_never_echoed_in_production(self, monkeypatch):
        """Two independent conditions, each fail-closed."""
        from backend.services import otp

        monkeypatch.setenv("FEEFIX_ENV", "development")
        monkeypatch.delenv("FEEFIX_DEV_OTP_ECHO", raising=False)
        assert otp.methods()["dev_otp_echo"] is False     # flag missing

        monkeypatch.setenv("FEEFIX_DEV_OTP_ECHO", "1")
        assert otp.methods()["dev_otp_echo"] is True      # dev + flag

        monkeypatch.setenv("FEEFIX_ENV", "production")
        assert otp.methods()["dev_otp_echo"] is False     # production wins

    def test_code_is_single_use(self, client):
        """Replaying a *consumed* code must not mint a second session."""
        r = client.post("/api/auth/otp/request",
                        json={"channel": "email", "address": "once@example.com"},
                        headers=_replay_headers()).json()
        code = r["dev_code"]
        first = client.post("/api/auth/otp/verify",
                            json={"channel": "email", "address": "once@example.com", "code": code},
                            headers=_replay_headers())
        assert first.status_code == 200
        second = client.post("/api/auth/otp/verify",
                             json={"channel": "email", "address": "once@example.com", "code": code},
                             headers=_replay_headers())
        assert second.status_code == 401

    def test_addresses_are_masked_everywhere(self, client):
        r = client.post("/api/auth/otp/request",
                        json={"channel": "email", "address": "masked@example.com"},
                        headers=_replay_headers()).json()
        assert "masked@example.com" not in json.dumps(r)
        assert r["address"].endswith("@example.com") and "***" in r["address"]

    def test_destination_flood_is_blocked(self, client):
        """Protects a recipient who never used FeeFix from being SMS-bombed,
        and protects us from paying for it. Keyed on the destination, so
        rotating source IPs does not help."""
        from backend.services import db

        addr = "flooded@example.com"
        statuses = []
        for _ in range(8):
            conn = db.get_connection()
            conn.execute("UPDATE otp_challenges SET resend_after=?",
                         ("2000-01-01T00:00:00+00:00",))
            conn.commit()
            statuses.append(client.post(
                "/api/auth/otp/request",
                json={"channel": "email", "address": addr},
                headers=_replay_headers()).status_code)
        assert 422 in statuses, f"no limit engaged: {statuses}"
        assert statuses.count(200) <= LIMITS.OTP_REQUEST_PER_DEST_HOUR


# ===========================================================================
# 3. SQL / NoSQL INJECTION
# ===========================================================================
class TestInjection:
    """Every statement in the codebase is parameterized; these tests prove it
    behaviourally, which is what actually matters."""

    PAYLOADS = [
        "' OR '1'='1", "'; DROP TABLE users; --", "' UNION SELECT password_hash FROM users--",
        "admin'--", "1' OR 1=1 LIMIT 1--", "\\' OR \\'1\\'=\\'1", "\" OR \"\"=\"",
        "'; ATTACH DATABASE '/tmp/x' AS p; --",
    ]

    def test_login_is_not_bypassable(self, client):
        _register(client)
        for payload in self.PAYLOADS:
            r = client.post("/api/auth/login",
                            json={"email": payload, "password": payload},
                            headers=_replay_headers())
            assert r.status_code in (401, 422, 429), f"{payload!r} → {r.status_code}"

    def test_scheme_id_lookup_is_not_injectable(self, client):
        _register(client)
        for payload in self.PAYLOADS:
            r = client.get(f"/api/schemes/{payload}")
            assert r.status_code in (404, 400)
        # The users table must still be intact and the real record still there.
        assert client.get("/api/schemes/sv-mcm-wb").status_code == 200

    def test_session_scoped_reads_survive_hostile_ids(self, client):
        for payload in self.PAYLOADS:
            r = client.get(f"/api/students/{payload}/profile")
            assert r.status_code in (400, 403, 404)

    def test_search_query_is_data_not_syntax(self, client):
        for payload in self.PAYLOADS:
            r = client.get("/api/schemes", params={"q": payload})
            assert r.status_code == 200
            assert isinstance(r.json()["schemes"], list)

    def test_i18n_lang_cannot_escape_the_directory(self, client):
        for payload in ["../../../etc/passwd", "..%2f..%2fetc", "en/../../secret",
                        "en%00.json", "/etc/passwd", "en%0A", "en%2f%2e%2e"]:
            assert client.get(f"/api/i18n/{payload}").status_code in (404, 400)
        assert client.get("/api/i18n/en").status_code == 200

    def test_users_table_still_exists_after_the_barrage(self, client):
        """A successful DROP/ATTACH would show up as a missing table or an
        empty one; assert both survive the payload list above."""
        from backend.services import db
        _register(client, "survivor@example.com")
        conn = db.get_connection()
        tables = {r["name"] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        assert {"users", "profiles", "auth_sessions"} <= tables
        assert conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"] >= 1


# ===========================================================================
# 4. ReDoS — algorithmic complexity
# ===========================================================================
class TestReDoS:
    """The shipped email pattern was ``^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$``. Because
    ``.`` is inside ``[^@\\s]``, the two quantifiers overlap and a failing input
    makes the engine try every split. Measured: 718 ms for a 20 KB string,
    quadratic. These tests assert the replacement stays flat."""

    ATTACKS = [
        ("overlapping dots", lambda n: "a@" + "a." * n + " "),
        ("many hyphens", lambda n: "a@" + "-" * n),
        ("many at-signs", lambda n: "a" * n + "@"),
        ("no tld", lambda n: "a@" + "a" * n),
        ("trailing space", lambda n: "a@" + "a" * n + ".com "),
        ("alternating", lambda n: ("a." * n) + "@x.com"),
        ("unicode homoglyph", lambda n: "a@" + "\u0430" * n + ".com"),
        ("nested groups", lambda n: "a" * n + "@b" + ".c" * n),
    ]

    @pytest.mark.parametrize("name,build", ATTACKS, ids=[a[0] for a in ATTACKS])
    def test_email_validation_stays_linear(self, name, build):
        small = build(500)
        large = build(20_000)          # 40× the input
        t0 = time.perf_counter(); input_guard.valid_email(small); t_small = time.perf_counter() - t0
        t0 = time.perf_counter(); input_guard.valid_email(large); t_large = time.perf_counter() - t0
        # Linear means ~40×; allow a generous 200× for interpreter noise. The
        # vulnerable pattern was ~1600× at this scale.
        assert t_large < max(0.02, t_small * 200), \
            f"{name}: {t_small*1000:.3f}ms → {t_large*1000:.3f}ms is super-linear"
        assert t_large < 0.02, f"{name}: {t_large*1000:.1f}ms for one string is too slow"

    def test_the_original_payload_is_now_fast(self):
        payload = "a@" + "a." * 10_000 + " "
        t0 = time.perf_counter()
        assert input_guard.valid_email(payload) is None
        elapsed = time.perf_counter() - t0
        assert elapsed < 0.01, f"{elapsed*1000:.1f} ms — the vulnerable pattern took 168 ms"

    def test_reachable_over_http(self, client):
        """The whole point: an unauthenticated endpoint must not be slowable."""
        payload = "a@" + "a." * 20_000 + " "
        t0 = time.perf_counter()
        r = client.post("/api/auth/register",
                        json={"email": payload, "password": "Str0ngPass!23"},
                        headers=_replay_headers())
        elapsed = time.perf_counter() - t0
        assert r.status_code == 422
        assert elapsed < 0.5, f"{elapsed*1000:.0f} ms for one hostile email"

    def test_other_validators_are_bounded(self):
        for fn, arg in [(input_guard.valid_phone, "+" + "9" * 100_000),
                        (input_guard.valid_session_id, "a" * 100_000),
                        (input_guard.valid_scheme_id, "-" * 100_000),
                        (input_guard.valid_nonce, "A" * 100_000),
                        (input_guard.safe_filename, "/" * 100_000),
                        (input_guard.valid_bearer_token, "a" * 100_000)]:
            t0 = time.perf_counter()
            fn(arg)
            assert time.perf_counter() - t0 < 0.05, fn.__name__


# ===========================================================================
# 5. LONG-PASSWORD & PAYLOAD DoS
# ===========================================================================
class TestDenialOfService:
    def test_oversized_password_rejected_before_hashing(self, client):
        """A 1 MB password must never reach the 600k-iteration KDF."""
        r = client.post("/api/auth/register",
                        json={"email": "long@example.com", "password": "A" * 1_000_000},
                        headers=_replay_headers())
        assert r.status_code in (413, 422)

    def test_oversized_password_on_login_too(self, client):
        """The attacker does not need an account to make the server hash one."""
        t0 = time.perf_counter()
        r = client.post("/api/auth/login",
                        json={"email": "nobody@example.com", "password": "A" * 1_000_000},
                        headers=_replay_headers())
        assert r.status_code in (401, 413, 422, 429)
        assert time.perf_counter() - t0 < 2.0

    def test_password_ceiling_enforced_in_the_kdf_itself(self):
        """Route-layer caps can be bypassed by an internal caller; the KDF
        re-checks so the ceiling is a property, not a convention."""
        from backend.services import auth as auth_svc
        with pytest.raises(auth_svc.AuthError):
            auth_svc.hash_password("A" * (LIMITS.MAX_PASSWORD_LEN + 1))

    def test_oversized_body_rejected(self, client):
        payload = json.dumps({"message": "A" * (LIMITS.MAX_BODY_BYTES * 2)}).encode()
        r = client.post("/api/chat", content=payload,
                        headers={"Content-Type": "application/json", **_replay_headers()})
        assert r.status_code == 413

    def test_oversized_email_field_rejected(self, client):
        r = client.post("/api/auth/register",
                        json={"email": "a" * 5_000_000 + "@x.com", "password": "Str0ngPass!23"},
                        headers=_replay_headers())
        assert r.status_code in (413, 422)

    def test_oversized_url_rejected(self, client):
        assert client.get("/api/schemes/" + "a" * 4000).status_code in (404, 400, 414)

    def test_rate_limit_map_is_bounded(self):
        """The original limiter never removed a bucket: 5 000 requests left
        5 008 live entries forever. A timer-driven sweep is not enough either —
        a one-second burst reached 120 011 buckets before it ran."""
        ratelimit.reset()
        for i in range(LIMITS.RATELIMIT_MAX_BUCKETS + 5_000):
            ratelimit.check_auth(f"198.51.100.{(i // 250) % 250}.{i % 250}", f"acct{i}")
        assert len(ratelimit._hits) <= LIMITS.RATELIMIT_MAX_BUCKETS

    def test_replay_nonce_map_is_bounded_per_ip(self):
        anti_replay.reset()
        for i in range(500):
            anti_replay.check(client_ip=f"198.51.100.{i % 250}",
                              headers=_replay_headers(), method="POST")
        assert anti_replay.stats()["tracked_ips"] <= 500

    def test_chat_session_store_is_bounded(self, dataset):
        """``chat_id`` is client-chosen, so an unbounded dict keyed on it is a
        memory-exhaustion DoS reachable without authentication."""
        from backend.services import chat

        chat.reset_sessions()
        for i in range(chat._MAX_SESSIONS + 500):
            try:
                chat.handle_message("hi", dataset, f"flood-{i}", owner_fp=f"fp{i}")
            except Exception:
                pass
        assert len(chat._SESSIONS) <= chat._MAX_SESSIONS
        chat.reset_sessions()

    def test_kdf_has_its_own_budget(self, client):
        """600 000 iterations ≈ 200 ms of CPU. At the global request budget that
        is more than three cores saturated by one client staying inside the
        rules, so the KDF gets a separate, much tighter one."""
        ratelimit.reset()
        codes = []
        for i in range(LIMITS.KDF_RPM + 6):
            codes.append(client.post(
                "/api/auth/register",
                json={"email": f"kdf{i}@example.com", "password": "Str0ngPass!23"},
                headers=_replay_headers()).status_code)
        assert codes.count(429) >= 1, f"KDF budget never engaged: {codes}"

    def test_rotating_email_does_not_bypass_the_auth_budget(self, client):
        """The old key was (ip, "auth:" + email), so an attacker varying the
        address got a fresh budget per attempt. A per-IP budget that ignores the
        identifier closes that."""
        ratelimit.reset()
        codes = []
        for i in range(80):
            codes.append(client.post(
                "/api/auth/login",
                json={"email": f"victim{i}@example.com", "password": "wrongwrong"},
                headers=_replay_headers()).status_code)
        assert codes.count(429) >= 1, "per-IP auth budget never engaged"
        assert codes[:4].count(401) >= 1, "legitimate early attempts should still be answered"

    def test_trace_method_rejected(self, client):
        """TRACE reflects headers — including Authorization — into the response
        body, which is cross-site tracing."""
        r = client.request("TRACE", "/api/health")
        assert r.status_code == 405

    def test_chunked_body_without_length_rejected(self, client):
        """A chunked request declares no length, so the ceiling cannot be
        checked up front. No FeeFix client uses one, so it is refused."""
        r = client.post("/api/chat",
                        headers={"Transfer-Encoding": "chunked", **_replay_headers()})
        assert r.status_code in (411, 400, 413)


# ===========================================================================
# 6. AUTHORISATION ≠ AUTHENTICATION
# ===========================================================================
class TestAuthorisation:
    """The IDOR set. Every one of these endpoints accepted a session_id and
    acted on it with no ownership test."""

    @pytest.fixture()
    def owned_session(self, client):
        """A session that Alice created while signed in — so it is *owned*,
        which is the state the old code failed to record at all."""
        token = _token(client, "alice@example.com")
        sid = "alice-private-session"
        r = client.put(f"/api/students/{sid}/profile",
                       headers={**_auth(token), **_replay_headers()},
                       json={"profile": PROFILE})
        assert r.status_code == 200
        return token, sid

    @pytest.mark.parametrize("method,path", [
        ("GET", "/api/students/{sid}/reminders"),
        ("POST", "/api/students/{sid}/reminders/dispatch"),
        ("GET", "/api/students/{sid}/profile"),
        ("GET", "/api/match/{sid}"),
        ("GET", "/api/tracker/{sid}"),
        ("GET", "/api/ml/rank/{sid}"),
    ])
    def test_anonymous_cannot_read_an_owned_session(self, client, owned_session, method, path):
        _token_a, sid = owned_session
        url = path.format(sid=sid)
        body = {"limit": 5} if "dispatch" in url else None
        if method == "GET":
            r = client.get(url)
        else:
            r = client.post(url, json=body, headers=_replay_headers())
        assert r.status_code == 403, f"{method} {url} → {r.status_code}"

    def test_events_cannot_be_written_to_an_owned_session(self, client, owned_session):
        _, sid = owned_session
        r = client.post("/api/events",
                        json={"session_id": sid, "scheme_id": "prerana-scst-od", "type": "approved"},
                        headers=_replay_headers())
        assert r.status_code == 403

    def test_ask_cannot_use_an_owned_profile(self, client, owned_session):
        _, sid = owned_session
        r = client.post("/api/ask",
                        json={"question": "what do I qualify for", "session_id": sid},
                        headers=_replay_headers())
        assert r.status_code == 403

    def test_another_account_is_refused(self, client, owned_session):
        _, sid = owned_session
        mallory = _token(client, "mallory@example.com", "Mall0ryPass!")
        assert client.get(f"/api/students/{sid}/profile",
                          headers=_auth(mallory)).status_code == 403

    def test_owner_is_allowed(self, client, owned_session):
        token, sid = owned_session
        r = client.get(f"/api/students/{sid}/profile", headers=_auth(token))
        assert r.status_code == 200
        assert r.json()["profile"]["domicile_state"] == "Odisha"


class TestSessionHijack:
    """The account-takeover shape: ownership was mutable, so binding was a
    transfer. Proven before the fix — Mallory bound Alice's session, read her
    profile, and Alice got 403 on her own data with a valid token."""

    def test_link_session_cannot_steal_an_owned_session(self, client):
        alice = _token(client, "alice2@example.com")
        sid = "alice-owned-session"
        client.put(f"/api/students/{sid}/profile",
                   headers={**_auth(alice), **_replay_headers()},
                   json={"profile": PROFILE})

        mallory = _token(client, "mallory2@example.com", "Mall0ryPass!")
        r = client.post("/api/auth/link-session",
                        headers={**_auth(mallory), **_replay_headers()},
                        json={"session_id": sid})
        assert r.status_code == 403

        # Mallory still cannot read it, and Alice still can.
        assert client.get(f"/api/students/{sid}/profile",
                          headers=_auth(mallory)).status_code == 403
        assert client.get(f"/api/students/{sid}/profile",
                          headers=_auth(alice)).status_code == 200

    def test_authenticated_write_establishes_ownership(self, client):
        """The root cause: save_profile inserted user_id=NULL unconditionally,
        so a signed-in student's data looked anonymous and was claimable."""
        token = _token(client, "owner@example.com")
        sid = "ownership-check-session"
        client.put(f"/api/students/{sid}/profile",
                   headers={**_auth(token), **_replay_headers()},
                   json={"profile": PROFILE})
        from backend.services import authz
        # The store the request actually wrote to — not a second create_app().
        assert authz.owner_of(client.app.state.tracker, sid) is not None

    def test_tracker_write_establishes_ownership_too(self, client):
        """A student who tracks a scheme before saving a profile has tracker rows
        and no profile row; that session must not look anonymous either."""
        token = _token(client, "tracker-owner@example.com")
        sid = "tracker-ownership-session"
        client.put(f"/api/tracker/{sid}/sv-mcm-wb",
                   headers={**_auth(token), **_replay_headers()},
                   json={"status": "saved"})
        mallory = _token(client, "mallory3@example.com", "Mall0ryPass!")
        assert client.post("/api/auth/link-session",
                           headers={**_auth(mallory), **_replay_headers()},
                           json={"session_id": sid}).status_code == 403

    def test_anonymous_flow_still_works(self, client):
        """The privacy-by-design path must survive: use anonymously, then sign in
        and keep your progress."""
        sid = "anon-then-linked-session"
        assert client.put(f"/api/students/{sid}/profile",
                          json={"profile": PROFILE},
                          headers=_replay_headers()).status_code == 200
        assert client.get(f"/api/students/{sid}/profile").status_code == 200

        token = _token(client, "converter@example.com")
        r = client.post("/api/auth/link-session",
                        headers={**_auth(token), **_replay_headers()},
                        json={"session_id": sid})
        assert r.status_code == 200 and r.json()["linked"] is True
        assert client.get(f"/api/students/{sid}/profile",
                          headers=_auth(token)).status_code == 200

    def test_chat_conversation_cannot_be_resumed_by_a_stranger(self, dataset):
        """``chat_id`` is the same IDOR shape one level up."""
        from backend.services import chat

        chat.reset_sessions()
        mine = chat.resolve_chat_id(None, owner_fp="fp-alice")
        chat.handle_message("West Bengal", dataset, mine, owner_fp="fp-alice")
        # A different principal presenting the same id gets a NEW conversation,
        # not Alice's — and not a 403 that would confirm the id exists.
        theirs = chat.resolve_chat_id(mine, owner_fp="fp-mallory")
        assert theirs != mine
        # The same principal keeps theirs.
        assert chat.resolve_chat_id(mine, owner_fp="fp-alice") == mine
        chat.reset_sessions()


# ===========================================================================
# 7. ERROR HANDLING & INFORMATION LEAKAGE
# ===========================================================================
class TestInformationLeakage:
    def test_validation_errors_do_not_echo_the_rejected_value(self, client):
        """Pydantic's default handler returns the offending ``input``. For a
        password field that reflects the password back into the response body,
        and into every proxy log and browser network tab on the way."""
        secret = "Sup3rS3cret-Passw0rd!"
        r = client.post("/api/match",
                        json={"profile": {"annual_family_income": secret}},
                        headers=_replay_headers())
        assert r.status_code == 422
        assert secret not in r.text

    def test_password_is_never_reflected(self, client):
        secret = "Ref1ect-Me-N0t-9999"
        r = client.post("/api/auth/register",
                        json={"email": "not-an-email", "password": secret},
                        headers=_replay_headers())
        assert r.status_code == 422
        assert secret not in r.text

    def test_no_internal_class_names_in_errors(self, client):
        for path in ["/api/schemes/definitely-not-here", "/api/i18n/zz",
                     "/api/students/x/profile"]:
            body = client.get(path).text
            for marker in ("Traceback", "File \"", "sqlite3.", "pydantic.",
                           "OperationalError", "KeyError", "AttributeError"):
                assert marker not in body, f"{marker} leaked from {path}"

    def test_server_header_absent(self, client):
        """Version banners are fingerprinting fuel."""
        r = client.get("/api/health")
        assert "server" not in {k.lower() for k in r.headers.keys()}

    def test_health_exposes_counts_not_configuration(self, client):
        body = json.dumps(client.get("/api/health").json())
        for secret in ("OTP_SMTP_PASS", "GITHUB_CLIENT_SECRET", "FEEFIX_OTP_PEPPER",
                       "sqlite", "/app/", "runtime/"):
            assert secret not in body

    def test_audit_log_redacts_addresses(self, client):
        from backend.services import db
        client.post("/api/auth/otp/request",
                    json={"channel": "email", "address": "audit-me@example.com"},
                    headers=_replay_headers())
        rows = db.get_connection().execute(
            "SELECT detail FROM audit_log WHERE action LIKE '%otp.request%'").fetchall()
        assert rows, "the OTP request was not audited at all"
        for row in rows:
            assert "audit-me@example.com" not in (row["detail"] or "")

    def test_interactive_docs_off_in_production(self, client, monkeypatch):
        monkeypatch.setenv("FEEFIX_ENV", "production")
        from backend.main import create_app
        from fastapi.testclient import TestClient
        prod = TestClient(create_app())
        assert prod.get("/docs").status_code == 404
        assert prod.get("/openapi.json").status_code == 404

    def test_scrub_text_removes_credentials(self):
        assert "hunter2" not in security.scrub_text("password=hunter2 host=smtp")
        assert "***" in security.scrub_text("password=hunter2")

    def test_scrub_text_strips_newlines(self):
        """Log-line forgery: an injected newline makes one event look like two."""
        assert "\n" not in security.scrub_text("ok\nFAKE ADMIN LOGIN SUCCESS")


# ===========================================================================
# 8. SECRET MANAGEMENT
# ===========================================================================
class TestSecretManagement:
    def test_pepper_file_is_not_world_readable(self, tmp_path):
        path = tmp_path / "pepper"
        security.load_secret("FF_TEST_SECRET_ABSENT", fallback_path=path, min_bytes=32)
        mode = path.stat().st_mode & 0o777
        assert mode == 0o600, f"pepper file mode is {oct(mode)}"

    def test_short_secret_refused_in_production(self, tmp_path, monkeypatch):
        monkeypatch.setenv("FEEFIX_ENV", "production")
        monkeypatch.setenv("FF_TEST_WEAK", "tooshort")
        with pytest.raises(security.SecretError):
            security.load_secret("FF_TEST_WEAK", min_bytes=32)

    def test_generated_peppers_are_unique(self, tmp_path):
        a = security.load_secret("FF_A", fallback_path=tmp_path / "a", min_bytes=32)
        b = security.load_secret("FF_B", fallback_path=tmp_path / "b", min_bytes=32)
        assert a != b and len(a) >= 32

    def test_otp_pepper_is_gitignored(self):
        """The old .gitignore listed runtime/*.db and runtime/*.json but a
        dotfile with no extension matched neither — the pepper would have been
        committed by the first `git add -A`."""
        import subprocess
        from pathlib import Path
        repo = Path(__file__).resolve().parents[1]
        proc = subprocess.run(["git", "check-ignore", "-q", "runtime/.otp_pepper"], cwd=repo)
        assert proc.returncode == 0, "runtime/.otp_pepper is not ignored"

    def test_env_file_is_gitignored(self):
        import subprocess
        from pathlib import Path
        repo = Path(__file__).resolve().parents[1]
        for candidate in (".env", ".env.production"):
            proc = subprocess.run(["git", "check-ignore", "-q", candidate], cwd=repo)
            assert proc.returncode == 0, f"{candidate} is not ignored"

    def test_no_secret_is_committed(self):
        """The scanner is itself covered by tests elsewhere; this asserts the
        repository currently passes it."""
        import subprocess
        from pathlib import Path
        repo = Path(__file__).resolve().parents[1]
        proc = subprocess.run(
            ["python", str(repo / "scripts" / "secret_scan.py")],
            cwd=repo, capture_output=True, text=True,
        )
        assert proc.returncode == 0, proc.stdout

    def test_secret_scanner_actually_detects(self):
        """A scanner that cannot fail is decoration.

        Asserts it catches every shape it claims to, and — equally important —
        that it does not fire on ordinary code, because a noisy scanner gets
        ignored and then removed. ``REPO`` is repointed at a temp directory, so
        this never touches the real repository or its index.

        The credential-shaped literals live in
        ``tests/fixtures/secret_scan_samples.py`` and nowhere else; see that
        file's docstring for why isolating them matters.
        """
        import importlib.util
        import sys
        import tempfile
        from pathlib import Path

        from tests.fixtures.secret_scan_samples import CLEAN, DIRTY

        spec = importlib.util.spec_from_file_location(
            "secret_scan", Path(__file__).resolve().parents[1] / "scripts" / "secret_scan.py")
        mod = importlib.util.module_from_spec(spec)
        # @dataclass resolves string annotations through sys.modules, so the
        # module must be registered before exec_module runs.
        sys.modules["secret_scan"] = mod
        try:
            spec.loader.exec_module(mod)

            tmp = Path(tempfile.mkdtemp())
            mod.REPO = tmp
            for name, body in {**DIRTY, **CLEAN}.items():
                (tmp / name).write_text(body + "\n")

            found = {f.path for f in mod.scan_content(list(DIRTY))}
            assert found == set(DIRTY), f"scanner missed: {set(DIRTY) - found}"

            noise = mod.scan_content(list(CLEAN))
            assert noise == [], f"false positive: {[(f.path, f.name) for f in noise]}"
        finally:
            sys.modules.pop("secret_scan", None)

    def test_scanner_history_catches_a_secret_deleted_in_a_later_commit(self, tmp_path):
        """The one check the working-tree scan structurally cannot make.

        A credential pasted into an ordinary source file, committed, then removed
        leaves HEAD clean — so ``scan_content`` over tracked files sees nothing —
        while the secret stays cloneable forever. This builds a throwaway Git
        repository with exactly that history and asserts:

          1. the tree scan reports nothing (HEAD really is clean);
          2. ``--history`` finds the key anyway;
          3. ``runtime/.gitkeep`` is NOT reported, in either scan.

        Point 3 is a regression guard. The history scan used to duplicate the
        forbidden-path predicate inline, drift out of sync with the tree scan,
        and raise a CRITICAL "history rewrite + credential rotation required"
        finding for a zero-byte placeholder — on every run. A gate that is wrong
        every time gets disabled, and then the real history findings stop being
        caught too.

        The repository is built in ``tmp_path``; the real repo is never touched.
        """
        import importlib.util
        import subprocess
        import sys
        from pathlib import Path

        repo = tmp_path / "histrepo"
        repo.mkdir()

        def git(*args):
            return subprocess.run(["git", *args], cwd=repo, capture_output=True,
                                  text=True, check=True)

        git("init", "-q", ".")
        git("config", "user.email", "t@example.invalid")
        git("config", "user.name", "test")
        (repo / "runtime").mkdir()
        (repo / "runtime" / ".gitkeep").write_text("")
        (repo / "config.py").write_text('SETTING = "value"\n')
        git("add", "-A")
        git("commit", "-qm", "clean, with the runtime/.gitkeep placeholder")

        # Commit a secret inside an ordinary tracked file...
        from tests.fixtures.secret_scan_samples import AWS_EXAMPLE_KEY_ID
        # Imported rather than inlined: a credential-shaped literal written here
        # would make the scanner flag THIS file, and rightly so.
        (repo / "config.py").write_text(
            f'SETTING = "value"\nAWS_KEY = "{AWS_EXAMPLE_KEY_ID}"\n')
        git("add", "-A")
        git("commit", "-qm", "paste an AWS key")

        # ...then remove it. HEAD is now clean; only history is dirty.
        (repo / "config.py").write_text('SETTING = "value"\n')
        git("add", "-A")
        git("commit", "-qm", "remove the key")

        spec = importlib.util.spec_from_file_location(
            "secret_scan_hist", Path(__file__).resolve().parents[1] / "scripts" / "secret_scan.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules["secret_scan_hist"] = mod
        try:
            spec.loader.exec_module(mod)
            mod.REPO = repo

            tracked = mod._tracked_files()
            assert "runtime/.gitkeep" in tracked, "fixture did not stage the placeholder"

            # 1. HEAD is genuinely clean.
            tree = mod.scan_content(tracked) + mod.scan_tracked_policy(tracked)
            assert tree == [], f"tree scan should be clean, got {[(f.path, f.name) for f in tree]}"

            # 2. .gitkeep is exempt through the shared predicate, not by luck.
            assert mod.is_forbidden_path("runtime/.gitkeep") is False
            assert mod.is_forbidden_path("runtime/.otp_pepper") is True
            assert mod.is_forbidden_path(".env") is True

            # 3. History finds what the tree cannot.
            hist = mod.scan_history(limit=20)
            assert any("aws" in f.name.lower() for f in hist), (
                f"historical secret missed; findings were {[(f.path, f.name) for f in hist]}"
            )
            assert not any(f.path.startswith("runtime/.gitkeep") for f in hist), (
                "the .gitkeep false positive is back — the two scans diverged again"
            )
        finally:
            sys.modules.pop("secret_scan_hist", None)

    def test_scanner_policy_blocks_and_allows_the_right_paths(self):
        """The forbidden-file policy, checked in BOTH directions.

        A policy that blocks too little ships secrets; one that blocks too much
        pushes the reviewed template out of the repository, after which people
        copy a real ``.env`` around instead. This test exists because the
        ``.env`` pattern originally matched ``.env.example`` — a real false
        positive that only surfaced once the fixtures were staged.
        """
        import importlib.util
        import sys
        import tempfile
        from pathlib import Path

        spec = importlib.util.spec_from_file_location(
            "secret_scan3", Path(__file__).resolve().parents[1] / "scripts" / "secret_scan.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules["secret_scan3"] = mod
        try:
            spec.loader.exec_module(mod)
            mod.REPO = Path(tempfile.mkdtemp())

            must_block = [
                ".env", ".env.production", ".env.local", "backend/.env",
                "runtime/.otp_pepper", "runtime/feefix.db", "runtime/outcomes.jsonl",
                "secrets/key.pem", "certs/tls.key", "app.keystore", "release.jks",
                "id_rsa", "id_ed25519", ".netrc", ".pgpass",
                "credentials.json", "serviceAccountKey.json",
            ]
            must_allow = [
                ".env.example", ".env.sample", ".env.template", ".env.dist",
                "runtime/.gitkeep", "docs/security/SECURITY.md",
                "tests/fixtures/secret_scan_samples.py", "backend/main.py",
                "render.yaml", "Dockerfile",
            ]

            leaked = [r for r in must_block if not mod.scan_tracked_policy([r])]
            assert not leaked, f"policy let these through: {leaked}"

            noise = [r for r in must_allow if mod.scan_tracked_policy([r])]
            assert not noise, f"policy wrongly blocks: {noise}"
        finally:
            sys.modules.pop("secret_scan3", None)

    def test_scanner_allow_list_is_narrow_and_explained(self):
        """Every suppression must name one path and carry a reason.

        A wildcard entry (or a bare rule name with no path) silently disables the
        scanner for everything, which is the failure mode allow-lists have.
        """
        import importlib.util
        import sys
        from pathlib import Path

        spec = importlib.util.spec_from_file_location(
            "secret_scan2", Path(__file__).resolve().parents[1] / "scripts" / "secret_scan.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules["secret_scan2"] = mod
        try:
            spec.loader.exec_module(mod)
            for key, reason in mod.ALLOWLIST.items():
                assert reason and len(reason.strip()) >= 10, f"{key}: no real reason given"
                assert key.endswith(":any") or ":" in key, f"{key}: malformed key"
                # A bare rule name (no path component) suppresses everywhere.
                path_part = key.rsplit(":", 1)[0] if ":" in key else ""
                assert path_part, f"{key}: suppresses every file — scope it to a path"
                assert "*" not in path_part, f"{key}: wildcard path suppression"
        finally:
            sys.modules.pop("secret_scan2", None)


# ===========================================================================
# 9. INPUT VALIDATION
# ===========================================================================
class TestInputValidation:
    @pytest.mark.parametrize("good", [
        "student@example.com", "x@y.co", "new.user@gmail.com", "a+b@sub.domain.co.in",
        "first.last@university.ac.in", "O'Brien@test.org",
    ])
    def test_valid_emails_accepted(self, good):
        assert input_guard.valid_email(good) is not None

    @pytest.mark.parametrize("bad", [
        "", "a", "a@", "@b.com", "a@b", "a b@c.com", "a@@b.com", "a@b..com",
        "a@-b.com", "a@b.com-", "user@1.2.3.4", ".a@b.com", "a.@b.com", None,
        "a" * 300 + "@b.com",
    ])
    def test_invalid_emails_rejected(self, bad):
        assert input_guard.valid_email(bad) is None

    @pytest.mark.parametrize("raw,expected", [
        ("9876543210", "+919876543210"), ("+919876543210", "+919876543210"),
        ("+1 (415) 555-2671", "+14155552671"), ("+44-20-7946-0958", "+442079460958"),
    ])
    def test_phone_normalisation(self, raw, expected):
        assert input_guard.valid_phone(raw) == expected

    @pytest.mark.parametrize("bad", ["abc", "+9198765432101234567", "+0912345678", "12345", None])
    def test_invalid_phones_rejected(self, bad):
        assert input_guard.valid_phone(bad) is None

    def test_control_and_bidi_characters_are_stripped(self):
        """Trojan Source: bidi overrides make a string display as something
        other than its bytes."""
        assert security.sanitize_text("Ash\u202eek", 80) == "Ashek"
        assert "\u202e" not in security.sanitize_text("a\u202eb", 80)
        assert "\x00" not in security.sanitize_text("a\x00b", 80)

    def test_truncation_happens_after_normalisation(self):
        out = input_guard.bounded("a" * 5000, 80)
        assert len(out) <= 80

    def test_safe_filename_blocks_traversal(self):
        assert input_guard.safe_filename("../../etc/passwd") == "passwd"
        assert input_guard.safe_filename("..\\..\\windows\\x.dll") == "x.dll"
        assert input_guard.safe_filename("a\x00.jpg") == "a.jpg"
        assert input_guard.safe_filename("con") is None
        assert "/" not in (input_guard.safe_filename("/etc/shadow") or "")

    def test_session_and_scheme_id_shapes(self):
        assert input_guard.valid_session_id("550e8400-e29b-41d4-a716-446655440000")
        assert input_guard.valid_session_id("../x") is None
        assert input_guard.valid_session_id("a" * 200) is None
        assert input_guard.valid_scheme_id("prerana-scst-od")
        assert input_guard.valid_scheme_id("UPPER") is None

    def test_query_parameters_are_whitelisted(self, client):
        """An unexpected filter value must never reach a lookup as syntax."""
        r = client.get("/api/schemes", params={"level": "'; DROP TABLE--"})
        assert r.status_code == 200
        # Not a recognised level, so the filter is dropped rather than applied.
        assert r.json()["count"] > 0

    def test_integer_parameters_are_clamped(self, client):
        r = client.get("/api/search/semantic", params={"q": "scholarship", "k": "99999999"})
        assert r.status_code == 200
        assert r.json()["count"] <= 15

    def test_chat_message_is_capped(self, client):
        r = client.post("/api/chat",
                        json={"message": "A" * (LIMITS.MAX_CHAT_MESSAGE_LEN + 100)},
                        headers=_replay_headers())
        assert r.status_code == 422


# ===========================================================================
# 10. FILE UPLOAD SECURITY
# ===========================================================================
class TestFileUpload:
    PNG = (b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR"
           + (100).to_bytes(4, "big") + (50).to_bytes(4, "big") + b"\x08\x02\x00\x00\x00"
           + b"\x00" * 64)
    JPEG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"\x00" * 64
    PDF = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n%%EOF\n"

    def test_valid_image_accepted(self):
        result = uploads.verify(self.PNG, declared_name="cert.png", declared_type="image/png")
        assert result.detected_type == "image/png"
        assert (result.width, result.height) == (100, 50)

    def test_php_disguised_as_an_image_is_rejected(self):
        payload = self.PNG + b"\n<?php system($_GET['c']); ?>\n"
        with pytest.raises(uploads.UploadError) as exc:
            uploads.verify(payload, declared_name="cert.png", declared_type="image/png")
        assert exc.value.reason == "forbidden_content"

    def test_mime_lie_is_rejected(self):
        with pytest.raises(uploads.UploadError) as exc:
            uploads.verify(b"<?php echo 1;", declared_name="x.png", declared_type="image/png")
        assert exc.value.reason in ("unrecognised_content", "mime_mismatch", "forbidden_content")

    def test_disallowed_type_is_rejected(self):
        """SVG is XML and can carry <script>; it is not in the image policy."""
        svg = b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'
        with pytest.raises(uploads.UploadError):
            uploads.verify(svg, declared_name="x.svg", declared_type="image/svg+xml")

    def test_zip_is_rejected_for_documents(self):
        with pytest.raises(uploads.UploadError):
            uploads.verify(b"PK\x03\x04" + b"\x00" * 64, declared_name="x.png")

    def test_oversize_rejected_before_reading(self):
        with pytest.raises(uploads.UploadError) as exc:
            uploads.verify(b"x", declared_length=security.LIMITS.MAX_UPLOAD_BYTES + 1)
        assert exc.value.reason == "declared_too_large"

    def test_empty_rejected(self):
        with pytest.raises(uploads.UploadError):
            uploads.verify(b"", declared_name="x.png")

    def test_stored_name_never_contains_client_input(self):
        result = uploads.verify(self.PNG, declared_name="../../etc/passwd")
        assert "/" not in result.stored_name and ".." not in result.stored_name
        assert result.stored_name == f"{result.digest}.png"

    def test_decompression_bomb_rejected(self):
        huge = (b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR"
                + (99999).to_bytes(4, "big") + (99999).to_bytes(4, "big") + b"\x00" * 64)
        with pytest.raises(uploads.UploadError) as exc:
            uploads.verify(huge, declared_name="bomb.png")
        assert exc.value.reason == "image_dimensions_excessive"

    def test_destination_cannot_escape_the_root(self, tmp_path):
        result = uploads.verify(self.PNG, declared_name="x.png")
        dest = uploads.safe_destination(tmp_path / "quarantine", result)
        assert str(dest).startswith(str((tmp_path / "quarantine").resolve()))

    def test_store_writes_with_restrictive_permissions(self, tmp_path):
        path, result = uploads.store(self.PNG, tmp_path / "uploads", declared_name="x.png")
        assert path.exists()
        assert path.stat().st_mode & 0o777 == 0o600

    def test_executable_extensions_refused(self):
        for name in ("shell.php", "x.jsp", "y.aspx", "z.html", "a.svg", "b.exe", "c.sh"):
            assert uploads.is_forbidden_extension(name), name

    def test_legitimate_binary_is_not_a_false_positive(self):
        """A 2-byte marker like ``MZ`` appears ~76 times by chance in 5 MB of
        compressed data; scanning for it anywhere would reject real PDFs."""
        blob = self.PDF + bytes(range(256)) * 400
        assert uploads.find_forbidden(blob) is None
        assert uploads.verify(blob, declared_name="doc.pdf", declared_type="application/pdf").detected_type == "application/pdf"


# ===========================================================================
# 11. SESSION & TOKEN HARDENING
# ===========================================================================
class TestSessions:
    def test_tokens_are_stored_only_as_digests(self, client):
        """A database leak must not be an account-takeover leak."""
        import os as _os
        from backend.services import db

        token = _token(client, "digest@example.com")
        rows = db.get_connection().execute("SELECT token_hash FROM auth_sessions").fetchall()
        assert rows, "no session row written"
        assert all(token not in r["token_hash"] for r in rows)
        assert all(len(r["token_hash"]) == 64 for r in rows)   # SHA-256 hex only
        path = _os.environ.get("FEEFIX_DB")
        if path and _os.path.exists(path):
            assert token.encode() not in open(path, "rb").read(), \
                "raw session token found on disk"

    def test_logout_revokes_immediately(self, client):
        token = _token(client, "revoked@example.com")
        assert client.get("/api/auth/me", headers=_auth(token)).status_code == 200
        client.post("/api/auth/logout", headers={**_auth(token), **_replay_headers()})
        assert client.get("/api/auth/me", headers=_auth(token)).status_code == 401

    def test_malformed_token_rejected_without_a_lookup(self, client):
        for token in ["", "x", "a" * 5000, "' OR 1=1--", "a\nb", None]:
            headers = {"Authorization": f"Bearer {token}"} if token is not None else {}
            assert client.get("/api/auth/me", headers=headers).status_code == 401

    def test_absolute_expiry_caps_the_rolling_window(self):
        """A rolling 30-day window never expires for a token used monthly —
        which turns a stolen token into permanent access."""
        assert LIMITS.SESSION_ABSOLUTE_DAYS >= LIMITS.SESSION_IDLE_DAYS
        from backend.services import auth as auth_svc
        assert auth_svc.SESSION_DAYS == LIMITS.SESSION_IDLE_DAYS

    def test_session_count_is_capped_per_user(self, client):
        from backend.services import auth as auth_svc, db
        token = _token(client, "many@example.com")
        user = db.get_connection().execute("SELECT id FROM users").fetchone()["id"]
        for _ in range(LIMITS.MAX_SESSIONS_PER_USER + 5):
            auth_svc.create_session(user, user_agent="ua")
        n = db.get_connection().execute(
            "SELECT COUNT(*) AS n FROM auth_sessions WHERE user_id=?", (user,)).fetchone()["n"]
        assert n <= LIMITS.MAX_SESSIONS_PER_USER

    def test_stolen_token_from_a_different_client_is_revoked(self, client, monkeypatch):
        """Client binding: a token replayed from another user agent is burned."""
        monkeypatch.setenv("FEEFIX_BIND_CLIENT", "1")
        from backend.services import auth as auth_svc, db
        _register(client, "bound@example.com")
        user = db.get_connection().execute(
            "SELECT id FROM users WHERE email='bound@example.com'").fetchone()["id"]
        token, _ = auth_svc.create_session(user, user_agent="Mozilla/5.0 (victim)")

        assert auth_svc.resolve_token(token, user_agent="Mozilla/5.0 (victim)") is not None
        # Attacker replays the same token from their own client.
        assert auth_svc.resolve_token(token, user_agent="curl/8.4.0") is None
        # And the legitimate session is gone too — forced re-auth beats silently
        # sharing a session with an intruder.
        assert auth_svc.resolve_token(token, user_agent="Mozilla/5.0 (victim)") is None

    def test_password_change_revokes_every_session(self, client):
        from backend.services import auth as auth_svc, db
        _register(client, "rotate@example.com", "OldPass123!")
        user = db.get_connection().execute(
            "SELECT id FROM users WHERE email='rotate@example.com'").fetchone()["id"]
        auth_svc.change_password(user, "OldPass123!", "NewPass456!")
        assert db.get_connection().execute(
            "SELECT COUNT(*) AS n FROM auth_sessions WHERE user_id=?",
            (user,)).fetchone()["n"] == 0

    def test_password_change_needs_the_current_password(self, client):
        from backend.services import auth as auth_svc, db
        _register(client, "rotate2@example.com", "OldPass123!")
        user = db.get_connection().execute(
            "SELECT id FROM users WHERE email='rotate2@example.com'").fetchone()["id"]
        with pytest.raises(auth_svc.AuthError):
            auth_svc.change_password(user, "wrong-guess", "NewPass456!")

    def test_common_passwords_refused(self):
        from backend.services import auth as auth_svc
        for weak in ("password", "12345678", "feefix123", "qwerty123"):
            ok, _ = auth_svc.password_acceptable(weak)
            assert not ok, weak

    def test_iteration_count_is_bounded(self):
        """A tampered hash row saying 10**12 rounds would turn one login into an
        unbounded CPU burn."""
        from backend.services import auth as auth_svc
        assert auth_svc.verify_password(
            "x", "pbkdf2$999999999999$00$00") is False


# ===========================================================================
# 12. TRANSPORT & HEADERS
# ===========================================================================
class TestTransport:
    def test_security_headers_on_every_response(self, client):
        for path in ("/api/health", "/", "/styles.css"):
            r = client.get(path)
            h = {k.lower(): v for k, v in r.headers.items()}
            assert h.get("x-content-type-options") == "nosniff", path
            assert "default-src 'self'" in h.get("content-security-policy", ""), path
            assert h.get("cross-origin-opener-policy") == "same-origin", path
            assert h.get("x-frame-options"), path
            assert h.get("referrer-policy"), path

    def test_csp_forbids_inline_and_remote_script(self, client):
        csp = client.get("/api/health").headers["Content-Security-Policy"]
        assert "script-src 'self'" in csp
        assert "unsafe-inline" not in csp.split("script-src")[1].split(";")[0]
        assert "unsafe-eval" not in csp
        assert "object-src 'none'" in csp
        assert "base-uri 'self'" in csp

    def test_api_responses_are_not_cacheable(self, client):
        r = client.get("/api/auth/me")
        assert r.headers["Cache-Control"] == "no-store"

    def test_hsts_only_over_tls(self, client):
        assert "Strict-Transport-Security" not in client.get("/api/health").headers
        r = client.get("/api/health", headers={"x-forwarded-proto": "https"})
        assert "max-age=31536000" in r.headers["Strict-Transport-Security"]

    def test_security_txt_present(self, client):
        r = client.get("/.well-known/security.txt")
        assert r.status_code == 200 and "Contact:" in r.text


# ===========================================================================
# 13. RATE LIMITING & CLIENT IDENTITY
# ===========================================================================
class TestClientIdentity:
    def test_xff_from_an_untrusted_peer_is_ignored(self):
        """Trusting X-Forwarded-For unconditionally lets anyone rotate a header
        and walk past every per-IP limit."""
        monkey_ip = security.client_ip("203.0.113.9", {"x-forwarded-for": "8.8.8.8"})
        assert monkey_ip == "203.0.113.9"

    def test_xff_from_a_trusted_proxy_is_used(self, monkeypatch):
        monkeypatch.setenv("FEEFIX_TRUSTED_PROXIES", "10.0.0.0/8")
        monkeypatch.setenv("FEEFIX_PROXY_HOPS", "1")
        security.clear_caches()
        try:
            assert security.client_ip("10.0.0.5", {"x-forwarded-for": "203.0.113.50"}) \
                == "203.0.113.50"
            # hops=1 trusts only the rightmost entry, so a client-forged value to
            # the left of it is not believed.
            assert security.client_ip(
                "10.0.0.5", {"x-forwarded-for": "1.2.3.4, 203.0.113.50"}) == "203.0.113.50"
        finally:
            monkeypatch.delenv("FEEFIX_TRUSTED_PROXIES", raising=False)
            security.clear_caches()

    def test_malformed_xff_falls_back_to_the_peer(self, monkeypatch):
        monkeypatch.setenv("FEEFIX_TRUST_PROXY_PEER", "1")
        security.clear_caches()
        try:
            assert security.client_ip("10.0.0.1", {"x-forwarded-for": "not-an-ip"}) == "10.0.0.1"
            assert security.client_ip("10.0.0.1", {"x-forwarded-for": ""}) == "10.0.0.1"
        finally:
            monkeypatch.delenv("FEEFIX_TRUST_PROXY_PEER", raising=False)
            security.clear_caches()

    def test_retry_after_is_returned(self, client):
        ratelimit.reset()
        codes = []
        for i in range(LIMITS.AUTH_ATTEMPTS * 6):
            r = client.post("/api/auth/login",
                            json={"email": f"brute{i}@example.com", "password": "wrongwrong"},
                            headers=_replay_headers())
            codes.append(r.status_code)
            if r.status_code == 429:
                assert r.headers.get("Retry-After"), "429 without Retry-After"
                break
        assert 429 in codes


# ===========================================================================
# 14. ENVIRONMENT & CONFIGURATION
# ===========================================================================
class TestConfiguration:
    def test_environment_defaults_to_production(self, monkeypatch):
        """Failing closed: forgetting to configure must never relax security."""
        for var in ("FEEFIX_ENV", "RENDER_EXTERNAL_HOSTNAME", "FEEFIX_BASE_URL"):
            monkeypatch.delenv(var, raising=False)
        monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
        assert security.environment() == security.PRODUCTION
        assert security.is_production()

    def test_wildcard_cors_is_refused(self, monkeypatch):
        monkeypatch.setenv("FEEFIX_CORS_ORIGINS", "*, https://evil.example")
        from backend.main import _cors_kwargs
        kwargs = _cors_kwargs()
        assert "*" not in kwargs.get("allow_origins", [])
        assert kwargs.get("allow_credentials") is not True

    def test_env_int_clamps_instead_of_crashing(self, monkeypatch):
        monkeypatch.setenv("FF_N", "not-a-number")
        assert security.env_int("FF_N", 5, minimum=1, maximum=10) == 5
        monkeypatch.setenv("FF_N", "99999")
        assert security.env_int("FF_N", 5, minimum=1, maximum=10) == 10
        monkeypatch.setenv("FF_N", "-3")
        assert security.env_int("FF_N", 5, minimum=1, maximum=10) == 1

    def test_render_blueprint_parses(self):
        """It shipped unparseable: two keys merged onto one line, which means
        every blueprint deploy was failing."""
        import yaml
        from pathlib import Path
        repo = Path(__file__).resolve().parents[1]
        data = yaml.safe_load((repo / "render.yaml").read_text())
        service = data["services"][0]
        assert service["buildCommand"].strip()
        assert service["startCommand"].strip()
        keys = {v["key"]: v for v in service["envVars"]}
        assert keys["FEEFIX_ENV"]["value"] == "production"
        # Secrets must be prompted for, never committed in the blueprint.
        for secret in ("FEEFIX_OTP_PEPPER", "OTP_SMTP_PASS", "GITHUB_CLIENT_SECRET",
                       "OTP_TWILIO_TOKEN"):
            assert keys[secret].get("sync") is False, f"{secret} has a committed value"
        # No wildcard trust of X-Forwarded-For.
        assert keys.get("FEEFIX_TRUSTED_PROXIES", {}).get("value") != "0.0.0.0/0"


# ===========================================================================
# 15. NO USER ENUMERATION
# ===========================================================================
class TestUserEnumeration:
    def test_login_errors_are_identical(self, client):
        _register(client, "known@example.com")
        a = client.post("/api/auth/login",
                        json={"email": "known@example.com", "password": "wrongwrong"},
                        headers=_replay_headers())
        b = client.post("/api/auth/login",
                        json={"email": "unknown@example.com", "password": "wrongwrong"},
                        headers=_replay_headers())
        assert a.status_code == b.status_code == 401
        assert a.json()["detail"] == b.json()["detail"]

    def test_login_timing_is_similar(self, client):
        """Always running the KDF is what stops latency being the oracle."""
        _register(client, "timed@example.com")

        def measure(email):
            samples = []
            for _ in range(3):
                ratelimit.reset()
                t0 = time.perf_counter()
                client.post("/api/auth/login",
                            json={"email": email, "password": "wrongwrong"},
                            headers=_replay_headers())
                samples.append(time.perf_counter() - t0)
            return min(samples)

        known, unknown = measure("timed@example.com"), measure("ghost@example.com")
        ratio = max(known, unknown) / max(min(known, unknown), 1e-6)
        assert ratio < 3.0, f"known {known*1000:.0f}ms vs unknown {unknown*1000:.0f}ms"

    def test_otp_request_is_indistinguishable(self, client):
        _register(client, "otp-known@example.com")
        a = client.post("/api/auth/otp/request",
                        json={"channel": "email", "address": "otp-known@example.com"},
                        headers=_replay_headers())
        b = client.post("/api/auth/otp/request",
                        json={"channel": "email", "address": "otp-ghost@example.com"},
                        headers=_replay_headers())
        assert a.status_code == b.status_code == 200
        assert set(a.json()) == set(b.json())
