"""Token rotation & replay policy — anti-replay without a self-DoS footgun.

The review's point #4: revoking the *whole session family* on any replayed
rotated token means one stale tab or slow mobile client logs the user out
everywhere. These tests pin the replacement policy:

* a late same-device request is *healed* (fresh token, same family),
* a stale token past the overlap is refused — and the live token survives,
* expired rows kill themselves, not the family,
* family revocation still happens when the pattern really looks like theft
  (repeated replays from a different client fingerprint), and ``strict`` mode
  remains available for deployments that prefer the old behaviour.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from backend.services import auth as auth_svc
from backend.services import db


def _register(client, email="rotate@example.com", password="S3cure!Pass"):
    r = client.post("/api/auth/register",
                    json={"email": email, "password": password, "name": "Rota"})
    assert r.status_code == 200
    return r.json()["token"]


def _age_creation(client, token, hours=25):
    conn = db.get_connection()
    aged = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(timespec="seconds")
    conn.execute("UPDATE auth_sessions SET created_at=? WHERE token_hash=?",
                 (aged, auth_svc._token_hash(token)))
    conn.commit()


def _set_replaced_at(token, seconds_ago):
    conn = db.get_connection()
    when = (datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)).isoformat(timespec="seconds")
    conn.execute("UPDATE auth_sessions SET replaced_at=? WHERE token_hash=?",
                 (when, auth_svc._token_hash(token)))
    conn.commit()


def _rotate(client, token):
    """Use an aged token once so it rotates; returns the fresh token."""
    r = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    fresh = r.headers.get("X-Session-Token")
    assert fresh and fresh != token
    return fresh


def _me(client, token, user_agent: str | None = None):
    headers = {"Authorization": f"Bearer {token}"}
    if user_agent:
        headers["User-Agent"] = user_agent
    return client.get("/api/auth/me", headers=headers)


# -- benign races must not log anyone out ---------------------------------------
def test_late_same_device_token_is_healed_not_punished(client):
    """A slow tab presents the superseded token: it gets a fresh one, same user."""
    token = _register(client)
    _age_creation(client, token)
    live = _rotate(client, token)

    # The stale token arrives again 5 minutes later — a slow tab, not a thief.
    _set_replaced_at(token, 300)
    r = _me(client, token)  # same client fingerprint as when the session was made
    assert r.status_code == 200, "a late same-device request must not hard-fail"
    healed = r.headers.get("X-Session-Token")
    assert healed, "the stale client is healed with a fresh token, not left stranded"
    assert healed != token
    assert _me(client, healed).status_code == 200, "the healed token works"
    assert _me(client, live).status_code == 200, "the original live session is untouched"


def test_foreign_client_inside_overlap_is_tolerated_but_not_minted(client):
    token = _register(client)
    _age_creation(client, token)
    live = _rotate(client, token)
    _set_replaced_at(token, 300)

    r = _me(client, token, user_agent="SomeOtherDevice/9.9")
    assert r.status_code == 200, "in-flight tolerance covers a changed client string"
    assert r.headers.get("X-Session-Token") is None, "no new token for a foreign client"
    assert _me(client, live).status_code == 200


def test_stale_token_past_overlap_is_refused_but_live_session_survives(client):
    """The self-DoS fix: refusing a stale token must not kill the live session."""
    token = _register(client)
    _age_creation(client, token)
    live = _rotate(client, token)
    _set_replaced_at(token, auth_svc.OVERLAP_S + 60)

    assert _me(client, token).status_code == 401, "stale token must not authenticate"
    assert _me(client, live).status_code == 200, "the live session must survive a replay"
    # A second account's session, same user, still untouched too.
    assert _me(client, live).json()["user"]["email"] == "rotate@example.com"


def test_expired_stale_row_does_not_revoke_the_family(client):
    """Expiry deletes one row — it used to revoke the whole family."""
    token = _register(client)
    _age_creation(client, token)
    live = _rotate(client, token)
    conn = db.get_connection()
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(timespec="seconds")
    conn.execute("UPDATE auth_sessions SET expires_at=? WHERE token_hash=?",
                 (past, auth_svc._token_hash(token)))
    conn.commit()

    assert _me(client, token).status_code == 401
    assert _me(client, live).status_code == 200


def test_legitimate_multi_device_sessions_are_independent(client):
    first = _register(client, email="multi@example.com")
    second = _register(client, email="multi2@example.com")
    # Two different accounts never share a family.
    assert _me(client, first).status_code == 200
    assert _me(client, second).status_code == 200
    conn = db.get_connection()
    keys = {r["session_key"] for r in conn.execute("SELECT session_key FROM auth_sessions")}
    assert len(keys) == 2


# -- theft signals still escalate ------------------------------------------------
def test_strict_policy_revokes_the_family_when_configured(client, monkeypatch):
    monkeypatch.setattr(auth_svc, "REPLAY_POLICY", "strict")
    token = _register(client)
    _age_creation(client, token)
    live = _rotate(client, token)
    _set_replaced_at(token, 3600)

    assert _me(client, token).status_code == 401
    assert _me(client, live).status_code == 401, "strict mode revokes the family"


def test_balanced_policy_escalates_after_repeated_foreign_replays(client, monkeypatch):
    monkeypatch.setattr(auth_svc, "REPLAY_POLICY", "balanced")
    monkeypatch.setattr(auth_svc, "REPLAY_STRIKES", 2)
    token = _register(client)
    _age_creation(client, token)
    live = _rotate(client, token)
    _set_replaced_at(token, 3600)

    # The owner's fingerprint is the default TestClient one; a thief presents a
    # different client fingerprint each time.
    assert _me(client, token, user_agent="thief-1").status_code == 401
    assert _me(client, live).status_code == 200, "one strike must not log the user out"
    assert _me(client, token, user_agent="thief-2").status_code == 401
    assert _me(client, live).status_code == 401, "escalation after the strike threshold"


def test_lenient_policy_only_audits(client, monkeypatch):
    monkeypatch.setattr(auth_svc, "REPLAY_POLICY", "lenient")
    token = _register(client)
    _age_creation(client, token)
    live = _rotate(client, token)
    _set_replaced_at(token, 7200)

    assert _me(client, token).status_code == 401
    assert _me(client, live).status_code == 200
    conn = db.get_connection()
    actions = [r["action"] for r in conn.execute("SELECT action FROM audit_log").fetchall()]
    assert "auth.token_replay_observed" in actions


def test_replay_events_are_audited_without_leaking_tokens(client):
    token = _register(client)
    _age_creation(client, token)
    live = _rotate(client, token)
    _set_replaced_at(token, auth_svc.OVERLAP_S + 60)
    assert _me(client, token).status_code == 401

    conn = db.get_connection()
    rows = conn.execute("SELECT action, detail FROM audit_log").fetchall()
    flat = " ".join(f"{r['action']} {r['detail']}" for r in rows)
    assert "auth.token_replay_rejected" in flat
    assert token not in flat and live not in flat, "audit must never store raw tokens"


# -- fingerprint plumbing ---------------------------------------------------------
def test_fingerprint_ignores_absent_headers_and_hashes_the_rest():
    class _Req:
        def __init__(self, headers):
            self.headers = headers

    assert auth_svc.client_fingerprint(_Req({})) is None
    a = auth_svc.client_fingerprint(_Req({"user-agent": "UA-1", "accept-language": "en"}))
    b = auth_svc.client_fingerprint(_Req({"user-agent": "UA-2", "accept-language": "en"}))
    assert a and b and a != b
    assert len(a) == 16 and "UA-1" not in a


def test_policy_summary_is_serialisable():
    summary = auth_svc.policy_summary()
    assert summary["replay_policy"] in ("balanced", "strict", "lenient")
    assert summary["token_overlap_s"] >= 1
