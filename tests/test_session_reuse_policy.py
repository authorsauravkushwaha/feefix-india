"""Token-replay handling: detection without the self-inflicted logout.

The old behaviour revoked the *entire session family* the moment a superseded
token was replayed. One stale tab — or a mobile app that still holds yesterday's
token while the web client rotated — logged the user out everywhere. That trades
availability for a replay defence that benign races trip constantly.

The policy now (default ``quarantine``):

* the replayed (superseded) token is killed immediately, so replay is worthless;
* the live token keeps working, and the client is told via ``X-Session-Warning``;
* the event is recorded and shown to the user at ``/api/auth/security-events``,
  with a deliberate ``/api/auth/logout-all`` for the "I don't trust this" case;
* escalation to family revocation happens only when the pattern is clearly not a
  race (≥ 3 replays within the window, or an operator opting into
  ``revoke_family``).
"""

from __future__ import annotations

import pytest
from datetime import datetime, timedelta, timezone

from backend.services import auth as auth_svc, db


def _aged_session(client, token: str, *, hours: int = 25) -> None:
    """Backdate a session so the next use rotates it."""
    conn = db.get_connection()
    aged = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(timespec="seconds")
    conn.execute(
        "UPDATE auth_sessions SET created_at=? WHERE token_hash=?",
        (aged, auth_svc._token_hash(token)),
    )
    conn.commit()


def _replay_after_grace(token: str, seconds: int | None = None) -> None:
    # Default: past the overlap window (the unified *heal* window) so these
    # tests exercise the refusal path — inside the overlap a same-device stale
    # token is healed instead (see tests/test_session_replay_policy.py).
    if seconds is None:
        seconds = auth_svc.OVERLAP_S + 60
    conn = db.get_connection()
    conn.execute(
        "UPDATE auth_sessions SET replaced_at=? WHERE token_hash=?",
        ((datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat(timespec="seconds"),
         auth_svc._token_hash(token)),
    )
    conn.commit()


def _rotate(client) -> tuple[str, str]:
    """Register, age the token, use it, and return (stale, fresh)."""
    stale = client.post(
        "/api/auth/register",
        json={"email": "rotate@example.com", "password": "S3cure!Pass"},
    ).json()["token"]
    _aged_session(client, stale)
    response = client.get("/api/auth/me", headers={"Authorization": f"Bearer {stale}"})
    assert response.status_code == 200
    fresh = response.headers["X-Session-Token"]
    return stale, fresh


def test_a_stale_token_is_killed_but_the_session_survives(client):
    """The benign race must not log anyone out."""
    stale, fresh = _rotate(client)
    _replay_after_grace(stale)

    replay = client.get("/api/auth/me", headers={"Authorization": f"Bearer {stale}"})
    assert replay.status_code == 401
    assert replay.headers.get("X-Session-Warning") == "stale-token-replayed"

    # The live token still works — this is the difference from revoke-family.
    assert client.get(
        "/api/auth/me", headers={"Authorization": f"Bearer {fresh}"}
    ).status_code == 200

    # The replayed token is now deleted, so it can never be replayed again.
    assert client.get(
        "/api/auth/me", headers={"Authorization": f"Bearer {stale}"}
    ).status_code == 401


def test_replay_is_recorded_and_visible_to_the_user(client):
    stale, fresh = _rotate(client)
    _replay_after_grace(stale)
    client.get("/api/auth/me", headers={"Authorization": f"Bearer {stale}"})

    events = client.get(
        "/api/auth/security-events", headers={"Authorization": f"Bearer {fresh}"}
    ).json()
    assert events["count"] >= 1
    assert events["events"][0]["kind"] == "token_replay"
    assert "stale tab" in events["interpretation"]


def test_sustained_replay_escalates_to_family_revocation(client):
    stale, fresh = _rotate(client)
    # Three separate replays inside the window = no longer a benign race.
    for seconds in (300, 600, 900):
        _replay_after_grace(stale, seconds=seconds)
        _aged_session(client, fresh)  # keep the family alive across attempts
        client.get("/api/auth/me", headers={"Authorization": f"Bearer {stale}"})

    # After escalation the whole family is gone: the user must sign in again.
    assert client.get(
        "/api/auth/me", headers={"Authorization": f"Bearer {fresh}"}
    ).status_code == 401


def test_operator_can_opt_into_aggressive_revocation(client, monkeypatch):
    monkeypatch.setenv("FEEFIX_SESSION_REUSE_POLICY", "revoke_family")
    stale, fresh = _rotate(client)
    _replay_after_grace(stale)
    client.get("/api/auth/me", headers={"Authorization": f"Bearer {stale}"})
    assert client.get(
        "/api/auth/me", headers={"Authorization": f"Bearer {fresh}"}
    ).status_code == 401


def test_observe_policy_records_without_killing_anything(client, monkeypatch):
    monkeypatch.setenv("FEEFIX_SESSION_REUSE_POLICY", "observe")
    stale, fresh = _rotate(client)
    _replay_after_grace(stale)
    client.get("/api/auth/me", headers={"Authorization": f"Bearer {stale}"})
    # The live token is untouched and the family is not revoked.
    assert client.get(
        "/api/auth/me", headers={"Authorization": f"Bearer {fresh}"}
    ).status_code == 200


def test_in_flight_grace_window_still_honours_the_old_token(client):
    """A request that started just before rotation must not fail."""
    stale, fresh = _rotate(client)
    _replay_after_grace(stale, seconds=5)  # inside REUSE_GRACE_S
    assert client.get(
        "/api/auth/me", headers={"Authorization": f"Bearer {stale}"}
    ).status_code == 200
    assert client.get(
        "/api/auth/me", headers={"Authorization": f"Bearer {fresh}"}
    ).status_code == 200


def test_unknown_reuse_policy_value_falls_back_to_quarantine(monkeypatch):
    monkeypatch.setenv("FEEFIX_SESSION_REUSE_POLICY", "yolo")
    assert auth_svc._reuse_policy() == "quarantine"


def test_logout_all_is_the_users_own_hammer(client):
    token = client.post(
        "/api/auth/register",
        json={"email": "multi@example.com", "password": "S3cure!Pass"},
    ).json()["token"]
    second = client.post(
        "/api/auth/login",
        json={"email": "multi@example.com", "password": "S3cure!Pass"},
    ).json()["token"]
    headers = {"Authorization": f"Bearer {token}"}

    assert client.get("/api/auth/me", headers=headers).status_code == 200
    assert client.post("/api/auth/logout-all", headers=headers).status_code == 200
    for candidate in (token, second):
        assert client.get(
            "/api/auth/me", headers={"Authorization": f"Bearer {candidate}"}
        ).status_code == 401

    # The action itself is auditable and visible in the event log.
    fresh = client.post(
        "/api/auth/login",
        json={"email": "multi@example.com", "password": "S3cure!Pass"},
    ).json()["token"]
    kinds = [
        event["kind"]
        for event in client.get(
            "/api/auth/security-events", headers={"Authorization": f"Bearer {fresh}"}
        ).json()["events"]
    ]
    assert "user_revoked_all_sessions" in kinds


@pytest.mark.parametrize("policy", ["quarantine", "revoke_family", "observe"])
def test_policy_is_documented_and_selectable(monkeypatch, policy):
    monkeypatch.setenv("FEEFIX_SESSION_REUSE_POLICY", policy)
    assert auth_svc._reuse_policy() == policy
