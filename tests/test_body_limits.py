"""Request-body limits — per endpoint, env-tunable, and actually enforced.

The review's point #9: a single fixed 1 MB cap plus fixed field lengths is a
blunt instrument — great against floods, hostile to legitimate large input (a
long note, a real document upload). And point #11 in ``HARDENING.md`` only held
for clients that *declare* ``Content-Length``; chunked bodies bypassed it.

These tests pin the replacement: a policy table (upload ≫ profile ≫ chat ≈ auth),
streaming enforcement that does not trust headers, operator-tunable numbers with
an absolute clamp, and an honest 413 that says which limit was hit.
"""

from __future__ import annotations

import json

import pytest

from backend.services.limits import (
    ABSOLUTE_MAX_BODY_BYTES,
    BODY_POLICIES,
    MAX_NOTES_LEN,
    MAX_UPLOAD_BYTES,
    body_limit_bytes,
    body_limit_for,
    describe_limits,
    reset_cache,
)

PROFILE = {"domicile_state": "Delhi", "category": "general"}


# --------------------------------------------------------------------------- #
# the policy table itself
# --------------------------------------------------------------------------- #
def test_limits_are_per_endpoint_not_one_size_fits_all():
    upload = body_limit_bytes("POST", "/api/uploads/sess-1")
    profile = body_limit_bytes("PUT", "/api/students/s/profile")
    chat = body_limit_bytes("POST", "/api/chat")
    auth = body_limit_bytes("POST", "/api/auth/login")

    assert upload > profile > chat >= auth, (
        "a document upload, a profile save and a chat turn must not share one number"
    )
    assert upload >= MAX_UPLOAD_BYTES, "the upload cap must accommodate the file cap"
    assert auth <= 16_000, "credentials are tiny; the KDF must never see a large body"


def test_policy_table_is_exposed_and_explained():
    described = describe_limits()
    assert {entry["name"] for entry in described} >= {
        "upload", "profile", "notes", "conversation", "auth", "api-default"
    }
    assert all(entry["rationale"] for entry in described)
    assert all(entry["max_bytes"] >= 1024 for entry in described)


def test_method_and_path_are_both_consulted():
    # Static paths still get a policy (never unbounded), unusual methods included.
    assert body_limit_for("POST", "/somewhere").max_bytes > 0
    assert body_limit_for("PUT", "/api/students/x/profile").name == "profile"


# --------------------------------------------------------------------------- #
# enforcement
# --------------------------------------------------------------------------- #
def test_declared_oversize_is_rejected_with_a_helpful_413(client):
    r = client.post(
        "/api/chat",
        content=b"x" * 1_100_000,
        headers={"content-type": "application/json"},
    )
    assert r.status_code == 413
    body = r.json()
    assert body["detail"] == "Payload too large."
    assert body["limit_bytes"] == body_limit_bytes("POST", "/api/chat")
    assert body["policy"] == "conversation"
    assert "limit" in body["hint"].lower()


def test_undeclared_chunked_body_is_still_bounded(client):
    """No Content-Length → the old header check was bypassable; counting is not."""
    chunks = [b"x" * 8192 for _ in range(20)]  # 160 KB, over the 64 KB chat cap
    r = client.post(
        "/api/chat",
        content=iter(chunks),
        headers={"content-type": "application/json"},
    )
    assert r.status_code == 413, "a chunked body must not slip past the limit"


def test_small_chunked_body_is_processed_normally(client):
    payload = json.dumps({"message": "hello"}).encode()
    r = client.post("/api/chat", content=iter([payload]),
                    headers={"content-type": "application/json"})
    assert r.status_code == 200


def test_same_payload_is_rejected_by_a_tight_endpoint_and_accepted_by_a_looser_one(client):
    """The point of per-endpoint policies, demonstrated end to end."""
    payload = json.dumps({"question": "x", "session_id": None, "padding": "y" * 70_000}).encode()
    assert len(payload) > body_limit_bytes("POST", "/api/ask")
    assert len(payload) < body_limit_bytes("PUT", "/api/students/s/profile")

    tight = client.post("/api/ask", content=payload, headers={"content-type": "application/json"})
    assert tight.status_code == 413

    looser = client.put("/api/students/s/profile", content=payload,
                        headers={"content-type": "application/json"})
    assert looser.status_code != 413, "a 70 KB body is legitimate for a profile save"


# --------------------------------------------------------------------------- #
# the long-input fix: a field that is *meant* to be large
# --------------------------------------------------------------------------- #
def test_notes_endpoint_accepts_a_legitimately_large_note(client):
    notes = "Application submitted at the district office; income certificate pending. " * 200
    assert len(notes) > 10_000
    r = client.put("/api/students/long-note/notes", json={"notes": notes})
    assert r.status_code == 200, r.text
    assert r.json()["notes"] == notes
    assert client.get("/api/students/long-note/notes").json()["notes"] == notes


def test_notes_endpoint_still_refuses_an_absurd_note(client):
    r = client.put("/api/students/long-note2/notes", json={"notes": "x" * (MAX_NOTES_LEN + 1)})
    assert r.status_code == 422, "the field cap still applies at the schema layer"


def test_notes_body_policy_covers_the_field_cap():
    assert body_limit_bytes("PUT", "/api/students/x/notes") > MAX_NOTES_LEN


# --------------------------------------------------------------------------- #
# operator tuning, with an absolute clamp
# --------------------------------------------------------------------------- #
def test_limits_are_operator_tunable(monkeypatch):
    """Limits are read from the environment at process start (boot-time policy)."""
    import importlib

    from backend.services import limits

    monkeypatch.setenv("FEEFIX_MAX_BODY_CONVERSATION_BYTES", "200000")
    reloaded = importlib.reload(limits)
    try:
        assert reloaded.body_limit_bytes("POST", "/api/chat") == 200_000
        assert reloaded.body_limit_bytes("POST", "/api/auth/login") <= 16_000, (
            "other tiers must be unaffected"
        )
    finally:
        monkeypatch.undo()
        importlib.reload(limits)
        reset_cache()


def test_junk_values_fall_back_to_the_safe_default(monkeypatch):
    import importlib

    from backend.services import limits

    monkeypatch.setenv("FEEFIX_MAX_BODY_CONVERSATION_BYTES", "not-a-number")
    reloaded = importlib.reload(limits)
    try:
        assert reloaded.body_limit_bytes("POST", "/api/chat") == 64_000
    finally:
        monkeypatch.undo()
        importlib.reload(limits)
        reset_cache()


def test_no_override_can_exceed_the_absolute_ceiling(monkeypatch):
    import importlib

    from backend.services import limits

    monkeypatch.setenv("FEEFIX_MAX_BODY_BYTES", str(10 ** 12))
    reloaded = importlib.reload(limits)
    try:
        assert reloaded.body_limit_bytes("POST", "/api/whatever") <= reloaded.ABSOLUTE_MAX_BODY_BYTES
    finally:
        monkeypatch.undo()
        importlib.reload(limits)
        reset_cache()


def test_field_caps_are_env_tunable(monkeypatch):
    import importlib

    from backend.services import limits

    monkeypatch.setenv("FEEFIX_MAX_MESSAGE_LEN", "5000")
    reloaded = importlib.reload(limits)
    try:
        assert reloaded.MAX_MESSAGE_LEN == 5000
        assert reloaded.MIN_PASSWORD_LEN == 8, "invalid overrides never weaken a floor"
    finally:
        monkeypatch.undo()
        importlib.reload(limits)


def test_meta_exposes_the_limit_table(client):
    body = client.get("/api/meta").json()
    names = {entry["name"] for entry in body["limits"]}
    assert {"upload", "profile", "notes", "conversation", "auth"} <= names
    assert body["uploads"]["max_bytes"] == MAX_UPLOAD_BYTES
    assert body["password_hashing"]["algorithm"] in ("argon2id", "pbkdf2")


def test_every_body_policy_regex_matches_something():
    """A policy that can never match is dead configuration."""
    samples = {
        "upload": "POST /api/uploads/sess",
        "profile": "PUT /api/students/s/profile",
        "notes": "PUT /api/students/s/notes",
        "conversation": "POST /api/chat",
        "events": "POST /api/events",
        "auth": "POST /api/auth/login",
        "api-default": "POST /api/stats",
        "static-default": "POST /",
    }
    for policy in BODY_POLICIES:
        method, path = samples[policy.name].split(" ", 1)
        assert policy.matches(method, path), f"{policy.name} policy is unreachable"


@pytest.mark.parametrize("size", [1, 512, 1500])
def test_tiny_bodies_are_untouched(client, size):
    body = json.dumps({"message": "a" * size}).encode()
    assert client.post("/api/chat", content=body,
                       headers={"content-type": "application/json"}).status_code == 200
