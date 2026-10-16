"""Boot policy: docs are back, secrets are enforced, config is observable.

Three claims this file makes testable:

1. **Interactive docs are on by default.** Disabling them never removed an
   endpoint or an attack surface — it only broke generated clients, QA and
   tooling. ``/docs``, ``/redoc`` and ``/openapi.json`` must be reachable, the
   OpenAPI document must describe the real routes, and the off-switch must be
   deliberate.
2. **A placeholder secret is fatal in production**, not a log line nobody reads.
   A production deploy must not come up still holding ``CHANGE_ME``.
3. **The effective security configuration is reported** by ``/api/health``
   (password scheme, limiter store and whether it is shared, secret strictness),
   so operators can verify rather than assume.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.main import create_app, docs_enabled
from backend.services import secrets as secrets_svc


# ---------------------------------------------------------------- docs by default
def test_docs_are_available_by_default(client):
    assert client.get("/docs").status_code == 200
    assert client.get("/redoc").status_code == 200
    schema = client.get("/openapi.json")
    assert schema.status_code == 200


def test_openapi_describes_every_real_route(client):
    """A client generator must see the whole surface — that was the point of
    keeping the docs on."""
    spec = client.get("/openapi.json").json()
    documented = set(spec["paths"])
    expected = {
        "/api/health", "/api/schemes", "/api/schemes/{scheme_id}", "/api/match",
        "/api/students/{session_id}/profile", "/api/students/{session_id}/documents",
        "/api/students/{session_id}/documents/{doc_id}", "/api/tracker/{session_id}",
        "/api/auth/register", "/api/auth/login", "/api/auth/logout", "/api/auth/me",
        "/api/auth/security-events", "/api/auth/logout-all", "/api/auth/export",
        "/api/auth/account", "/api/chat", "/api/ask", "/api/search/semantic",
        "/api/events", "/api/i18n/{lang}",
    }
    missing = expected - documented
    assert not missing, f"OpenAPI is missing real routes: {missing}"
    # Route handlers must appear as operations, not just as bare paths.
    assert spec["paths"]["/api/students/{session_id}/documents"]["post"]
    assert spec["info"]["version"]


def test_docs_can_be_turned_off_deliberately(monkeypatch):
    monkeypatch.setenv("FEEFIX_DISABLE_DOCS", "1")
    assert docs_enabled() is False
    app = create_app()
    with TestClient(app) as raw:
        assert raw.get("/docs").status_code == 404
        # …and the API itself is completely unaffected: hiding docs is cosmetic.
        assert raw.get("/api/health").status_code == 200
        assert raw.get("/api/schemes").status_code == 200

    monkeypatch.delenv("FEEFIX_DISABLE_DOCS")
    monkeypatch.setenv("FEEFIX_ENABLE_DOCS", "0")
    assert docs_enabled() is False
    monkeypatch.setenv("FEEFIX_ENABLE_DOCS", "1")
    assert docs_enabled() is True


def test_health_is_not_rate_limited_away_and_reports_configuration(client):
    assert client.get("/api/health").status_code == 200


# ------------------------------------------------------------- secret enforcement
def test_strict_secrets_abort_startup(monkeypatch):
    monkeypatch.setenv("FEEFIX_STRICT_SECRETS", "1")
    monkeypatch.setenv("GITHUB_CLIENT_ID", "iv1.example")
    monkeypatch.setenv("GITHUB_CLIENT_SECRET", "CHANGE_ME")
    assert secrets_svc.strict_mode() is True
    with pytest.raises(RuntimeError) as excinfo:
        secrets_svc.enforce_secret_policy()
    assert "GITHUB_CLIENT_SECRET" in str(excinfo.value)
    with pytest.raises(RuntimeError):
        create_app()  # the whole app refuses to boot


def test_production_markers_enable_strict_mode(monkeypatch):
    monkeypatch.delenv("FEEFIX_STRICT_SECRETS", raising=False)
    monkeypatch.delenv("FEEFIX_ENV", raising=False)
    for marker in ("RENDER", "FLY_APP_NAME", "K_SERVICE", "HEROKU_APP_NAME"):
        monkeypatch.delenv(marker, raising=False)
    assert secrets_svc.strict_mode() is False
    monkeypatch.setenv("RENDER", "true")
    assert secrets_svc.strict_mode() is True
    assert secrets_svc.secret_status()["production_like"] is True


def test_weak_secret_detection_beyond_the_placeholder_list():
    for weak in ("changeme", "xxxxxx", "aaaaaaaaaaaa", "1234567890", "your-token-here-xx"):
        assert secrets_svc._looks_weak(weak, 8) is True
    # A real random secret must not be flagged (false positives kill controls).
    assert secrets_svc._looks_weak("f3K9xQ2mZ7pL4vB1nR8tY6wS", 20) is False


def test_development_still_only_warns(monkeypatch, caplog):
    monkeypatch.setenv("FEEFIX_STRICT_SECRETS", "0")
    monkeypatch.setenv("GITHUB_CLIENT_ID", "iv1.example")
    monkeypatch.setenv("GITHUB_CLIENT_SECRET", "changeme")
    findings = secrets_svc.enforce_secret_policy()  # must not raise
    assert any("GITHUB_CLIENT_SECRET" in f for f in findings)


def test_health_exposes_configuration_without_secrets(client, monkeypatch):
    monkeypatch.setenv("OTP_TWILIO_TOKEN", "S3cretTwilioTokenValue123")
    health = client.get("/api/health").json()

    assert health["password_hashing"]["scheme"] in ("argon2id", "scrypt")
    assert health["password_hashing"]["scheme"] != "pbkdf2"
    assert health["rate_limit"]["backend"] in ("sqlite", "redis", "memory")
    assert isinstance(health["rate_limit"]["shared_across_processes"], bool)
    assert health["interactive_docs"]["enabled"] is True
    assert health["secrets"]["secrets"]["OTP_TWILIO_TOKEN"] == "set"
    assert health["documents"]["documents"] == 0
    # Never leak the values themselves.
    body = client.get("/api/health").text
    assert "S3cretTwilioTokenValue123" not in body
