"""Per-endpoint body caps, enforced while the body streams.

The old gate compared ``Content-Length`` only, so ``Transfer-Encoding: chunked``
(or a lying header) walked straight past it and the cap became advisory for the
clients that matter. These tests pin the behaviour that replaced it:

* every route class has its own limit (a chat turn and a document upload no
  longer share one blunt number);
* a chunked body with no ``Content-Length`` is still bounded;
* the 413 tells the client the limit and the scope, so large legitimate input
  has a discoverable path instead of a mystery rejection;
* real limits are reported by ``/api/health`` instead of being tribal knowledge.
"""

from __future__ import annotations

import pytest

from backend.services.limits import (
    DEFAULT_MAX_BODY_BYTES,
    MAX_UPLOAD_BYTES,
    body_limit_for,
    limit_report,
)


def test_each_route_class_has_its_own_cap():
    chat = body_limit_for("/api/chat").max_bytes
    ask = body_limit_for("/api/ask").max_bytes
    auth = body_limit_for("/api/auth/login").max_bytes
    profile = body_limit_for("/api/students/x/profile").max_bytes
    upload = body_limit_for("/api/students/x/documents").max_bytes
    generic = body_limit_for("/api/schemes").max_bytes

    assert chat < generic and ask < chat and auth < profile
    assert upload > MAX_UPLOAD_BYTES  # multipart framing overhead is allowed for
    assert upload > max(generic, profile)
    assert generic == DEFAULT_MAX_BODY_BYTES
    assert body_limit_for("/api/students/x/documents").scope == "upload"


def test_limits_are_environment_tunable(monkeypatch):
    """A deployment can raise one limit for a real need without weakening the rest."""
    import importlib

    monkeypatch.setenv("FEEFIX_MAX_MESSAGE_LEN", "5000")
    monkeypatch.setenv("FEEFIX_MAX_UPLOAD_BYTES", "20000000")
    from backend.services import limits

    reloaded = importlib.reload(limits)
    try:
        assert reloaded.MAX_MESSAGE_LEN == 5000
        assert reloaded.body_limit_for("/api/students/x/documents").max_bytes > 20_000_000
        assert reloaded.body_limit_for("/api/auth/login").max_bytes < 100_000  # still tight
    finally:
        monkeypatch.undo()
        importlib.reload(limits)


def test_junk_env_values_are_ignored_not_crashed(monkeypatch):
    import importlib

    from backend.services import limits

    monkeypatch.setenv("FEEFIX_MAX_MESSAGE_LEN", "not-a-number")
    reloaded = importlib.reload(limits)
    try:
        assert reloaded.MAX_MESSAGE_LEN == 2000
    finally:
        monkeypatch.undo()
        importlib.reload(limits)


def test_declared_oversize_body_is_rejected_with_the_limit(client):
    response = client.post(
        "/api/chat",
        content=b"x" * 100_000,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 413
    body = response.json()
    assert body["limit_bytes"] == body_limit_for("/api/chat").max_bytes
    assert body["scope"] == "chat"
    assert response.headers["X-Max-Body-Bytes"] == str(body["limit_bytes"])


def test_chunked_body_without_content_length_is_still_bounded(client):
    """The bypass the Content-Length-only gate could not see."""
    def chunks():
        for _ in range(40):
            yield b"x" * 8_000  # 320 KB, streamed with no Content-Length

    # A generator body ⇒ httpx streams it with Transfer-Encoding: chunked and no
    # Content-Length, which is exactly the shape the old gate could not see.
    response = client.post(
        "/api/chat", content=chunks(), headers={"content-type": "application/json"},
    )
    assert response.status_code == 413, "chunked uploads must not bypass the cap"


def test_upload_route_gets_the_upload_budget_not_the_json_cap(client):
    """A legitimate large document must not eat a 413 from the generic cap."""
    payload = b"%PDF-1.7\n" + b"a" * (DEFAULT_MAX_BODY_BYTES + 50_000)
    assert len(payload) < MAX_UPLOAD_BYTES
    response = client.post(
        "/api/students/big-doc/documents",
        files={"file": ("report.pdf", payload, "application/pdf")},
        data={"doc_type": "marksheet"},
    )
    assert response.status_code == 201, response.text
    assert response.json()["document"]["size_bytes"] == len(payload)


def test_health_reports_the_effective_limits(client):
    limits = client.get("/api/health").json()["limits"]
    assert limits["body"]["chat"] == body_limit_for("/api/chat").max_bytes
    assert limits["body"]["upload"] == body_limit_for("/api/students/x/documents").max_bytes
    assert limits["fields"]["message"] > 0
    assert limits["upload"]["extensions"] == sorted({".pdf", ".png", ".jpg", ".jpeg"})
    assert limit_report()["fields"]["password"]["max"] >= 64


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH"])
def test_every_write_method_is_gated(client, method):
    response = client.request(
        method, "/api/students/x/profile", content=b"y" * 200_000,
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 413
