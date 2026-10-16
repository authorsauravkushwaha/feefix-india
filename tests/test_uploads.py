"""Uploads — the hardened gate is now *called* by a real, protected endpoint.

The review's point #7: ``services/upload.py`` was hardened and tested but no route
used it, so it protected nothing, and nothing forced a future endpoint to use it.
These tests close both halves:

* the endpoint rejects dangerous/spoofed content **before** anything is written,
* the bytes land outside the web root, with random names and 0600 permissions,
* ownership (authz), quotas and rate/body limits apply to the real route,
* a structural test keeps the gate non-bypassable: no route may accept an
  ``UploadFile`` without going through ``services/uploads.py``.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from backend.services import uploads as uploads_svc
from backend.services.limits import (
    MAX_UPLOAD_BYTES,
    MAX_UPLOAD_FILES_PER_SESSION,
    UPLOAD_ALLOWED_EXTS,
)

REPO = Path(__file__).resolve().parents[1]
PDF = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\ntrailer\n%%EOF\n"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32


@pytest.fixture(autouse=True)
def _upload_tmpdir(tmp_path, monkeypatch):
    """Point storage at a throwaway directory for the duration of each test."""
    monkeypatch.setattr(uploads_svc, "UPLOAD_ROOT", tmp_path / "uploads")
    yield


def _post_file(client, session_id, filename, content, content_type="application/pdf", **kw):
    return client.post(
        f"/api/uploads/{session_id}",
        files={"file": (filename, content, content_type)},
        **kw,
    )


# --------------------------------------------------------------------------- #
# the endpoint exists, works, and stores safely
# --------------------------------------------------------------------------- #
def test_endpoint_is_wired_and_stores_a_valid_pdf(client):
    r = _post_file(client, "sess-1", "income.pdf", PDF)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["stored"] is True
    record = body["upload"]
    assert record["size_bytes"] == len(PDF)
    assert record["kind"] == "pdf"
    assert len(record["sha256"]) == 64
    assert record["url"] == f"/api/uploads/sess-1/{record['id']}/content"
    # The client-supplied name is metadata only; the stored name is random.
    assert record["original_name"] == "income.pdf"
    assert record["stored_name"].endswith(".pdf")
    assert "income" not in record["stored_name"]


def test_stored_bytes_live_outside_the_web_root_with_tight_permissions(client):
    record = _post_file(client, "sess-perms", "marks.png", PNG, "image/png").json()["upload"]
    stored = uploads_svc.UPLOAD_ROOT / "sess-perms" / record["stored_name"]
    assert stored.is_file()
    web_root = REPO / "web" / "frontend"
    assert web_root not in stored.parents, "uploads must never sit under the static mount"
    mode = stored.stat().st_mode & 0o777
    assert mode == 0o600, f"expected 0600, got {oct(mode)}"


def test_download_serves_as_attachment_not_sniffable_content(client):
    record = _post_file(client, "sess-dl", "caste.pdf", PDF).json()["upload"]
    r = client.get(record["url"])
    assert r.status_code == 200
    assert r.content == PDF
    assert r.headers["content-type"] == "application/octet-stream"
    assert "attachment" in r.headers.get("content-disposition", "")
    assert r.headers.get("x-content-type-options") == "nosniff"


def test_listing_and_deletion(client):
    record = _post_file(client, "sess-list", "a.pdf", PDF).json()["upload"]
    listed = client.get("/api/uploads/sess-list").json()
    assert listed["count"] == 1
    assert listed["items"][0]["id"] == record["id"]
    assert listed["policy"]["max_bytes"] == MAX_UPLOAD_BYTES
    assert set(listed["policy"]["allowed_extensions"]) == set(UPLOAD_ALLOWED_EXTS)

    assert client.delete(f"/api/uploads/sess-list/{record['id']}").json()["deleted"] is True
    assert client.get("/api/uploads/sess-list").json()["count"] == 0
    assert client.get(record["url"]).status_code == 404
    stored = uploads_svc.UPLOAD_ROOT / "sess-list" / record["stored_name"]
    assert not stored.exists(), "deleting an upload must remove the bytes"


# --------------------------------------------------------------------------- #
# the gate actually gates
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "filename,content,content_type",
    [
        ("shell.php", b"<?php system($_GET[0]); ?>", "application/pdf"),
        ("shell.pdf.php", PDF, "application/pdf"),
        ("fake.pdf", b"<?php echo 1; ?>", "application/pdf"),
        ("vector.svg", b"<svg onload=alert(1)>", "image/svg+xml"),
        ("script.html", b"<script>alert(1)</script>", "text/html"),
        ("payload.js", b"alert(1)", "text/javascript"),
        ("run.exe", b"MZ\x90\x00", "application/octet-stream"),
    ],
)
def test_dangerous_or_spoofed_files_never_reach_disk(client, filename, content, content_type):
    r = _post_file(client, "sess-evil", filename, content, content_type)
    assert r.status_code == 422, f"{filename} was accepted"
    assert uploads_svc.list_uploads("sess-evil") == []
    assert not (uploads_svc.UPLOAD_ROOT / "sess-evil").exists() or not list(
        (uploads_svc.UPLOAD_ROOT / "sess-evil").iterdir()
    )


def test_oversized_upload_is_a_413_not_a_500(client):
    big = PDF + b"a" * (MAX_UPLOAD_BYTES + 10)
    r = _post_file(client, "sess-big", "big.pdf", big)
    assert r.status_code == 413
    assert "large" in r.json()["detail"].lower()
    assert uploads_svc.list_uploads("sess-big") == []


def test_empty_file_rejected(client):
    assert _post_file(client, "sess-empty", "empty.pdf", b"").status_code == 422


def test_path_traversal_filename_cannot_escape_the_session_directory(client):
    r = _post_file(client, "sess-trav", "../../../etc/passwd.pdf", PDF)
    assert r.status_code == 200
    record = r.json()["upload"]
    assert "/" not in record["stored_name"] and ".." not in record["original_name"]
    stored = uploads_svc.UPLOAD_ROOT / "sess-trav" / record["stored_name"]
    assert stored.resolve().parent == (uploads_svc.UPLOAD_ROOT / "sess-trav").resolve()


def test_session_id_cannot_traverse_either(client):
    r = _post_file(client, "..%2f..%2fescape", "x.pdf", PDF)
    # Either the id is rejected or it is sanitised into a plain directory name.
    if r.status_code == 200:
        stored = Path(r.json()["upload"]["stored_name"])
        assert stored.parent == Path(".")
        root = uploads_svc.UPLOAD_ROOT.resolve()
        for path in root.rglob("*.pdf"):
            assert root in path.resolve().parents


def test_per_session_file_quota(client):
    for i in range(MAX_UPLOAD_FILES_PER_SESSION):
        assert _post_file(client, "sess-quota", f"f{i}.pdf", PDF).status_code == 200
    refused = _post_file(client, "sess-quota", "one-too-many.pdf", PDF)
    assert refused.status_code == 413
    assert "limit" in refused.json()["detail"].lower()


def test_overwriting_an_existing_file_is_impossible(client, monkeypatch):
    """Storage names are random and created O_EXCL — no clobbering."""
    first = _post_file(client, "sess-dup", "same.pdf", PDF).json()["upload"]
    monkeypatch.setattr(uploads_svc.secrets, "token_hex", lambda n: "0" * (n * 2))
    second = _post_file(client, "sess-dup", "same.pdf", PDF)
    assert second.status_code == 500 or second.json().get("upload", {}).get("id") != first["id"]
    # The original bytes are intact either way.
    assert client.get(first["url"]).content == PDF


# --------------------------------------------------------------------------- #
# authorization on the real routes
# --------------------------------------------------------------------------- #
def _owned_session(client, sid, email="uploader@example.com"):
    client.put(f"/api/students/{sid}/profile", json={"profile": {"domicile_state": "Delhi"}})
    token = client.post(
        "/api/auth/register",
        json={"email": email, "password": "S3cure!Pass", "name": "Up"},
    ).json()["token"]
    assert client.post(
        "/api/auth/link-session",
        json={"session_id": sid},
        headers={"Authorization": f"Bearer {token}"},
    ).status_code == 200
    return token


def test_owned_session_uploads_require_the_owner(client):
    token = _owned_session(client, "owned-up")
    assert _post_file(client, "owned-up", "x.pdf", PDF).status_code == 403
    assert client.get("/api/uploads/owned-up").status_code == 403
    owner = _post_file(client, "owned-up", "x.pdf", PDF,
                       headers={"Authorization": f"Bearer {token}"})
    assert owner.status_code == 200
    record = owner.json()["upload"]
    assert client.get(record["url"]).status_code == 403
    assert client.get(record["url"],
                      headers={"Authorization": f"Bearer {token}"}).status_code == 200


def test_another_account_cannot_read_or_delete_your_document(client):
    token = _owned_session(client, "owned-up2")
    record = _post_file(client, "owned-up2", "x.pdf", PDF,
                        headers={"Authorization": f"Bearer {token}"}).json()["upload"]
    other = client.post(
        "/api/auth/register",
        json={"email": "other-up@example.com", "password": "S3cure!Pass"},
    ).json()["token"]
    headers = {"Authorization": f"Bearer {other}"}
    assert client.get(record["url"], headers=headers).status_code == 403
    assert client.delete(f"/api/uploads/owned-up2/{record['id']}",
                         headers=headers).status_code == 403
    assert client.get(record["url"], headers={"Authorization": f"Bearer {token}"}).status_code == 200


def test_upload_id_cannot_be_used_across_sessions(client):
    record = _post_file(client, "sess-a", "x.pdf", PDF).json()["upload"]
    assert client.get(f"/api/uploads/sess-b/{record['id']}/content").status_code == 404


# --------------------------------------------------------------------------- #
# the gate cannot be bypassed by accident
# --------------------------------------------------------------------------- #
def test_no_route_accepts_an_upload_without_the_sanctioned_service():
    """Structural guard: ``UploadFile`` may only appear in the upload routes.

    This is what turns "a control nobody wired in" into "a control that cannot be
    skipped": a future endpoint that declares ``UploadFile`` has to come through
    ``services/uploads.py`` (or this test fails and the reviewer sees why).
    """
    allowed_module = (REPO / "backend" / "api" / "routes.py").resolve()
    offenders: list[str] = []
    for path in list((REPO / "backend").rglob("*.py")) + list((REPO / "agents").rglob("*.py")):
        if path.resolve() == allowed_module:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                names = [a.name for a in node.names]
                if "UploadFile" in names or "File" in names:
                    offenders.append(f"{path.relative_to(REPO)}:{node.lineno}")
    assert not offenders, f"UploadFile/File used outside the sanctioned module: {offenders}"


def test_upload_route_calls_the_validated_service():
    """The route reads bytes and hands them to the service — no ad-hoc writes."""
    source = (REPO / "backend" / "api" / "routes.py").read_text(encoding="utf-8")
    handler = source[source.index("async def upload_document("):source.index("@router.get(\"/uploads/{session_id}\")")]
    assert "uploads_svc.store_upload(" in handler
    assert "open(" not in handler and ".write(" not in handler, (
        "the route must not touch the filesystem itself"
    )
    assert "MAX_UPLOAD_BYTES + 1" in handler, "read one byte past the cap, not the whole body"


def test_upload_metadata_is_auditable(client):
    from backend.services import db

    record = _post_file(client, "sess-audit", "income.pdf", PDF).json()["upload"]
    rows = db.get_connection().execute(
        "SELECT action, detail FROM audit_log WHERE action LIKE 'upload.%'"
    ).fetchall()
    assert any(record["id"] in (r["detail"] or "") for r in rows)


def test_storage_root_defaults_to_runtime_not_the_repo_root():
    source = (REPO / "backend" / "services" / "uploads.py").read_text(encoding="utf-8")
    assert re.search(r'RUNTIME_DIR / "uploads"', source)
    assert "FEEFIX_UPLOAD_DIR" in source, "operators must be able to relocate storage"


# --------------------------------------------------------------------------- #
# session identifiers: one rule, enforced on every path
# --------------------------------------------------------------------------- #
def _upload(client, session_id: str, filename: str = "doc.pdf", content: bytes = b"%PDF-1.4\nok\n"):
    return client.post(
        f"/api/uploads/{session_id}",
        files={"file": (filename, content, "application/pdf")},
    )


#: Hostile ids that *do* reach the handler (httpx normalises the URL, so control
#: characters are sent percent-encoded — exactly what an attacker sends).
#: Everything here must be a clean 422, never a 200 and never a 500.
_REACHES_HANDLER = [
    "s" * 65,
    "s" * 10_000,
    "%00",          # NUL — used to be rewritten into a directory name
    "%0a",          # newline
    "%7f",          # DEL
]

#: Traversal-shaped ids are normalised or rejected by the routing layer before
#: they reach us (405) — also a refusal, just a different layer. Asserted only
#: as "not accepted", because pinning the exact framework status would be
#: testing Starlette rather than our contract. The service-level rule still
#: refuses `..` if it ever does arrive (asserted below).
_UNROUTABLE = ["%2e%2e%2f%2e%2e%2fetc", "a%2fb", ".."]


def test_hostile_session_ids_are_refused_by_every_route(client):
    """The store path validated these; the listing path echoed them back.

    A 10 KB session id was refused on upload but reflected by `GET
    /api/uploads/<id>`, and ids containing NUL or `/` produced filesystem
    directories that only survived because the storage layer happened to
    sanitise them. Every route must now agree on what a session id is.
    """
    from backend.services import uploads as uploads_svc

    for session_id in _REACHES_HANDLER:
        assert _upload(client, session_id).status_code == 422, repr(session_id)
        assert client.get(f"/api/uploads/{session_id}").status_code == 422, repr(session_id)
        assert (
            client.delete(f"/api/uploads/{session_id}/deadbeef").status_code == 422
        ), repr(session_id)
        assert (
            client.get(f"/api/uploads/{session_id}/deadbeef/content").status_code == 422
        ), repr(session_id)

    for session_id in _UNROUTABLE:
        assert _upload(client, session_id).status_code >= 400, repr(session_id)
        assert client.get(f"/api/uploads/{session_id}").status_code >= 400, repr(session_id)

    # And the service refuses empty and separator-bearing identifiers directly,
    # so the guarantee does not depend on routing behaviour.
    for value in ("", "a/b", "a\\b", ".."):
        with pytest.raises(uploads_svc.UploadRejected):
            uploads_svc.ensure_session_id(value)


def test_hostile_session_ids_create_nothing_on_disk(client):
    """A refused identifier must not reach the filesystem at all."""
    from backend.services import uploads as uploads_svc

    root = uploads_svc.UPLOAD_ROOT
    before = sorted(p.name for p in root.iterdir()) if root.exists() else []

    for session_id in _REACHES_HANDLER + ["x" * 200, "%2f%5c"]:
        _upload(client, session_id)
        client.get(f"/api/uploads/{session_id}")

    after = sorted(p.name for p in root.iterdir()) if root.exists() else []
    assert after == before, f"hostile ids created directories: {set(after) - set(before)}"


def test_legitimate_session_id_shapes_still_work(client):
    """The rule must not break ids the app actually generates."""
    for session_id in ("sess-1", "6f1c0a3b9d4e5f60a1b2c3d4e5f60123", "s_1729000000_ab12cd"):
        assert _upload(client, session_id).status_code == 200, session_id
        assert client.get(f"/api/uploads/{session_id}").status_code == 200


def test_session_directory_can_never_escape_the_upload_root():
    """Defence in depth: the storage layer itself refuses to leave its root.

    `..` is a valid string that resolves to the upload root's *parent* — the
    route layer rejects it today, but a filesystem guarantee should not depend
    on a URL parser, so the resolved path is checked too.
    """
    import os

    from backend.services import uploads as uploads_svc

    root = uploads_svc.UPLOAD_ROOT.resolve()
    for hostile in ("..", "../..", "a/../../b", "..\\\\..", "%2e%2e", "...."):
        try:
            target = uploads_svc._session_dir(hostile).resolve()
        except uploads_svc.UploadRejected:
            continue  # refused outright, which is also fine
        assert target == root or root in target.parents, f"{hostile!r} escaped to {target}"

    # A normal id lands exactly one level below the root.
    normal = uploads_svc._session_dir("sess-1").resolve()
    assert normal.parent == root
    assert os.path.commonpath([str(normal), str(root)]) == str(root)
