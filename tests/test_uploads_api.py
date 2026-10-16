"""Uploads, end to end — proof that the hardened gate is actually *wired in*.

``services/upload.py`` was tested but never called by any route, so it protected
nothing. These tests exercise the real HTTP endpoints, which is the only thing
that proves the control is live:

* a valid document round-trips (upload → list → download → delete);
* dangerous, spoofed, empty and oversized payloads are refused;
* filenames never influence the stored path;
* ownership is enforced exactly like profiles/tracker rows;
* the stored bytes live outside the web root and are unreachable statically;
* account deletion removes the files from disk (erasure includes documents).
"""

from __future__ import annotations

import hashlib

import pytest

from backend.services.limits import MAX_UPLOAD_BYTES

PDF = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n%%EOF\n"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64


def _upload(client, session_id="doc-session", filename="income.pdf", content=PDF, **extra):
    return client.post(
        f"/api/students/{session_id}/documents",
        files={"file": (filename, content, "application/octet-stream")},
        data={"doc_type": extra.pop("doc_type", "income-certificate")},
        **extra,
    )


def test_upload_download_list_delete_round_trip(client, tmp_path):
    from backend.services.documents import upload_root

    response = _upload(client)
    assert response.status_code == 201, response.text
    document = response.json()["document"]
    assert document["media_type"] == "application/pdf"      # from OUR allowlist
    assert document["size_bytes"] == len(PDF)
    assert document["filename"] == "income.pdf"
    assert document["sha256"] == hashlib.sha256(PDF).hexdigest()
    assert "stored_name" not in document                    # never leaks the path

    stored = upload_root() / "x"
    files = list(stored.parent.glob("*.pdf"))
    assert len(files) == 1
    assert files[0].parent == upload_root().resolve() or files[0].parent == upload_root()
    assert files[0].read_bytes() == PDF

    listing = client.get("/api/students/doc-session/documents").json()
    assert listing["count"] == 1 and listing["documents"][0]["id"] == document["id"]

    download = client.get(document["download_url"])
    assert download.status_code == 200
    assert download.content == PDF
    # Never rendered inline in the app's origin, never sniffed into something else.
    assert download.headers["content-disposition"].startswith("attachment;")
    assert download.headers["x-content-type-options"] == "nosniff"

    assert client.delete(document["download_url"]).status_code == 200
    assert client.get(document["download_url"]).status_code == 404
    assert not files[0].exists()
    assert client.get("/api/students/doc-session/documents").json()["count"] == 0


@pytest.mark.parametrize(
    "filename,content,label",
    [
        ("shell.php", b"<?php system($_GET['c']); ?>", "php"),
        ("evil.pdf.php", b"%PDF-1.7 double extension", "double-extension"),
        ("fake.pdf", b"<?php echo 'not a pdf'; ?>", "magic-byte mismatch"),
        ("icon.svg", b"<svg onload=alert(1)>", "svg"),
        ("page.html", b"<script>alert(1)</script>", "html"),
        ("", b"", "empty"),
    ],
)
def test_upload_rejects_dangerous_and_spoofed_files(client, filename, content, label):
    response = _upload(client, filename=filename, content=content)
    assert response.status_code == 422, f"{label} was accepted: {response.text}"
    assert client.get("/api/students/doc-session/documents").json()["count"] == 0


def test_upload_rejects_oversized_payload(client):
    response = _upload(client, filename="big.pdf", content=b"%PDF-" + b"a" * (MAX_UPLOAD_BYTES + 10))
    assert response.status_code in (413, 422)
    if response.status_code == 413:
        assert response.headers.get("X-Max-Body-Bytes")


def test_traversal_filename_cannot_escape_the_upload_directory(client):
    response = _upload(client, filename="../../../../etc/passwd.pdf")
    assert response.status_code == 201
    document = response.json()["document"]
    assert "/" not in document["filename"] and ".." not in document["filename"]
    download = client.get(document["download_url"])
    assert download.status_code == 200
    assert download.content == PDF


def test_uploads_are_not_reachable_through_the_static_mount(client):
    from backend.services.documents import upload_root

    _upload(client, filename="private.pdf")
    stored_name = next(upload_root().glob("*.pdf")).name
    # The SPA is mounted at / — the upload directory is not under it, so the
    # file must not be servable, whatever its name.
    assert client.get(f"/{stored_name}").status_code == 404
    assert client.get(f"/uploads/{stored_name}").status_code == 404


def test_ownership_is_enforced_like_every_other_session_resource(client):
    token = client.post(
        "/api/auth/register",
        json={"email": "owner@example.com", "password": "S3cure!Pass", "name": "Owner"},
    ).json()["token"]
    client.put("/api/students/owned-docs/profile", json={"profile": {
        "domicile_state": "West Bengal", "category": "general",
        "annual_family_income": 200000, "course_level": "ug"}})
    assert client.post(
        "/api/auth/link-session",
        json={"session_id": "owned-docs"},
        headers={"Authorization": f"Bearer {token}"},
    ).status_code == 200

    # Anonymous caller: the session belongs to an account now.
    assert _upload(client, session_id="owned-docs").status_code == 403

    response = _upload(client, session_id="owned-docs", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 201
    document_id = response.json()["document"]["id"]

    # A different account cannot read or delete it.
    other = client.post(
        "/api/auth/register",
        json={"email": "other@example.com", "password": "S3cure!Pass"},
    ).json()["token"]
    other_headers = {"Authorization": f"Bearer {other}"}
    url = f"/api/students/owned-docs/documents/{document_id}"
    assert client.get(url, headers=other_headers).status_code == 403
    assert client.delete(url, headers=other_headers).status_code == 403
    assert client.get(url, headers={"Authorization": f"Bearer {token}"}).status_code == 200


def test_document_id_from_another_session_is_not_found(client):
    document = _upload(client, session_id="session-a").json()["document"]
    url = f"/api/students/session-b/documents/{document['id']}"
    assert client.get(url).status_code == 404


def test_account_deletion_removes_stored_files(client):
    from backend.services.documents import upload_root

    token = client.post(
        "/api/auth/register",
        json={"email": "erase@example.com", "password": "S3cure!Pass"},
    ).json()["token"]
    headers = {"Authorization": f"Bearer {token}"}
    client.put("/api/students/erase-me/profile", json={"profile": {
        "domicile_state": "Bihar", "category": "sc", "annual_family_income": 90000}})
    client.post("/api/auth/link-session", json={"session_id": "erase-me"}, headers=headers)
    _upload(client, session_id="erase-me", headers=headers)
    assert list(upload_root().glob("*.pdf"))

    assert client.delete("/api/auth/account", headers=headers).status_code == 200
    assert not list(upload_root().glob("*.pdf")), "erasure must delete document bytes too"


def test_png_is_accepted_and_served_with_its_real_type(client):
    response = _upload(client, filename="certificate.png", content=PNG)
    assert response.status_code == 201
    document = response.json()["document"]
    assert document["media_type"] == "image/png"
    download = client.get(document["download_url"])
    assert download.headers["content-type"].startswith("image/png")
    assert download.content == PNG


def test_document_storage_paths_are_contained(tmp_path, monkeypatch):
    """resolve_path refuses anything that is not inside the upload root.

    Stored names are generated by us, but a corrupted or hand-edited row must
    still not be able to make the app read an arbitrary file.
    """
    from backend.services import documents as documents_svc

    monkeypatch.setenv("FEEFIX_UPLOAD_DIR", str(tmp_path / "root"))
    root = documents_svc.upload_root()
    root.mkdir(parents=True, exist_ok=True)

    # Traversal, absolute paths and missing files are all refused.
    for candidate in ("../../etc/passwd", "/etc/passwd", "..", "", "nope.pdf"):
        assert documents_svc.resolve_path(candidate) is None

    # A file that *is* inside the root resolves.
    inside = root / "abc123.pdf"
    inside.write_bytes(PDF)
    assert documents_svc.resolve_path("abc123.pdf") == inside.resolve()


def test_delete_document_and_its_bytes(client):
    from backend.services.documents import upload_root

    document = _upload(client, session_id="del-session").json()["document"]
    stored = next(upload_root().glob("*.pdf"))
    assert stored.exists()

    assert client.delete(document["download_url"]).status_code == 200
    assert not stored.exists(), "deleting the metadata must delete the file"
    # Deleting again is a clean 404, not an error.
    assert client.delete(document["download_url"]).status_code == 404


def test_remove_stored_files_tolerates_missing_and_hostile_names(tmp_path, monkeypatch):
    from backend.services import documents as documents_svc

    monkeypatch.setenv("FEEFIX_UPLOAD_DIR", str(tmp_path / "root"))
    root = documents_svc.upload_root()
    root.mkdir(parents=True, exist_ok=True)
    (root / "keep.pdf").write_bytes(PDF)

    # Missing files, traversal attempts and directories are ignored, not raised.
    removed = documents_svc.remove_stored_files(["gone.pdf", "../../escape.pdf", "", "."])
    assert removed == 0
    assert (root / "keep.pdf").exists(), "unrelated files must survive"
    assert documents_svc.remove_stored_files(["keep.pdf"]) == 1
    assert not (root / "keep.pdf").exists()


def test_upload_root_follows_the_environment(tmp_path, monkeypatch):
    from backend.services import documents as documents_svc

    monkeypatch.setenv("FEEFIX_UPLOAD_DIR", str(tmp_path / "elsewhere"))
    assert documents_svc.upload_root() == tmp_path / "elsewhere"
    # A relative value is resolved against the repository, never the CWD.
    monkeypatch.setenv("FEEFIX_UPLOAD_DIR", "runtime/custom-uploads")
    assert documents_svc.upload_root().is_absolute()
    assert documents_svc.upload_root().name == "custom-uploads"
