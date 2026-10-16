"""Upload storage — the one place in the application that accepts file bytes.

``services/upload.py`` is the *validator* (allowlist, magic-byte sniffing, size
cap, filename sanitising). This module is the *service* that routes call, and it
exists to close the gap the validator alone could not:

* **A control nobody calls protects nothing.** The hardened gate shipped with no
  caller, so it guarded exactly zero endpoints. Every upload now goes through
  :func:`store_upload`, and the route layer is not allowed to touch
  ``UploadFile`` directly (enforced by a test that scans the route module).
* **Bytes never reach a web-served path.** Files are written under
  ``FEEFIX_UPLOAD_DIR`` (default ``runtime/uploads/<session>/``), which is *not*
  mounted by the static SPA mount, with ``0600`` permissions, an ``O_EXCL``
  create and a random storage name — a caller-supplied filename can never
  influence the path on disk.
* **Ownership and quota are enforced at the service boundary**, not in the
  route: per-session file count and total-bytes caps, plus content hashing so a
  stored file can be audited or de-duplicated later.
* **Failure modes are explicit** — :class:`UploadRejected` carries the HTTP
  status the route should return, so "too large" (413) is never conflated with
  "wrong type" (422).
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path

import re

from backend.services import db
from backend.services.limits import (
    MAX_SESSION_ID_LEN,
    MAX_UPLOAD_BYTES,
    MAX_UPLOAD_FILES_PER_SESSION,
    MAX_UPLOAD_TOTAL_BYTES_PER_SESSION,
)
from backend.services.upload import sanitize_filename, validate_upload

log = logging.getLogger("feefix.uploads")

RUNTIME_DIR = Path(__file__).resolve().parents[2] / "runtime"
UPLOAD_ROOT = Path(os.environ.get("FEEFIX_UPLOAD_DIR", str(RUNTIME_DIR / "uploads")))


class UploadRejected(Exception):
    """Validation refusal. ``status`` is the HTTP status the route should use."""

    def __init__(self, reason: str, *, status: int = 422) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = status


#: Characters that never belong in a session identifier: control characters
#: (a NUL used to reach the filesystem layer, where it was silently rewritten
#: into a directory name) and path separators (a `%2f` in the URL decodes to
#: `/`). Everything else is allowed so existing ids keep working.
_BAD_SESSION_CHARS = re.compile(r"[\x00-\x1f\x7f/\\]")


def ensure_session_id(session_id: str) -> str:
    """Validate a session identifier. One rule, used by *every* uploads path.

    The store path validated this and the read paths did not, so a 10 KB
    session id was refused on upload but **echoed back** by the listing
    endpoint, and ids containing NUL or `/` produced filesystem directories
    that only survived because the storage layer happened to sanitise them.
    Validation at the service boundary means the routes cannot drift apart.

    Dot-only ids are refused too: ``..`` is a legal *string* but it resolves to
    the parent of the upload root, i.e. a one-character traversal primitive. The
    routing layer happens to reject it today; relying on that would put a
    filesystem guarantee in the hands of a URL parser.
    """
    if (
        not session_id
        or len(session_id) > MAX_SESSION_ID_LEN
        or _BAD_SESSION_CHARS.search(session_id)
        or not session_id.strip(".")
    ):
        raise UploadRejected("Invalid session id.", status=422)
    return session_id


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _session_dir(session_id: str) -> Path:
    """Directory for a session — sanitised *and* verified to stay under the root.

    Two independent layers, because the check is cheap and the failure mode is
    writing user-supplied paths anywhere on the filesystem: the name is
    sanitised first, then the resolved path is required to be inside
    ``UPLOAD_ROOT``. A future refactor of the sanitiser therefore cannot
    silently reintroduce traversal.
    """
    safe = sanitize_filename(session_id) or "session"
    root = UPLOAD_ROOT.resolve()
    target = (root / safe).resolve()
    if target != root and root not in target.parents:
        raise UploadRejected("Invalid session id.", status=422)
    return target


def usage(session_id: str) -> tuple[int, int]:
    """``(files, total_bytes)`` currently stored for a session."""
    ensure_session_id(session_id)
    conn = db.get_connection()
    row = conn.execute(
        "SELECT COUNT(*) AS n, COALESCE(SUM(size_bytes), 0) AS total"
        " FROM uploads WHERE session_id=?",
        (session_id,),
    ).fetchone()
    return (int(row["n"]), int(row["total"])) if row else (0, 0)


def store_upload(
    session_id: str,
    filename: str,
    content: bytes,
    *,
    content_type: str | None = None,
    user_id: str | None = None,
    max_bytes: int = MAX_UPLOAD_BYTES,
) -> dict:
    """Validate and persist one file. Returns its metadata record.

    Raises :class:`UploadRejected` (with the right HTTP status) on refusal — the
    caller maps it straight to a response.
    """
    ensure_session_id(session_id)

    files, total = usage(session_id)
    if files >= MAX_UPLOAD_FILES_PER_SESSION:
        raise UploadRejected(
            f"Upload limit reached ({MAX_UPLOAD_FILES_PER_SESSION} files per session).",
            status=413,
        )
    if total + len(content or b"") > MAX_UPLOAD_TOTAL_BYTES_PER_SESSION:
        raise UploadRejected(
            "Session upload quota exceeded — remove a file and try again.", status=413
        )

    ok, reason = validate_upload(filename, content, max_bytes=max_bytes)
    if not ok:
        # Size problems are 413, everything else is a validation failure.
        status = 413 if "too large" in reason else 422
        raise UploadRejected(reason, status=status)

    safe_name = sanitize_filename(filename)
    stored_name = _storage_name(safe_name)
    target_dir = _session_dir(session_id)
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / stored_name
    # O_EXCL: never overwrite an existing file, even under a race.
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(target, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
    except Exception:
        target.unlink(missing_ok=True)
        raise
    try:
        os.chmod(target, 0o600)  # belt and braces; never executable
    except OSError:  # pragma: no cover - platform dependent
        pass

    upload_id = secrets.token_hex(12)
    digest = hashlib.sha256(content).hexdigest()
    kind = Path(safe_name).suffix.lower().lstrip(".") or "bin"
    record = {
        "id": upload_id,
        "session_id": session_id,
        "original_name": safe_name,
        "stored_name": stored_name,
        "content_type": content_type or "application/octet-stream",
        "kind": kind,
        "size_bytes": len(content),
        "sha256": digest,
        "created_at": _utcnow(),
    }
    conn = db.get_connection()
    with db._lock:
        conn.execute(
            "INSERT INTO uploads (id, session_id, user_id, original_name, stored_name,"
            " content_type, kind, size_bytes, sha256, created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                upload_id, session_id, user_id, safe_name, stored_name,
                record["content_type"], kind, record["size_bytes"], digest,
                record["created_at"],
            ),
        )
        conn.commit()
    db.audit(user_id, "upload.stored", f"{upload_id} {kind} {record['size_bytes']}B")
    return record


def _storage_name(safe_name: str) -> str:
    ext = Path(safe_name).suffix.lower()
    if ext not in (".pdf", ".png", ".jpg", ".jpeg"):
        ext = ""
    return f"{secrets.token_hex(16)}{ext}"


def list_uploads(session_id: str) -> list[dict]:
    ensure_session_id(session_id)
    conn = db.get_connection()
    rows = conn.execute(
        "SELECT id, original_name, kind, size_bytes, sha256, created_at"
        " FROM uploads WHERE session_id=? ORDER BY created_at DESC",
        (session_id,),
    ).fetchall()
    return [
        {
            "id": r["id"],
            "name": r["original_name"],
            "kind": r["kind"],
            "size_bytes": r["size_bytes"],
            "sha256": r["sha256"],
            "created_at": r["created_at"],
        }
        for r in rows
    ]


def load_upload(session_id: str, upload_id: str) -> tuple[dict, Path]:
    """Fetch one record + its path, scoped to the owning session."""
    ensure_session_id(session_id)
    conn = db.get_connection()
    row = conn.execute(
        "SELECT * FROM uploads WHERE id=? AND session_id=?", (upload_id, session_id)
    ).fetchone()
    if not row:
        raise UploadRejected("Upload not found.", status=404)
    path = _session_dir(session_id) / row["stored_name"]
    if not path.is_file():
        # Metadata without bytes: treat as gone rather than 500.
        raise UploadRejected("Upload not found.", status=404)
    return dict(row), path


def delete_upload(session_id: str, upload_id: str, *, user_id: str | None = None) -> bool:
    record, path = load_upload(session_id, upload_id)
    path.unlink(missing_ok=True)
    conn = db.get_connection()
    with db._lock:
        conn.execute("DELETE FROM uploads WHERE id=?", (upload_id,))
        conn.commit()
    db.audit(user_id, "upload.deleted", upload_id)
    return record["id"] == upload_id


def describe_policy() -> dict:
    """Machine-readable upload policy (served at ``/api/meta``)."""
    return {
        "max_bytes": MAX_UPLOAD_BYTES,
        "allowed_extensions": sorted({".pdf", ".png", ".jpg", ".jpeg"}),
        "max_files_per_session": MAX_UPLOAD_FILES_PER_SESSION,
        "max_total_bytes_per_session": MAX_UPLOAD_TOTAL_BYTES_PER_SESSION,
        "storage_root": "runtime (not web-served)",
    }
