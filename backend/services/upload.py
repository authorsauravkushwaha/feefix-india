"""Hardened file-upload validation — use this for *any* file FeeFix accepts.

FeeFix ships no upload endpoint today, but students will eventually attach
income certificates, marksheets and disability certificates. This module is the
single, audited gate every future upload must pass through, so a dangerous file
never reaches disk:

* **Extension allowlist** — only document/image types (``.pdf/.png/.jpg/.jpeg``);
  never ``.php/.html/.svg/.exe`` or anything scriptable.
* **Content sniffing** — the *bytes* must match the claimed type's magic
  signature, so a renamed ``shell.php`` → ``shell.pdf`` is rejected (polyglot /
  double-extension defence).
* **Size cap** — ``MAX_UPLOAD_BYTES``; empty and oversized files rejected.
* **Filename sanitising** — path components, control chars and traversal
  (``../``, absolute paths, NUL) are stripped; the stored name is a random token,
  so an attacker-controlled name can never escape the upload directory.
* **No execution** — callers store outside the web root; this module never marks
  a file executable.

Pure stdlib; returns a structured verdict instead of raising, so a route can map
it straight to a 4xx.
"""

from __future__ import annotations

import os
import re
import secrets

from backend.services.limits import MAX_UPLOAD_BYTES, UPLOAD_ALLOWED_EXTS

# Magic-byte signatures for the allowlisted types (offset 0 unless noted).
_SIGNATURES: dict[str, list[bytes]] = {
    ".pdf": [b"%PDF-"],
    ".png": [b"\x89PNG\r\n\x1a\n"],
    ".jpg": [b"\xff\xd8\xff"],
    ".jpeg": [b"\xff\xd8\xff"],
}
# Extensions we must never accept even if renamed — belt-and-braces.
_DANGEROUS_EXTS = frozenset({
    ".php", ".phtml", ".php3", ".php4", ".php5", ".phar", ".html", ".htm",
    ".xhtml", ".svg", ".js", ".mjs", ".ts", ".py", ".sh", ".bash", ".zsh",
    ".exe", ".dll", ".so", ".bat", ".cmd", ".com", ".msi", ".jar", ".war",
    ".cgi", ".pl", ".rb", ".asp", ".aspx", ".jsp", ".jspx", ".htaccess",
})
_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


class UploadError(Exception):
    """Raised by :func:`assert_safe_upload` when a file fails validation."""


def sanitize_filename(filename: str) -> str:
    """Reduce an arbitrary name to a bare, safe basename.

    Strips directory components (``/`` and ``\\``), NUL bytes and control chars,
    collapses anything outside ``[A-Za-z0-9._-]`` to ``_``, and forbids leading
    dots (hidden files) and ``..``. Never trust this for storage paths on its
    own — prefer :func:`safe_storage_name`.
    """
    name = os.path.basename((filename or "").replace("\\", "/")).strip()
    name = name.replace("\x00", "")
    name = _SAFE_NAME_RE.sub("_", name)
    name = name.lstrip(".")
    return name[:128] or "upload"


def _extension(filename: str) -> str:
    _, ext = os.path.splitext(filename.lower())
    return ext


def safe_storage_name(filename: str) -> str:
    """A collision-free, non-executable storage name that keeps the extension."""
    ext = _extension(filename)
    if ext not in UPLOAD_ALLOWED_EXTS:
        ext = ""
    return f"{secrets.token_hex(16)}{ext}"


def validate_upload(
    filename: str,
    content: bytes,
    *,
    max_bytes: int = MAX_UPLOAD_BYTES,
) -> tuple[bool, str]:
    """Return ``(ok, reason)``. ``reason`` is empty on success."""
    if content is None:
        return False, "missing file content"
    if len(content) == 0:
        return False, "empty file"
    if len(content) > max_bytes:
        return False, f"file too large (max {max_bytes} bytes)"

    base = os.path.basename((filename or "").replace("\\", "/"))
    # Reject double-extension tricks like "resume.pdf.php".
    parts = base.lower().rsplit(".", 1)
    ext = _extension(base)
    if ext in _DANGEROUS_EXTS:
        return False, "file type not allowed"
    if len(base.split(".")) > 2 and any(
        "." + p in _DANGEROUS_EXTS for p in base.lower().split(".")[1:-1]
    ):
        return False, "file type not allowed"
    if ext not in UPLOAD_ALLOWED_EXTS:
        return False, "file type not allowed"

    # Content must actually be the claimed type (magic bytes), not a rename.
    signatures = _SIGNATURES.get(ext, [])
    if signatures and not any(content.startswith(sig) for sig in signatures):
        return False, "file content does not match its type"

    _ = parts  # (kept for clarity; parsing is via _extension)
    return True, ""


def assert_safe_upload(
    filename: str, content: bytes, *, max_bytes: int = MAX_UPLOAD_BYTES
) -> str:
    """Validate and return a safe storage name, or raise :class:`UploadError`."""
    ok, reason = validate_upload(filename, content, max_bytes=max_bytes)
    if not ok:
        raise UploadError(reason)
    return safe_storage_name(filename)
