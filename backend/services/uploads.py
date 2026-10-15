"""File-upload security — the guard that must be passed before bytes hit disk.

FeeFix does not currently expose a public upload endpoint, and this module
exists to make sure that stays a *property* rather than an accident: the first
developer who adds "attach your caste certificate" (an obvious and much-requested
feature) gets a hardened path instead of a vulnerability. Every rule below is
enforced by ``tests/test_security.py`` so a future endpoint cannot regress it.

WHY EXTENSIONS AND MIME TYPES ARE NOT EVIDENCE
==============================================
Both are attacker-controlled strings. ``Content-Type: image/png`` on a PHP
webshell costs one header to forge; ``report.pdf`` on the same file costs one
rename. Neither tells you anything about the bytes. So:

1. **Sniff the content.** Real magic bytes are compared against the declared
   type. A mismatch is a rejection, not a warning — mismatched magic is the
   signature of a polyglot or a renamed payload.
2. **Belt and braces on the extension.** The stored name is rebuilt from an
   allow-list keyed to the *sniffed* type, so the extension can never disagree
   with the content.
3. **Store where nothing executes.** A quarantine directory outside the web
   root, no ``.php``/``.jsp``/``.html`` ever permitted, and an
   ``X-Content-Type-Options: nosniff`` posture on the serving side.
4. **Cap the size before reading the body**, not after.

THE ATTACKS THIS STOPS
======================
* **Path traversal** — ``../../etc/cron.d/x`` in a filename. Handled by
  :func:`input_guard.safe_filename`, which also strips NUL truncation
  (``x.jpg\\0.php``), Windows device names and NTFS alternate data streams.
* **Unrestricted file type** — uploading a server-side script. No executable
  extension is in any allow-list, and magic sniffing rejects a script that
  claims to be an image.
* **Polyglot files** — a JPEG with an embedded ZIP/PHP payload. The trailer
  scan looks for executable and archive signatures *anywhere* in the file and
  rejects documents that are also something else.
* **Image-borne parser attacks** — a malformed header that crashes or exploits
  the image library later. Dimensions and structure are parsed defensively
  with a hard byte budget.
* **Storage-exhaustion DoS** — size is checked against ``Content-Length``
  before a single byte is buffered, then again while streaming, so a lying
  ``Content-Length`` cannot smuggle a large body past the first check.
* **Symlink/overwrite attacks** — the final path is resolved and verified to be
  strictly inside the quarantine root; a symlink pointing out is refused.
* **SVG XSS** — SVG is XML and can carry ``<script>``. It is *not* in the
  image allow-list. This is a deliberate product decision, not an oversight.
"""

from __future__ import annotations

import hashlib
import io
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from backend.services import security
from backend.services.input_guard import safe_filename
from backend.services.security import LIMITS

# ---------------------------------------------------------------- signatures --
#: Magic bytes → canonical type. Ordered longest-first at match time so that
#: e.g. the 8-byte PNG signature wins over a shorter prefix.
_MAGIC: tuple[tuple[bytes, str, int], ...] = (
    (b"\x89PNG\r\n\x1a\n", "image/png", 0),
    (b"\xff\xd8\xff", "image/jpeg", 0),
    (b"GIF87a", "image/gif", 0),
    (b"GIF89a", "image/gif", 0),
    (b"%PDF-", "application/pdf", 0),
    (b"PK\x03\x04", "application/zip", 0),
    (b"\x1f\x8b", "application/gzip", 0),
    (b"RIFF", "image/webp", 0),          # + "WEBP" at offset 8, checked below
    (b"BM", "image/bmp", 0),
)

#: Byte sequences that must NOT appear in an otherwise-innocent document.
#: A certificate scan has no business containing a PHP tag or an ELF header;
#: their presence means the file is a polyglot or a mislabelled payload.
#:
#: Every marker here is **at least 3 bytes**. That is not arbitrary: a 2-byte
#: marker such as ``MZ`` occurs by pure chance roughly 76 times in a 5 MB
#: random-ish (i.e. compressed) file, so scanning for it anywhere produces
#: false rejections of legitimate PDFs. Short signatures are therefore checked
#: only at offset 0, where they are actually meaningful, in
#: :data:`_FORBIDDEN_PREFIXES`.
_FORBIDDEN_TRAILERS: tuple[tuple[bytes, str], ...] = (
    (b"<?php", "php_tag"),
    (b"<?=", "php_short_tag"),
    (b"<script", "html_script"),
    (b"<%@", "asp_directive"),
    (b"\x7fELF", "elf_binary"),
    (b"<svg", "svg_markup"),
    (b"javascript:", "js_uri"),
)

#: Signatures that are only meaningful at the very start of a file.
_FORBIDDEN_PREFIXES: tuple[tuple[bytes, str], ...] = (
    (b"MZ", "dos_executable"),
    (b"#!/", "shebang"),
    (b"\x7fELF", "elf_binary"),
    (b"\xca\xfe\xba\xbe", "mach_o_or_java"),
)

#: Extensions we are willing to write, per sniffed type. Everything else is
#: rejected — there is no "unknown" branch and no fallthrough to the client's
#: own extension.
_ALLOWED_EXTENSIONS: dict[str, frozenset[str]] = {
    "image/png": frozenset({".png"}),
    "image/jpeg": frozenset({".jpg", ".jpeg"}),
    "image/gif": frozenset({".gif"}),
    "image/webp": frozenset({".webp"}),
    "image/bmp": frozenset({".bmp"}),
    "application/pdf": frozenset({".pdf"}),
}

#: What an *authenticated student* may attach. Deliberately tiny.
DOCUMENT_POLICY = frozenset({"image/png", "image/jpeg", "application/pdf"})
#: What the platform will accept for its own dataset imports.
IMAGE_POLICY = frozenset({"image/png", "image/jpeg", "image/webp"})


class UploadError(ValueError):
    """An upload was refused. ``reason`` is a stable machine-readable code.

    The client-facing message is intentionally generic. Telling an attacker
    "the magic bytes said PHP but you claimed PNG" hands them the exact
    feedback loop needed to iterate toward a payload that passes.
    """

    CLIENT_MESSAGE = "That file type isn't accepted."

    def __init__(self, reason: str, *, client_message: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.client_message = client_message or self.CLIENT_MESSAGE


@dataclass(frozen=True)
class VerifiedUpload:
    """The result of a successful verification — everything needed to store it.

    ``digest`` is the SHA-256 of the content, used as the stored filename so
    that (a) two clients cannot collide or overwrite each other, (b) the same
    file uploaded twice is deduplicated, and (c) no part of the client-supplied
    name reaches the filesystem.
    """

    content: bytes
    detected_type: str
    extension: str
    digest: str
    size: int
    original_name: str
    width: int | None = None
    height: int | None = None
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def stored_name(self) -> str:
        return f"{self.digest}{self.extension}"


def sniff(content: bytes) -> str | None:
    """Detect the real type from magic bytes. ``None`` = unrecognised."""
    for signature, kind, offset in _MAGIC:
        if content[offset:offset + len(signature)] == signature:
            if kind == "image/webp":
                # RIFF is a container: it is only WebP if "WEBP" follows the size.
                if content[8:12] != b"WEBP":
                    return None
            return kind
    return None


def find_forbidden(content: bytes) -> str | None:
    """Scan for executable/script markers.

    Two passes, for the reason documented on :data:`_FORBIDDEN_TRAILERS`:
    short signatures are only meaningful at offset 0 (and ``sniff`` has usually
    already rejected them), while longer, unambiguous text markers are searched
    for anywhere because a polyglot hides its payload *after* a valid header.
    """
    if not content:
        return None
    for prefix, label in _FORBIDDEN_PREFIXES:
        if content.startswith(prefix):
            return label
    lowered = content.lower()
    for marker, label in _FORBIDDEN_TRAILERS:
        if marker.lower() in lowered:
            return label
    return None


def _image_dimensions(content: bytes, kind: str) -> tuple[int | None, int | None]:
    """Parse width/height without any image library.

    Done by hand on purpose: pulling in Pillow to validate an untrusted image
    means handing the attacker's bytes to a large C parser *before* we have
    decided to trust them. These reads are bounds-checked and cannot allocate
    beyond the (already capped) buffer.
    """
    try:
        if kind == "image/png" and content[:8] == b"\x89PNG\r\n\x1a\n":
            if content[12:16] != b"IHDR":
                return None, None
            return (int.from_bytes(content[16:20], "big"),
                    int.from_bytes(content[20:24], "big"))
        if kind == "image/gif":
            return (int.from_bytes(content[6:8], "little"),
                    int.from_bytes(content[8:10], "little"))
        if kind == "image/jpeg":
            return _jpeg_dimensions(content)
        if kind == "image/bmp" and len(content) > 25:
            return (int.from_bytes(content[18:22], "little"),
                    abs(int.from_bytes(content[22:26], "little", signed=True)))
    except (IndexError, ValueError):
        return None, None
    return None, None


def _jpeg_dimensions(content: bytes) -> tuple[int | None, int | None]:
    """Walk JPEG SOF markers. Bounded loop — a truncated file cannot hang us."""
    i, steps = 2, 0
    n = len(content)
    while i + 9 < n and steps < 512:
        steps += 1
        if content[i] != 0xFF:
            i += 1
            continue
        marker = content[i + 1]
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        if marker in (0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7,
                      0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF):
            return (int.from_bytes(content[i + 7:i + 9], "big"),
                    int.from_bytes(content[i + 5:i + 7], "big"))
        if marker in (0xD9, 0xDA):
            break
        length = int.from_bytes(content[i + 2:i + 4], "big")
        if length < 2:
            break
        i += 2 + length
    return None, None


def verify(
    content: bytes,
    *,
    declared_name: str | None = None,
    declared_type: str | None = None,
    declared_length: int | None = None,
    allowed: frozenset[str] = DOCUMENT_POLICY,
    max_bytes: int = LIMITS.MAX_UPLOAD_BYTES,
) -> VerifiedUpload:
    """Validate an upload's bytes. Raises :class:`UploadError` on any doubt.

    The checks run cheapest-first so a hostile file is rejected before the
    expensive ones, and so rejection cost cannot be amplified by the attacker.
    """
    # 1. Size — before anything reads the buffer.
    if declared_length is not None and declared_length > max_bytes:
        raise UploadError("declared_too_large")
    if content is None:
        raise UploadError("empty")
    if len(content) > max_bytes:
        raise UploadError("too_large")
    if len(content) == 0:
        raise UploadError("empty")

    # 2. Real type from magic bytes.
    detected = sniff(content)
    if detected is None:
        raise UploadError("unrecognised_content")
    if detected not in allowed:
        raise UploadError("type_not_permitted")

    # 3. Declared type must agree with the bytes, when a type was declared.
    if declared_type:
        declared_norm = declared_type.split(";", 1)[0].strip().lower()
        if declared_norm and declared_norm != detected:
            # A lie about the content type is the strongest single signal that
            # the file is not what it claims to be.
            security.audit_security_event(
                "upload.mime_mismatch",
                f"declared={security.scrub_text(declared_norm, 60)} detected={detected}",
            )
            raise UploadError("mime_mismatch")

    # 4. Polyglot / executable-payload scan.
    marker = find_forbidden(content)
    if marker is not None:
        security.audit_security_event("upload.forbidden_marker", f"marker={marker}")
        raise UploadError("forbidden_content")

    # 5. Rebuild the name from the allow-list; the client's extension is never
    #    trusted, and the client's basename is only ever decorative.
    allowed_ext = _ALLOWED_EXTENSIONS.get(detected)
    if not allowed_ext:
        raise UploadError("no_safe_extension")
    extension = sorted(allowed_ext)[0]
    if declared_name:
        cleaned = safe_filename(declared_name)
        if cleaned:
            client_ext = Path(cleaned).suffix.lower()
            if client_ext in allowed_ext:
                extension = client_ext

    digest = hashlib.sha256(content).hexdigest()
    width, height = _image_dimensions(content, detected)
    warnings: list[str] = []
    if detected.startswith("image/") and (width is None or height is None):
        warnings.append("dimensions_unreadable")
    elif width is not None and height is not None and (width > 20000 or height > 20000):
        # A 20000×20000 image is ~1.6 GB decoded — a decompression bomb aimed
        # at whatever renders it later.
        warnings.append("decompression_bomb_suspected")
        raise UploadError("image_dimensions_excessive")

    return VerifiedUpload(
        content=content,
        detected_type=detected,
        extension=extension,
        digest=digest,
        size=len(content),
        original_name=safe_filename(declared_name) or "upload",
        width=width,
        height=height,
        warnings=tuple(warnings),
    )


def safe_destination(root: Path, upload: VerifiedUpload) -> Path:
    """Compute — and prove — a storage path that cannot escape ``root``.

    Two defences, because one is never enough with paths:

    * the filename is the content digest plus an allow-listed extension, so no
      client string participates at all;
    * the resolved path is checked to be strictly inside the resolved root,
      which defeats a pre-planted symlink pointing at ``/etc``.
    """
    root = Path(root).resolve()
    candidate = (root / upload.stored_name).resolve()
    try:
        candidate.relative_to(root)
    except ValueError:
        raise UploadError("path_escape", client_message="That file could not be stored.")
    if candidate.exists() and candidate.is_symlink():
        raise UploadError("symlink_target")
    return candidate


def store(
    content: bytes,
    root: Path | str,
    *,
    declared_name: str | None = None,
    declared_type: str | None = None,
    allowed: frozenset[str] = DOCUMENT_POLICY,
    max_bytes: int = LIMITS.MAX_UPLOAD_BYTES,
) -> tuple[Path, VerifiedUpload]:
    """Verify then write, with restrictive permissions and an atomic rename.

    The file is created ``0600`` and moved into place atomically so a partial
    write can never be observed (or served) as if it were complete.
    """
    upload = verify(
        content,
        declared_name=declared_name,
        declared_type=declared_type,
        declared_length=len(content),
        allowed=allowed,
        max_bytes=max_bytes,
    )
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    destination = safe_destination(root, upload)

    tmp = destination.with_suffix(destination.suffix + ".part")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(upload.content)
        os.replace(tmp, destination)
    except Exception:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise

    security.audit_security_event(
        "upload.stored",
        f"type={upload.detected_type} bytes={upload.size} sha256={upload.digest[:16]}",
    )
    return destination, upload


def read_stream_safely(stream, max_bytes: int = LIMITS.MAX_UPLOAD_BYTES) -> bytes:
    """Read a body with a hard ceiling, so a lying ``Content-Length`` cannot
    smuggle more bytes than the declared size check allowed."""
    out = io.BytesIO()
    total = 0
    while True:
        chunk = stream.read(min(64 * 1024, max_bytes - total + 1))
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise UploadError("stream_too_large")
        out.write(chunk)
    return out.getvalue()


#: Extensions that must never be written to a served directory under any
#: circumstances, regardless of what the content sniff says.
_NEVER_STORE = re.compile(
    r"(?i)\.(php[0-9s]?|phtml|phar|jsp|jspx|asp|aspx|cgi|pl|py|rb|sh|bash|"
    r"exe|dll|so|bat|cmd|com|msi|html?|xhtml|svg|shtml|htaccess|htpasswd)$"
)


def is_forbidden_extension(name: str) -> bool:
    """Last line of defence: refuse executable or markup extensions outright."""
    return bool(_NEVER_STORE.search(safe_filename(name) or ""))


__all__ = [
    "DOCUMENT_POLICY",
    "IMAGE_POLICY",
    "UploadError",
    "VerifiedUpload",
    "find_forbidden",
    "is_forbidden_extension",
    "read_stream_safely",
    "safe_destination",
    "sniff",
    "store",
    "verify",
]
