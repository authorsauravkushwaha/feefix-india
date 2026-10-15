#!/usr/bin/env python3
"""Secret scanner — the control that stops a credential reaching Git history.

WHY THIS EXISTS
===============
A secret committed to a repository is not removed by deleting it in the next
commit. It lives in the object database forever, is cloned by every fork and CI
runner, and is indexed by services that scan public repositories within minutes
of a push. For a public repo, a leaked key is compromised the moment it lands,
whether or not anyone notices.

FeeFix has real key material to protect: an OTP pepper (whose whole job is to
make a stolen database useless), SMTP relay credentials, a Twilio auth token and
a GitHub OAuth client secret. Any one of them in Git means either sign-in codes
can be forged or the platform can be made to spend money and send messages as us.

This scanner runs in CI on every push and pull request, and locally via
``scripts/dev.sh``. It checks three things:

1. **Content patterns** in tracked files — the shapes real credentials take.
2. **Tracked-file policy** — files that must never be in the index at all
   (``.env``, ``runtime/.otp_pepper``, private keys), regardless of content.
3. **Ignore coverage** — that ``.gitignore`` actually covers the secret-bearing
   paths. A secret file that is merely *untracked* is one ``git add -A`` away
   from being committed; the old ``.gitignore`` listed ``runtime/*.db`` and
   friends but missed ``runtime/.otp_pepper``, because a dotfile with no
   extension matches neither pattern.

False positives are handled with an explicit, reviewed allow-list keyed on
``path:line`` — never by weakening a pattern. A scanner people learn to ignore
is worse than no scanner.

Usage::

    python scripts/secret_scan.py              # working tree
    python scripts/secret_scan.py --history    # + every reachable commit
    python scripts/secret_scan.py --json       # machine-readable output

Exit code 0 = clean, 1 = findings, 2 = the scanner itself failed.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

# ---------------------------------------------------------------------------
# Detection patterns. Each one is anchored enough to avoid matching prose or
# ordinary code, and loose enough to catch the rotated form of a real credential.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Pattern:
    name: str
    regex: re.Pattern
    severity: str = "high"
    note: str = ""


PATTERNS: tuple[Pattern, ...] = (
    Pattern("private-key-block",
            re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY")),
    Pattern("aws-access-key-id",
            re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")),
    Pattern("github-token",
            re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    Pattern("github-fine-grained",
            re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b")),
    Pattern("slack-token",
            re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,255}\b")),
    Pattern("twilio-account-sid-with-secret",
            re.compile(r"\bAC[a-f0-9]{32}\b\s*[:=]\s*[A-Za-z0-9_\-]{20,}")),
    Pattern("stripe-secret-key",
            re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,255}\b")),
    Pattern("google-api-key",
            re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    Pattern("jwt",
            re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")),
    Pattern("postgres-url-with-password",
            re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s:/@]+:[^\s@]{4,}@"),
            note="a connection string with an embedded password"),
    Pattern("assigned-secret-literal",
            re.compile(
                r"""(?ix)
                \b(?:api[_-]?key|apikey|secret[_-]?key|client[_-]?secret|access[_-]?token
                    |auth[_-]?token|private[_-]?key|signing[_-]?key|encryption[_-]?key
                    |otp[_-]?pepper|smtp[_-]?pass(?:word)?|db[_-]?password)\b
                \s*(?:[:=]|"\s*:)\s*
                ["'](?P<value>[A-Za-z0-9/+_\-\.=]{16,})["']
                """),
            note="a secret-shaped identifier assigned a long literal"),
    Pattern("bearer-token-literal",
            re.compile(r"""["']Bearer\s+[A-Za-z0-9._\-]{24,}["']""")),
    Pattern("basic-auth-literal",
            re.compile(r"""["']Basic\s+[A-Za-z0-9+/=]{20,}["']"""),
            severity="medium",
            note="may be a legitimate example; confirm it decodes to nothing real"),
)

# ---------------------------------------------------------------------------
# Allow-list. Keyed on "<relative path>:<line>" so a change in the file forces
# the entry to be re-reviewed rather than silently continuing to suppress.
# Each entry REQUIRES a reason — an unexplained suppression is how a scanner
# stops working.
# ---------------------------------------------------------------------------
ALLOWLIST: dict[str, str] = {
    # The scanner's own patterns are, necessarily, credential-shaped strings.
    "scripts/secret_scan.py:assigned-secret-literal":
        "the detection pattern itself",
    # Documentation and the environment template deliberately NAME the variables
    # without values; .env.example is the safe reference copy.
    ".env.example:any": "template with no values assigned",
    # Fake credentials whose only purpose is to prove this scanner detects them.
    # Scoped to the fixture module rather than to tests/test_security.py, so a
    # real secret pasted into a test still fails the build. Every value in that
    # file is a published documentation example or invented; see its docstring.
    "tests/fixtures/secret_scan_samples.py:any":
        "deliberately fake credential fixtures for the scanner's own self-test",
}

#: Files never scanned for content (binary or generated).
# Binary or generated. NOTE: .pem and .key are deliberately NOT here. They are
# text formats and the single most common home for a private key, so skipping
# them by suffix would blind the scanner to exactly what it exists to find.
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf",
                 ".woff", ".woff2", ".ttf", ".eot", ".db", ".sqlite", ".pyc",
                 ".zip", ".gz", ".lock"}
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache",
             "dist", "build", "out", "runtime", ".mypy_cache", ".ruff_cache"}
MAX_FILE_BYTES = 2 * 1024 * 1024

#: Ceiling on distinct historical blobs scanned by ``--history``. De-duplication
#: on blob SHA keeps the real number far below this on a normal repository; the
#: cap exists so a squashed-import or vendored-dependency commit cannot turn a
#: CI gate into a multi-minute job. Blobs beyond it are skipped, not failed.
MAX_HISTORY_BLOBS = 4000

#: Files that must never appear in the Git index, whatever they contain.
FORBIDDEN_TRACKED = (
    ".env", ".otp_pepper", "id_rsa", "id_ed25519", "credentials.json",
    "serviceAccountKey.json", ".netrc", ".pgpass",
)
# Conventional suffixes for a *template* env file: it is committed on purpose,
# documents the variables, and carries no values. Blocking these would push the
# template out of the repository, which is worse than allowing it — without a
# reviewed example, people copy a real .env around instead.
_ENV_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".md")

FORBIDDEN_TRACKED_PATTERNS = (
    re.compile(r"(^|/)\.env(\..+)?$"),
    re.compile(r"(^|/)runtime/.+"),
    re.compile(r"\.pem$|\.key$|\.p12$|\.pfx$|\.keystore$|\.jks$"),
    re.compile(r"(^|/)secrets/.+"),
)


def _is_env_template(rel: str) -> bool:
    """True for ``.env.example`` and friends — a committed template, not a secret."""
    base = os.path.basename(rel)
    return base.startswith(".env") and base.lower().endswith(_ENV_TEMPLATE_SUFFIXES)

#: Paths .gitignore must cover. Verified by asking git directly, which is the
#: only authoritative answer — reading .gitignore text is not, because negations
#: and directory rules interact in ways that are easy to get wrong by eye.
MUST_BE_IGNORED = (
    ".env",
    ".env.production",
    "runtime/.otp_pepper",
    "runtime/feefix.db",
    "runtime/whatsapp_outbox.jsonl",
    "secrets/key.pem",
)


@dataclass
class Finding:
    path: str
    line: int
    name: str
    severity: str
    preview: str
    note: str = ""

    def as_dict(self) -> dict:
        return {
            "path": self.path, "line": self.line, "name": self.name,
            "severity": self.severity, "preview": self.preview, "note": self.note,
        }


def is_forbidden_path(rel: str) -> bool:
    """True if ``rel`` must never appear in the Git index, whatever it contains.

    SINGLE SOURCE OF TRUTH. Used by both :func:`scan_tracked_policy` (working
    tree) and :func:`scan_history` (every reachable commit). It used to be
    duplicated inline in the history scan, and the two copies diverged: the tree
    scan exempted ``runtime/.gitkeep`` and the history scan did not, so
    ``--history`` raised a CRITICAL finding demanding a history rewrite and
    credential rotation for a zero-byte placeholder file.

    That failure mode is worse than an ordinary false positive. A CRITICAL
    finding that is wrong on every single run gets the gate disabled — and then
    the real history findings stop being caught too: a key committed in 2024 and
    deleted in 2025 is still cloneable today, and ``--history`` is the only
    check that can see it.

    Exemptions:
      * ``runtime/.gitkeep`` — the deliberate placeholder that keeps the
        directory in the tree while everything inside it is ignored.
      * ``.env.example`` and friends — a committed template with no values,
        which is strictly better for a new contributor than no template.
      * anything carrying an allow-list entry with a documented reason.
    """
    if rel == "runtime/.gitkeep":
        return False
    if _is_env_template(rel):
        return False
    if os.path.basename(rel) in FORBIDDEN_TRACKED:
        return True
    if any(p.search(rel) for p in FORBIDDEN_TRACKED_PATTERNS):
        return not _is_allowed(rel, 0, "forbidden-tracked-file")
    return False


def _is_allowed(rel: str, line_no: int, name: str) -> bool:
    for key in (f"{rel}:{line_no}", f"{rel}:any", f"{rel}:{name}", name):
        if key in ALLOWLIST:
            return True
    return False


def _preview(line: str, width: int = 72) -> str:
    """A redacted snippet: enough to locate the finding, not enough to use it.

    Printing the secret to CI logs would turn the scanner itself into a leak —
    build logs are readable by a much wider audience than the repository.
    """
    text = line.strip()
    if len(text) > width:
        text = text[:width] + "…"
    # Collapse any long token-looking run to its first and last 3 characters.
    return re.sub(r"[A-Za-z0-9/+_\-\.=]{12,}",
                  lambda m: f"{m.group(0)[:3]}…{m.group(0)[-3:]}", text)


def _tracked_files() -> list[str]:
    """Files git would commit. This is the real scope — scanning the working
    tree instead would miss a staged secret and flag untracked local noise."""
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z"], cwd=REPO, capture_output=True, text=True, check=True
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        print(f"secret_scan: could not list tracked files ({exc})", file=sys.stderr)
        raise SystemExit(2)
    return [p for p in out.split("\0") if p]


def scan_content(files: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for rel in files:
        path = REPO / rel
        if path.suffix.lower() in SKIP_SUFFIXES:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        for line_no, line in enumerate(text.splitlines(), start=1):
            # A cheap pre-filter: credentials contain a long unbroken token run.
            # The threshold must be LOOSER than every pattern above, or it
            # silently skips matches — 16 was too tight and missed a Postgres
            # URL (longest run: the 15-char password) and a PEM header
            # ("-----BEGIN", 10 characters). 8 keeps the speedup and is below
            # the shortest thing any pattern can match.
            if not re.search(r"[A-Za-z0-9/+_\-\.=]{8,}", line):
                continue
            for pattern in PATTERNS:
                if not pattern.regex.search(line):
                    continue
                if _is_allowed(rel, line_no, pattern.name):
                    continue
                findings.append(Finding(
                    path=rel, line=line_no, name=pattern.name,
                    severity=pattern.severity, preview=_preview(line),
                    note=pattern.note,
                ))
    return findings


def scan_tracked_policy(files: list[str]) -> list[Finding]:
    """Files that must not be in the index at all.

    Exemptions go through the same ``ALLOWLIST`` as content findings, so every
    suppression is a single documented decision in one place rather than an
    ``if rel == …: continue`` that nobody remembers to review.
    """
    findings = []
    for rel in files:
        if not is_forbidden_path(rel):
            continue
        findings.append(Finding(
            path=rel, line=0, name="forbidden-tracked-file", severity="critical",
            preview=f"{rel} is tracked but must never be committed",
            note="remove it with `git rm --cached` and fix .gitignore",
        ))
    return findings


def scan_ignore_coverage() -> list[Finding]:
    """Ask git whether each secret-bearing path would actually be ignored."""
    findings = []
    for candidate in MUST_BE_IGNORED:
        try:
            proc = subprocess.run(
                ["git", "check-ignore", "-q", candidate], cwd=REPO,
                capture_output=True, text=True,
            )
        except FileNotFoundError:
            return findings
        # check-ignore exits 0 when the path IS ignored, 1 when it is not.
        if proc.returncode != 0:
            findings.append(Finding(
                path=".gitignore", line=0, name="ignore-gap", severity="high",
                preview=f"{candidate} is NOT ignored by .gitignore",
                note="one `git add -A` away from being committed",
            ))
    return findings


def _head_blobs() -> dict[str, str]:
    """path -> blob SHA for the current HEAD tree."""
    try:
        out = subprocess.run(
            ["git", "ls-tree", "-r", "HEAD"],
            cwd=REPO, capture_output=True, text=True, check=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        return {}
    blobs = {}
    for line in out.splitlines():
        # "<mode> <type> <sha>\t<path>"
        meta, _, path = line.partition("\t")
        parts = meta.split()
        if len(parts) == 3 and path:
            blobs[path] = parts[2]
    return blobs


def _blob_text(sha: str) -> str | None:
    """Read one blob by SHA. ``None`` if it is missing, binary or oversized."""
    try:
        raw = subprocess.run(
            ["git", "cat-file", "blob", sha],
            cwd=REPO, capture_output=True, check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    if raw.returncode != 0 or len(raw.stdout) > MAX_FILE_BYTES:
        return None
    if b"\x00" in raw.stdout[:8192]:
        return None                      # binary
    return raw.stdout.decode("utf-8", errors="ignore")


def scan_history(limit: int = 200) -> list[Finding]:
    """Scan reachable commits, not just HEAD.

    Two checks, because a secret survives in history two different ways:

    1. **A forbidden file that was committed and later deleted.** ``.env``
       removed in a follow-up commit is invisible to the working-tree scan and
       still cloneable today.
    2. **A secret inside an ordinary file that was later edited out.** An AWS key
       pasted into ``backend/config.py``, committed, then removed. The file is
       still tracked and still clean at HEAD — only its history is dirty.

    Check 2 is what makes ``--history`` worth its runtime, and it was missing
    entirely: the previous version only compared *filenames*, so it could never
    see a credential that lived inside a normal source file.

    Cost is bounded by de-duplicating on blob SHA. A repository's history
    repeats the same blobs across hundreds of commits, so scanning unique blobs
    is a fraction of scanning unique (commit, file) pairs — and blobs identical
    to HEAD are skipped outright, because the working-tree scan has already
    covered them.
    """
    findings: list[Finding] = []
    try:
        revs = subprocess.run(
            ["git", "rev-list", "--max-count", str(limit), "HEAD"],
            cwd=REPO, capture_output=True, text=True, check=True,
        ).stdout.split()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return findings

    head_blobs = _head_blobs()

    seen_path: set[str] = set()
    # blob SHA -> the first (rev, path) we saw it in, for the finding message.
    pending: dict[str, tuple[str, str]] = {}

    for rev in revs:
        try:
            listing = subprocess.run(
                ["git", "ls-tree", "-r", rev],
                cwd=REPO, capture_output=True, text=True, check=True,
            ).stdout.splitlines()
        except subprocess.CalledProcessError:
            continue

        for line in listing:
            meta, _, rel = line.partition("\t")
            parts = meta.split()
            if len(parts) != 3 or not rel:
                continue
            _, obj_type, sha = parts
            if obj_type != "blob":
                continue

            # 1. forbidden path, exempted through the SAME predicate as the tree
            if is_forbidden_path(rel):
                if rel in seen_path:
                    continue
                seen_path.add(rel)
                findings.append(Finding(
                    path=f"{rel} (in {rev[:9]})", line=0,
                    name="forbidden-tracked-file", severity="critical",
                    preview=f"{rel} appears in commit {rev[:9]}",
                    note="history rewrite + credential rotation required",
                ))

            # 2. content that differs from HEAD — HEAD's copy is already scanned
            if head_blobs.get(rel) == sha:
                continue
            if Path(rel).suffix.lower() in SKIP_SUFFIXES:
                continue
            if any(part in SKIP_DIRS for part in Path(rel).parts):
                continue
            pending.setdefault(sha, (rev, rel))

    # Scan each distinct historical blob exactly once.
    for sha, (rev, rel) in list(pending.items())[:MAX_HISTORY_BLOBS]:
        text = _blob_text(sha)
        if not text:
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            # Same cheap pre-filter as the working-tree scan, and for the same
            # reason: it must stay LOOSER than every pattern or it silently
            # skips real matches.
            if not re.search(r"[A-Za-z0-9/+_\-\.=]{8,}", line):
                continue
            for pattern in PATTERNS:
                if not pattern.regex.search(line):
                    continue
                if _is_allowed(rel, line_no, pattern.name):
                    continue
                findings.append(Finding(
                    path=f"{rel} (in {rev[:9]})", line=line_no,
                    name=pattern.name, severity=pattern.severity,
                    preview=_preview(line),
                    note="present in Git history — the file may be clean at HEAD",
                ))
                break                      # one finding per line is enough
    return findings


def report(findings: list[Finding], as_json: bool) -> int:
    if as_json:
        print(json.dumps({"findings": [f.as_dict() for f in findings]}, indent=2))
        return 1 if findings else 0

    print("== FeeFix secret scanner ==")
    if not findings:
        print("  ✓ no secrets detected in tracked content")
        return 0

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for f in sorted(findings, key=lambda x: (order.get(x.severity, 9), x.path, x.line)):
        loc = f"{f.path}:{f.line}" if f.line else f.path
        print(f"  ✗ [{f.severity.upper()}] {f.name}\n      {loc}\n      {f.preview}")
        if f.note:
            print(f"      → {f.note}")
    print(f"\n  {len(findings)} finding(s). Rotate any credential that was committed,")
    print("  then remove it — deleting a file does not remove it from Git history.")
    return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan for committed secrets.")
    parser.add_argument("--history", action="store_true",
                        help="also scan reachable commits (slower)")
    parser.add_argument("--history-limit", type=int, default=200)
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)

    try:
        files = _tracked_files()
        findings = scan_content(files)
        findings += scan_tracked_policy(files)
        findings += scan_ignore_coverage()
        if args.history:
            findings += scan_history(args.history_limit)
    except SystemExit:
        raise
    except Exception as exc:  # the scanner must never fail silently open
        print(f"secret_scan: internal error ({type(exc).__name__}: {exc})", file=sys.stderr)
        return 2

    return report(findings, args.json)


if __name__ == "__main__":
    sys.exit(main())
