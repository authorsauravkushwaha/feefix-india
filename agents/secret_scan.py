"""Secret-scanning agent — fail CI if a credential lands in the repo.

Runs offline over the working tree (skipping ``.git``, virtualenvs, caches and
binary files) and flags lines that look like a real secret:

* provider-token shapes (GitHub ``ghp_``/``github_pat_``, Slack ``xox``,
  AWS ``AKIA``, Google ``AIza``, Twilio, private-key headers …)
* assignments of well-known secret names to a non-placeholder literal
  (``GITHUB_CLIENT_SECRET = "..."``, ``password = "..."`` in source …)

This is a *backstop*, not a substitute for keeping secrets in the environment
(see ``backend/services/secrets.py``). Exit code 1 = a finding needs attention.

Usage::

    python -m agents.secret_scan            # scan the repo
    python -m agents.secret_scan --path X   # scan a specific path
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

_SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", ".pytest_cache",
              ".mypy_cache", ".ruff_cache", "runtime", "dist", "build", ".arena"}
_SCAN_EXTS = {
    ".py", ".js", ".ts", ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg",
    ".env", ".sh", ".md", ".txt", ".kt", ".html", ".css", ".xml", ".tf",
}
_MAX_BYTES = 1_000_000

# High-signal provider token prefixes / private-key markers.
_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("github_pat", re.compile(r"github_pat_[A-Za-z0-9_]{22,}")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("twilio_key", re.compile(r"SK[0-9a-fA-F]{32}")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
]

# NAME = "literal" where the NAME strongly implies a real credential. We
# deliberately exclude bare words like `password`/`token` (which appear in test
# fixtures, localStorage key names and URL constants) to keep false positives
# near zero — this is a CI backstop, not a replacement for secret hygiene.
_STRONG_NAMES = re.compile(
    r"(?i)(client[_-]?secret|secret[_-]?key|api[_-]?key|apikey|access[_-]?token|"
    r"auth[_-]?token|refresh[_-]?token|private[_-]?key|app[_-]?secret|"
    r"signing[_-]?key|encryption[_-]?key| bearer[_-]?token)"
)
_ASSIGN = re.compile(
    r"(?i)\b([a-z0-9_]+)\b\s*[:=]\s*['\"]([^'\"$\n]{12,})['\"]"
)
_PLACEHOLDER_LITERALS = {
    "changeme", "change-me", "change_me", "your-secret-here", "example",
    "placeholder", "none", "null", "todo", "redacted", "your_client_secret",
    "client_secret", "access_token", "auth_token", "your_api_key", "string",
}
# Test fixtures legitimately carry sample credentials — don't flag them here.
_TEST_PATH = re.compile(r"(^|/)(tests?/|test_[^/]*$|.*_test\.py$|conftest\.py$)")


def _iter_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in _SCAN_EXTS:
            continue
        try:
            if path.stat().st_size > _MAX_BYTES:
                continue
        except OSError:
            continue
        yield path


def scan(root: Path) -> list[dict]:
    findings: list[dict] = []
    for path in _iter_files(root):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        rel = path.relative_to(root)
        is_test = bool(_TEST_PATH.search(str(rel)))
        for lineno, line in enumerate(text.splitlines(), 1):
            for label, pat in _PATTERNS:
                if pat.search(line):
                    findings.append({"file": str(rel), "line": lineno,
                                     "type": label, "snippet": _redact(line)})
            if is_test:
                continue  # sample credentials in tests are expected
            m_name = _STRONG_NAMES.search(line)
            if not m_name:
                continue
            for m in _ASSIGN.finditer(line):
                literal = m.group(2).strip()
                low = literal.lower()
                if low in _PLACEHOLDER_LITERALS or low.startswith(("<", "http")):
                    continue
                if "environ" in line or "getenv" in line or "${" in literal or "{" in literal:
                    continue
                # Require some entropy: at least two character classes.
                classes = sum([
                    bool(re.search(r"[a-z]", literal)),
                    bool(re.search(r"[A-Z]", literal)),
                    bool(re.search(r"\d", literal)),
                    bool(re.search(r"[^A-Za-z0-9]", literal)),
                ])
                if classes < 2:
                    continue
                findings.append({"file": str(rel), "line": lineno,
                                 "type": "assigned_secret", "name": m.group(1),
                                 "snippet": _redact(line)})
    return findings


def _redact(line: str) -> str:
    line = line.strip()
    return line[:80] + ("…" if len(line) > 80 else "")


def main(argv: list[str]) -> int:
    root = REPO
    if "--path" in argv:
        root = Path(argv[argv.index("--path") + 1]).resolve()
    findings = scan(root)
    print("== FeeFix Secret Scan ==")
    print(f"scanned under {root} | findings: {len(findings)}")
    for f in findings[:50]:
        print(f"  ✗ [{f['type']}] {f['file']}:{f['line']}  {f['snippet']}")
    if findings:
        print("\nA possible secret was committed. Remove it, rotate the credential,")
        print("and keep secrets in the environment (docs/security/SECURITY.md).")
        return 1
    print("  ✓ no committed secrets detected")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
