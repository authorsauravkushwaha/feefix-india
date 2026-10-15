"""Secret-scanning agent — fail CI if a credential lands in the repo.

Runs offline over the working tree (skipping ``.git``, virtualenvs, caches and
binary files) and flags lines that look like a real secret:

* **provider token shapes** (GitHub ``ghp_``/``github_pat_``, Slack, AWS, Google,
  Twilio, Stripe, SendGrid-style keys, private-key headers, connection strings
  with inline passwords …)
* **assignments of credential-named variables** to a non-placeholder literal
  (``GITHUB_CLIENT_SECRET = "…"``, ``api_key: …``), including
* **split / concatenated literals** (``KEY = "abc" "def"`` or ``"abc" + "def"``),
* **base64/url-safe-encoded payloads** that decode to a known provider token,
* **high-entropy literals** under a credential-ish name (catches novel formats
  that no fixed pattern knows about).

This is a *backstop*, not a substitute for keeping secrets in the environment
(see ``backend/services/secrets.py``). Exit code 1 = a finding needs attention.

Usage::

    python -m agents.secret_scan                 # scan the repo
    python -m agents.secret_scan --path X        # scan a specific path
    python -m agents.secret_scan --staged        # scan only staged files (pre-commit)
    python -m agents.secret_scan --json out.json # machine-readable report

A finding can be waived in-line (``# secret-scan: allow <reason>``) or by path
glob in ``.secretscanignore``. Waivers are deliberate and reviewable, which is
the point: a scanner you cannot silence honestly gets silenced dishonestly
(the check still runs everywhere — see ``.pre-commit-config.yaml`` and the CI
``secret-scan`` job, plus the third-party ``gitleaks`` job that shares no code
with this file).
"""

from __future__ import annotations

import base64
import binascii
import fnmatch
import json
import math
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

_SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", ".pytest_cache",
              ".mypy_cache", ".ruff_cache", "runtime", "dist", "build", ".arena",
              ".hypothesis", "uploads"}
_MAX_BYTES = 1_000_000
_IGNORE_FILE = ".secretscanignore"
_INLINE_ALLOW = re.compile(r"secret-scan:\s*allow|nosec:\s*secret-scan|noqa:\s*secret-scan", re.I)

# High-signal provider token prefixes / private-key markers.
_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("github_pat", re.compile(r"github_pat_[A-Za-z0-9_]{22,}")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("slack_webhook", re.compile(r"hooks\.slack\.com/services/[A-Za-z0-9_/]{20,}")),
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("twilio_key", re.compile(r"SK[0-9a-fA-F]{32}")),
    ("stripe_key", re.compile(r"[sr]k_(live|test)_[A-Za-z0-9]{20,}")),
    ("sendgrid_key", re.compile(r"SG\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("dsn_with_password", re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|amqps?)://[^\s:@/]+:[^\s@/]{6,}@")),
    ("bearer_literal", re.compile(r"(?i)authorization['\"]?\s*[:=]\s*['\"]?bearer\s+[A-Za-z0-9._\-]{20,}")),
]

# NAME = "literal" where the NAME strongly implies a real credential. Bare
# words like `password`/`token` are excluded on purpose (they appear in test
# fixtures, localStorage key names and URL constants) to keep false positives
# near zero — this is a CI backstop, not a replacement for secret hygiene.
_STRONG_NAMES = re.compile(
    r"(?i)(client[_-]?secret|secret[_-]?key|api[_-]?key|apikey|access[_-]?token|"
    r"auth[_-]?token|refresh[_-]?token|private[_-]?key|app[_-]?secret|"
    r"signing[_-]?key|encryption[_-]?key|bearer[_-]?token|consumer[_-]?secret|"
    r"client[_-]?password|db[_-]?password|smtp[_-]?pass|twilio[_-]?token|otp[_-]?pepper)"
)
_ASSIGN = re.compile(
    r"(?i)\b([a-z0-9_]+)\b\s*[:=]\s*['\"]([^'\"$\\\n]{12,})['\"]"
)
# Unquoted `KEY: value` / `KEY=value` assignments (a committed .env or CI yaml).
# Restricted to configuration-shaped files and to bare token values, because in
# source code ``token = _bearer_token(request)`` is an expression, not a literal.
_YAML_ASSIGN = re.compile(r"(?i)^\s*([a-z0-9_]+)\s*[:=]\s*([A-Za-z0-9+/=_\-]{16,})\s*$")
_CONFIG_SUFFIXES = (".yml", ".yaml", ".env", ".ini", ".cfg", ".toml", ".conf",
                    ".properties", ".envrc", ".service", ".json")


def _is_config_like(rel_str: str) -> bool:
    name = rel_str.rsplit("/", 1)[-1].lower()
    return name.startswith(".env") or name.endswith(_CONFIG_SUFFIXES)
_PLACEHOLDER_LITERALS = {
    "changeme", "change-me", "change_me", "your-secret-here", "example",
    "placeholder", "none", "null", "todo", "redacted", "your_client_secret",
    "client_secret", "access_token", "auth_token", "your_api_key", "string",
    "unset", "test", "dummy", "sample", "secret", "password",
}
# Test fixtures legitimately carry sample credentials — don't flag them here.
_TEST_PATH = re.compile(r"(^|/)(tests?/|test_[^/]*$|.*_test\.py$|conftest\.py$)")
# Values that are references, not secrets.
_SAFE_VALUE_PREFIXES = ("<", "http://", "https://", "${", "$(", "{{", "%(", "{")
_SAFE_NAME_CONTEXT = re.compile(
    r"(?i)(sha256|sha1|md5|digest|checksum|etag|hash|commit|revision|version|"
    r"fingerprint|uuid|nonce_id|build|image|assert|expect|fixture)"
)
_B64_CANDIDATE = re.compile(r"[A-Za-z0-9+/_=\-]{20,200}")

#: Entropy thresholds. ``_ENTROPY_FLOOR`` rejects low-entropy filler outright;
#: ``_NORMALIZED_ENTROPY_FLOOR`` then asks "is this random *for its alphabet*",
#: which is what makes hex/base64 secrets detectable without flagging prose.
_ENTROPY_FLOOR = 3.0
_NORMALIZED_ENTROPY_FLOOR = 0.75
_ENTROPY_THRESHOLD = 4.0
_DECODED_ENTROPY_THRESHOLD = 3.6
#: Split literals are only reported when clearly random (prose entropies out).
_SPLIT_ENTROPY_FLOOR = 4.6
#: Unquoted config values must be near-uniform for their alphabet.
_UNQUOTED_ENTROPY_FLOOR = 0.85


def _load_ignore_globs(root: Path) -> list[str]:
    path = root / _IGNORE_FILE
    if not path.exists():
        return []
    globs: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        entry = line.strip()
        if entry and not entry.startswith("#"):
            globs.append(entry)
    return globs


def _ignored(rel: str, globs: list[str]) -> bool:
    return any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(rel, f"*/{g}") for g in globs)


def _iter_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        try:
            if path.stat().st_size > _MAX_BYTES or path.stat().st_size == 0:
                continue
            blob = path.read_bytes()
        except OSError:
            continue
        # Content sniffing rather than an extension allowlist: a secret in an
        # unexpected file type is exactly what a bypass looks like.
        if b"\x00" in blob[:8192]:
            continue
        try:
            yield path, blob.decode("utf-8")
        except UnicodeDecodeError:
            continue


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def _char_classes(value: str) -> int:
    return sum(
        [
            bool(re.search(r"[a-z]", value)),
            bool(re.search(r"[A-Z]", value)),
            bool(re.search(r"\d", value)),
            bool(re.search(r"[^A-Za-z0-9]", value)),
        ]
    )


def _normalized_entropy(value: str) -> float:
    """Entropy relative to the alphabet actually used (1.0 = uniform random).

    Raw entropy alone rejects real secrets: a 40-character *hex* GitHub client
    secret has only ~3.9 bits/char because its alphabet is 16 symbols. Dividing
    by ``log2(alphabet)`` measures "randomness for this alphabet" and keeps hex,
    base64 and base32 tokens detectable while still rejecting repeated filler.
    """
    if not value:
        return 0.0
    alphabet = len(set(value))
    if alphabet <= 1:
        return 0.0
    return _entropy(value) / math.log2(alphabet)


def _looks_like_secret_value(value: str) -> bool:
    """Entropy/shape heuristic for a literal that is not a known-safe reference."""
    if len(value) < 16 or value.lower() in _PLACEHOLDER_LITERALS:
        return False
    if value.startswith(_SAFE_VALUE_PREFIXES):
        return False
    if _char_classes(value) < 2:
        return False
    if _entropy(value) < _ENTROPY_FLOOR:
        return False
    return _normalized_entropy(value) >= _NORMALIZED_ENTROPY_FLOOR


def _decode_candidates(value: str) -> list[str]:
    """base64/url-safe decodings of a literal — catches encoded secrets."""
    out: list[str] = []
    for attempt in (value, value.replace("-", "+").replace("_", "/")):
        padded = attempt + "=" * (-len(attempt) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if text and text != value and text.isprintable():
            out.append(text)
    return out


def _join_adjacent_literals(line: str) -> str:
    """``"abc" "def"`` / ``"abc" + "def"`` → ``abcdef`` (split-literal bypass).

    Only true concatenations count: literals separated by nothing but whitespace
    and an optional ``+``. That distinction keeps ordinary sentences (a tuple of
    prose strings, an error message split across lines) out of the results —
    English prose also has ~4 bits/char of entropy, so a loose join would flag
    every docstring in the repo.
    """
    parts = re.findall(r"""["']([^"'\n]{3,})["']\s*(?:\+\s*)?["']([^"'\n]{3,})["']""", line)
    if not parts:
        return ""
    return "".join(parts[0])


#: Placeholder passwords that appear in *documentation* DSNs
#: (``postgres://user:password@host``, ``redis://default:<your-password>@host``).
#: Flagging these trains people to add waivers, which is how a scanner dies.
_DSN_PLACEHOLDER_HINT = re.compile(
    r"(?i)^(?:<.*>|\{.*\}|\*{3,}|x{3,}|password|passwd|pwd|pass|secret|token|example|"
    r"placeholder|changeme|change[_-]me|your[_-]?password|redacted|none|unset|"
    r"\.\.\.)$"
)
_DSN_PASSWORD = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s:@/]+:([^\s@/]+)@")


def _dsn_password_is_placeholder(text: str) -> bool:
    """True when every DSN on the line carries a documented placeholder password."""
    found = _DSN_PASSWORD.findall(text)
    if not found:
        return False
    return all(_DSN_PLACEHOLDER_HINT.match(pw.strip()) for pw in found)


def _provider_hits(text: str) -> list[str]:
    hits = [label for label, pattern in _PATTERNS if pattern.search(text)]
    if "dsn_with_password" in hits and _dsn_password_is_placeholder(text):
        hits.remove("dsn_with_password")
    return hits


def _redact(line: str) -> str:
    line = line.strip()
    return line[:80] + ("…" if len(line) > 80 else "")


def _scan_text(rel_str: str, text: str) -> list[dict]:
    """All detectors for one file's text (shared by path and staged scans)."""
    findings: list[dict] = []
    is_test = bool(_TEST_PATH.search(rel_str))
    for lineno, line in enumerate(text.splitlines(), 1):
        if _INLINE_ALLOW.search(line):
            continue

        # 1) provider shapes anywhere (even in tests — a real token is real)
        for label in _provider_hits(line):
            findings.append({"file": rel_str, "line": lineno, "type": label,
                             "snippet": _redact(line)})

        # 2) encoded payloads that decode to a provider token or to
        #    something high-entropy under a credential-ish context
        for candidate in _B64_CANDIDATE.findall(line):
            for decoded in _decode_candidates(candidate):
                labels = _provider_hits(decoded)
                if labels:
                    findings.append({"file": rel_str, "line": lineno,
                                     "type": f"encoded_{labels[0]}",
                                     "snippet": _redact(line)})
                elif _STRONG_NAMES.search(line) and _entropy(decoded) >= _DECODED_ENTROPY_THRESHOLD:
                    findings.append({"file": rel_str, "line": lineno,
                                     "type": "encoded_secret", "snippet": _redact(line)})

        if is_test:
            continue  # sample credentials in tests are expected

        strong = bool(_STRONG_NAMES.search(line)) and not _SAFE_NAME_CONTEXT.search(line)
        config_like = _is_config_like(rel_str)

        # 3) credential-named assignments to a non-placeholder literal
        if strong:
            for match in _ASSIGN.finditer(line):
                literal = match.group(2).strip()
                if literal.lower() in _PLACEHOLDER_LITERALS:
                    continue
                if "environ" in line or "getenv" in line or "$" in line or "{" in literal:
                    continue
                if _looks_like_secret_value(literal):
                    findings.append({"file": rel_str, "line": lineno,
                                     "type": "assigned_secret", "name": match.group(1),
                                     "snippet": _redact(line)})
            if config_like:
                yaml_match = _YAML_ASSIGN.match(line)
                if (
                    yaml_match
                    and _looks_like_secret_value(yaml_match.group(2))
                    and _normalized_entropy(yaml_match.group(2)) >= _UNQUOTED_ENTROPY_FLOOR
                ):
                    findings.append({"file": rel_str, "line": lineno,
                                     "type": "assigned_secret", "name": yaml_match.group(1),
                                     "snippet": _redact(line)})

        # 4) split literals reassembled (bypass via concatenation)
        joined = _join_adjacent_literals(line)
        if joined and _provider_hits(joined):
            findings.append({"file": rel_str, "line": lineno,
                             "type": "split_secret", "snippet": _redact(line)})
        elif (
            joined
            and strong
            and len(joined) >= 24
            and _char_classes(joined) >= 3
            and _entropy(joined) >= _SPLIT_ENTROPY_FLOOR
        ):
            findings.append({"file": rel_str, "line": lineno,
                             "type": "split_secret", "snippet": _redact(line)})
    return findings


def _dedupe(findings: list[dict]) -> list[dict]:
    """One finding per (file, line, type) — a token that decodes twice is one."""
    seen: set[tuple] = set()
    out: list[dict] = []
    for finding in findings:
        key = (finding["file"], finding["line"], finding["type"])
        if key in seen:
            continue
        seen.add(key)
        out.append(finding)
    return out


def scan(root: Path) -> list[dict]:
    findings: list[dict] = []
    globs = _load_ignore_globs(root)
    for path, text in _iter_files(root):
        rel_str = str(path.relative_to(root))
        if _ignored(rel_str, globs):
            continue
        findings.extend(_scan_text(rel_str, text))
    return _dedupe(findings)


def _staged_files(root: Path) -> list[Path]:
    """Files staged for commit (pre-commit hook / CI convenience)."""
    try:
        out = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
            cwd=root, capture_output=True, text=True, check=False,
        ).stdout
    except OSError:  # pragma: no cover - git missing
        return []
    return [root / line.strip() for line in out.splitlines() if line.strip()]


def scan_paths(paths: list[Path]) -> list[dict]:
    """Scan an explicit list of files (used by ``--staged``)."""
    findings: list[dict] = []
    globs = _load_ignore_globs(REPO)
    for path in paths:
        if not path.is_file() or any(part in _SKIP_DIRS for part in path.parts):
            continue
        try:
            rel_str = str(path.relative_to(REPO))
        except ValueError:
            rel_str = str(path)
        if not str(path).startswith(str(REPO)) and str(path).startswith(str(Path.cwd())):
            rel_str = str(Path(path).resolve().relative_to(REPO.resolve()))
        if _ignored(rel_str, globs):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        findings.extend(_scan_text(rel_str, text))
    return _dedupe(findings)


def main(argv: list[str]) -> int:
    root = REPO
    if "--path" in argv:
        root = Path(argv[argv.index("--path") + 1]).resolve()

    if "--staged" in argv:
        findings = scan_paths(_staged_files(root))
        scope = "staged files"
    else:
        findings = scan(root)
        scope = str(root)

    if "--json" in argv:
        out = Path(argv[argv.index("--json") + 1])
        out.write_text(json.dumps({"scope": scope, "findings": findings}, indent=2))

    print("== FeeFix Secret Scan ==")
    print(f"scanned {scope} | findings: {len(findings)}")
    for f in findings[:50]:
        where = f"{f['file']}:{f['line']}"
        print(f"  ✗ [{f['type']}] {where}  {f['snippet']}")
    if findings:
        print("\nA possible secret was committed. Remove it, rotate the credential,")
        print("and keep secrets in the environment (docs/security/SECURITY.md).")
        print("If it is a false positive, waive it in-line with")
        print("  # secret-scan: allow <reason>")
        return 1
    print("  ✓ no committed secrets detected")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
