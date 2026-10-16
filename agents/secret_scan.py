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
# A waiver without a reason is how a scanner gets silenced. The reason has to
# be long enough that `# secret-scan: allow x` is not a bypass.
_INLINE_ALLOW = re.compile(r"secret-scan:\s*allow\s+\S.{7,}", re.I)
_OVERBROAD_GLOBS = {"*", "**", "**/*", "/*", "./**", "**/**", "*.*"}

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


def _is_overbroad_glob(entry: str) -> bool:
    """True when a glob would hide a secret in an arbitrary path."""
    if entry in _OVERBROAD_GLOBS:
        return True
    probes = (
        "backend/services/secrets.py",
        "README.md",
        "web/frontend/app.js",
        "docs/security/SECURITY.md",
    )
    return all(fnmatch.fnmatch(probe, entry) or fnmatch.fnmatch(probe, f"*/{entry}") for probe in probes)


def _load_ignore_globs(root: Path) -> tuple[list[str], list[str]]:
    path = root / _IGNORE_FILE
    if not path.exists():
        return [], []
    globs: list[str] = []
    rejected: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        if _is_overbroad_glob(entry):
            rejected.append(entry)
            continue
        globs.append(entry)
    return globs, rejected


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


def _obfuscated_forms(line: str) -> list[str]:
    """Hex, unicode-escape and hex-blob forms of a line — the bypasses a regex misses."""
    forms: list[str] = []
    unescaped = re.sub(
        r"\\x([0-9a-fA-F]{2})",
        lambda match: chr(int(match.group(1), 16)),
        line,
    )
    unescaped = re.sub(
        r"\\u([0-9a-fA-F]{4})",
        lambda match: chr(int(match.group(1), 16)),
        unescaped,
    )
    if unescaped != line:
        forms.append(unescaped)
    for blob in re.findall(r"\b[0-9a-fA-F]{16,}\b", line):
        if len(blob) % 2:
            continue
        try:
            text = bytes.fromhex(blob).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if text and text.isprintable() and text != line:
            forms.append(text)
    return forms


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
    logical = rel_str[8:] if rel_str.startswith("history:") else rel_str
    is_test = bool(_TEST_PATH.search(logical))
    for lineno, line in enumerate(text.splitlines(), 1):
        if _INLINE_ALLOW.search(line):
            continue

        # 1) provider shapes anywhere (even in tests — a real token is real),
        #    including hex / unicode-escaped forms of the same line.
        seen_labels: set[str] = set()
        for variant in (line, *_obfuscated_forms(line)):
            for label in _provider_hits(variant):
                kind = label if variant is line else f"obfuscated_{label}"
                if kind in seen_labels:
                    continue
                seen_labels.add(kind)
                findings.append({"file": rel_str, "line": lineno, "type": kind,
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
        config_like = _is_config_like(logical)

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


def _scan_split_across_lines(rel_str: str, text: str) -> list[dict]:
    """``\"abc\" +\\n \"def\"`` is the split-literal bypass that a per-line scan misses."""
    logical = rel_str[8:] if rel_str.startswith("history:") else rel_str
    if _TEST_PATH.search(logical):
        return []  # fixtures split tokens on purpose; production code is not a fixture
    findings: list[dict] = []
    lines = text.splitlines()
    for index in range(len(lines) - 1):
        window = lines[index] + " " + lines[index + 1]
        if _INLINE_ALLOW.search(lines[index]) and _INLINE_ALLOW.search(lines[index + 1]):
            continue
        joined = _join_adjacent_literals(window)
        if joined and _provider_hits(joined):
            findings.append({
                "file": rel_str,
                "line": index + 1,
                "type": "split_secret",
                "snippet": _redact(window),
            })
    return findings


def scan(root: Path) -> list[dict]:
    findings: list[dict] = []
    globs, rejected = _load_ignore_globs(root)
    for entry in rejected:
        findings.append({
            "file": _IGNORE_FILE,
            "line": 1,
            "type": "overbroad_ignore",
            "snippet": entry,
        })
    for path, text in _iter_files(root):
        rel_str = str(path.relative_to(root))
        if _ignored(rel_str, globs):
            continue
        findings.extend(_scan_text(rel_str, text))
        findings.extend(_scan_split_across_lines(rel_str, text))
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


def scan_history(root: Path) -> list[dict]:
    """Scan added lines in every commit, not only the working tree.

    Deleting a file after it was committed used to clear the in-house scanner
    while the secret stayed in git history. gitleaks covers that independently;
    this is the same check in the scanner we ship, so disabling one job is not
    enough.
    """
    try:
        proc = subprocess.run(
            ["git", "log", "-p", "--all", "-U0", "--no-color"],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return [{
            "file": "(git)",
            "line": 0,
            "type": "history_unscanned",
            "snippet": "git is not available; history was not scanned",
        }]
    if proc.returncode != 0:
        return [{
            "file": "(git)",
            "line": 0,
            "type": "history_unscanned",
            "snippet": (proc.stderr or "git log failed")[:120],
        }]
    findings: list[dict] = []
    current = "(commit)"
    lineno = 0
    for raw in proc.stdout.splitlines():
        if raw.startswith("diff --git "):
            parts = raw.split(" b/", 1)
            current = parts[1] if len(parts) == 2 else raw
            continue
        if raw.startswith("@@"):
            match = re.search(r"\+(\d+)", raw)
            lineno = int(match.group(1)) if match else 0
            continue
        if not raw.startswith("+") or raw.startswith("+++"):
            continue
        line = raw[1:]
        findings.extend(_scan_text(f"history:{current}", line))
        lineno += 1
    return _dedupe(findings)


def scan_paths(paths: list[Path]) -> list[dict]:
    """Scan an explicit list of files (used by ``--staged``)."""
    findings: list[dict] = []
    globs, rejected = _load_ignore_globs(REPO)
    for entry in rejected:
        findings.append({
            "file": _IGNORE_FILE,
            "line": 1,
            "type": "overbroad_ignore",
            "snippet": entry,
        })
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


_USAGE = """FeeFix secret scanner — commit-time and CI gate for leaked credentials.

Usage:
  python -m agents.secret_scan [--path DIR] [--json FILE] [--annotate]
                               [--staged] [--history]

  --path DIR   scan a directory tree (default: this repository)
  --json FILE  also write a machine-readable report (CI artifact)
  --annotate   print each finding as a GitHub check annotation, so a red run
               can be read from the API (`gh pr checks`, the check-runs
               endpoint) instead of a log blob
  --staged     scan only git-staged files (pre-commit mode)
  --history    scan added lines in every commit, not only the working tree
  --help       show this message

Exit codes: 0 = clean, 1 = findings (fails the build on purpose).
False positives: waive in-line with `# secret-scan: allow <reason>`,
or list paths in .secretscanignore.
"""


def _annotation(finding: dict) -> str:
    """One GitHub workflow command for a finding.

    GitHub renders ``::error`` lines as check annotations, which is how a red
    run stays diagnosable when the log blob is not reachable (this scanner spent
    a red CI run with its findings visible only in a log nobody could fetch).
    The message is single-line and escaped per GitHub's workflow-command rules.
    """
    message = f"[{finding['type']}] {finding['file']}:{finding['line']} {finding['snippet']}"
    for char, escape in (("%", "%25"), ("\r", "%0D"), ("\n", "%0A")):
        message = message.replace(char, escape)
    location = ""
    if not str(finding["file"]).startswith("("):  # "(git)" is not a real path
        location = f" file={finding['file']},line={finding['line']}"
    return f"::error title=secret-scan {finding['type']}{location}::{message}"


def main(argv: list[str]) -> int:
    # A CI tool that swallows `--help` and quietly runs the scan instead is a
    # tool people stop trusting; the flag check below (tests/test_ci_config.py)
    # asserts every flag CI passes is advertised here.
    if "--help" in argv or "-h" in argv:
        print(_USAGE, end="")
        return 0

    known = {"--path", "--json", "--annotate", "--staged", "--history"}
    unknown = [
        a for i, a in enumerate(argv)
        if a.startswith("-") and a not in known
    ]
    if unknown:
        print(f"unknown option(s): {' '.join(unknown)}", file=sys.stderr)
        print("run with --help for usage", file=sys.stderr)
        return 2

    root = REPO
    if "--path" in argv:
        root = Path(argv[argv.index("--path") + 1]).resolve()

    if "--staged" in argv and "--history" in argv:
        print("--staged and --history cannot be combined", file=sys.stderr)
        return 2
    if "--staged" in argv:
        findings = scan_paths(_staged_files(root))
        scope = "staged files"
    elif "--history" in argv:
        findings = scan_history(root)
        scope = f"git history of {root}"
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
        if "--annotate" in argv:
            for finding in findings[:20]:
                print(_annotation(finding))
        return 1
    print("  ✓ no committed secrets detected")
    return 0


def _run(argv: list[str]) -> int:
    """``main`` plus one guarantee: a red run always leaves something readable.

    Findings are annotated (``--annotate``); a *crash* is annotated too, because
    a gate that fails for a reason nobody can fetch from the log is a gate
    nobody can act on.
    """
    try:
        return main(argv)
    except BaseException as exc:  # noqa: BLE001 - re-raised below
        if not isinstance(exc, SystemExit):
            print(f"::error title=secret-scan crashed::{type(exc).__name__}: {exc}")
        raise


if __name__ == "__main__":
    sys.exit(_run(sys.argv[1:]))
