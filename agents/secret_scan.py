"""Secret-scanning agent — fail CI if a credential lands in the repo.

Turns out "regex for known token shapes" is not a control: it misses anything
base64'd, split across lines, in a novel provider's format, or living in a file
whose extension nobody listed. This version closes those holes while staying
offline and dependency-free:

1. **Known shapes** — provider prefixes for GitHub/Slack/AWS/Google/Twilio/
   Stripe/SendGrid/GitLab/npm/OpenAI/Anthropic/Hugging Face/Heroku/DigitalOcean,
   PEM private keys, JWTs, and `.env`-style assignments.
2. **Entropy** — a Shannon-entropy pass over any quoted literal or ``NAME=value``
   in the token character set, so a secret that matches *no* known pattern but
   looks like one (random 32+ chars) is still caught. To stay usable it ignores
   checksum/digest contexts, hashes of URLs, and single-character-class words.
3. **Split/concatenated secrets** — adjacent literals on a line
   (``"ghp_" "abcdef…"`` or ``"a" + "b"``) are re-joined and re-scanned, which
   defeats the "split it so the regex misses" bypass.
4. **All text files** — not an allowlist of extensions: every file is scanned
   unless it is binary (NUL-sniffed), oversized, or in a skip directory.
5. **History** — ``--history`` walks ``git log -p --all`` so a secret that was
   committed and later deleted is still reported (removal is not rotation).
6. **Allowlist instead of bypass** — ``.secretscanignore`` (path globs, with a
   reason) and ``# pragma: allowlist secret`` on a line handle false positives
   in-band, so nobody has to disable the job to get a build green.
7. **Wiring self-check** — ``--check-ci`` verifies the CI workflow actually runs
   this scan *without* ``continue-on-error`` and that the ignore rules for
   ``.env``/``*.pem``/``*.key``/the OTP pepper are still in place. The
   regression suite calls it, so un-wiring the control fails the tests.

Exit code 1 = a finding needs attention. Usage::

    python -m agents.secret_scan                 # scan the working tree
    python -m agents.secret_scan --history       # + this branch's history
    python -m agents.secret_scan --history --all-branches   # whole-repo audit
    python -m agents.secret_scan --check-ci      # assert CI wiring is intact
    python -m agents.secret_scan --json          # machine-readable output

A finding can be waived in-line (``# secret-scan: allow <reason>``) or by path
glob in ``.secretscanignore``. Waivers are deliberate and reviewable, which is
the point: a scanner you cannot silence honestly gets silenced dishonestly.
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
              ".hypothesis", "uploads", ".pydantic_cache", ".idea", ".vscode"}
_MAX_BYTES = 2_000_000
_IGNORE_FILE = ".secretscanignore"
#: Artifacts this pipeline writes about its own findings: the scanner's JSON
#: reports and the archived pytest output. They quote findings on purpose, so
#: scanning them reports every finding twice (once as a credential, once as a
#: quoted copy) — which is how a red scan became a red scan for the *wrong*
#: reason in CI. Everything they quote came from a file that is scanned directly.
_GENERATED_ARTIFACTS = frozenset({
    "secret-scan-report.json",
    "secret-scan-history.json",
    "pytest-report.xml",
    "pytest-output.txt",
})
# A waiver without a reason is how a scanner gets silenced. The reason has to
# be long enough that `# secret-scan: allow x` is not a bypass.
_INLINE_ALLOW = re.compile(r"secret-scan:\s*allow\s+\S.{7,}", re.I)
_OVERBROAD_GLOBS = {"*", "**", "**/*", "/*", "./**", "**/**", "*.*"}

# ---- 1) high-signal provider shapes --------------------------------------- #
_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("github_pat", re.compile(r"github_pat_[A-Za-z0-9_]{22,}")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("slack_webhook", re.compile(r"hooks\.slack\.com/services/[A-Za-z0-9_/]{20,}")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("google_oauth_secret", re.compile(r"GOCSPX-[0-9A-Za-z\-_]{20,}")),
    ("twilio_key", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    ("twilio_sid", re.compile(r"\bAC[0-9a-fA-F]{32}\b")),
    ("stripe_key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}")),
    ("sendgrid_key", re.compile(r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}")),
    ("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}")),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    ("huggingface_token", re.compile(r"\bhf_[A-Za-z0-9]{30,}")),
    ("heroku_key", re.compile(r"\bheroku_[A-Za-z0-9]{20,}")),
    ("digitalocean_token", re.compile(r"\bdop_v1_[a-f0-9]{40,}")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----")),
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

_ENV_ASSIGN = re.compile(r"""(?m)^\s*(?:export\s+)?([A-Z][A-Z0-9_]{2,})\s*[:=]\s*([^\s#'"]{12,})\s*$""")
_LITERAL = re.compile(r"""['"]([^'"\n]{16,})['"]""")

# Only the charsets a real credential uses; prose never matches this.
_TOKEN_CHARS = re.compile(r"^[A-Za-z0-9+/=_\-\.:~]{16,}$")
#: A nameless literal must look like a bare token (no path/identifier syntax).
_BARE_TOKEN = re.compile(r"^[A-Za-z0-9+/=_-]{20,}$")
#: Pure hex can never reach 4.0 bits/char (max is 4.0 exactly), so it needs its
#: own length rule — 40+ hex chars is 160 bits of secret, a UUID is not.
_HEX_BLOB = re.compile(r"^[0-9a-fA-F]{40,}$")
#: Natural-language hyphenation ("sentence-transformers") and dotted identifiers
#: ("auth.token_replay_detected") and MIME types score high on Shannon entropy
#: but are not credentials. Filtering them is what keeps the signal usable.
_NATURAL_WORD = re.compile(r"^[a-z]+(?:[._-][a-z]+)+$")
_DOTTED_IDENT = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+$")
#: Any-case dotted identifier/attribute path — code, never a credential.
_DOTTED_PATH = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$")
_MIME_TYPE = re.compile(r"^[a-z]+/[a-z0-9.+-]+$")
_HTTP_HEADER_NAMES = frozenset({
    "content-type", "accept", "authorization", "user-agent", "cache-control",
    "content-disposition", "x-session-token", "referer", "origin", "host",
    "content-length", "accept-encoding", "accept-language",
})
HIGH_ENTROPY_BITS = 4.0

_PLACEHOLDER_LITERALS = {
    "changeme", "change-me", "change_me", "your-secret-here", "example",
    "placeholder", "none", "null", "todo", "redacted", "your_client_secret",
    "client_secret", "access_token", "auth_token", "your_api_key", "string",
    "your-secret", "supersecret", "not-a-real-secret", "fake-secret",
    "unset", "test", "dummy", "sample", "secret", "password",
}
#: Contexts where a high-entropy string is expected and legitimate.
_BENIGN_CONTEXT = (
    "sha256", "sha1", "sha512", "md5", "hashlib", "checksum", "digest",
    "hmac", "uuid", "salt", "etag", "integrity=", "cache-bust", "nonce",
    "localhost", "127.0.0.1", "example.com", "fonts.googleapis",
    "cdn.jsdelivr", "unpkg.com", "data:image", "base64,", "utf-8",
    "application/", "text/plain", "charset", "model_name", "sentence-transformers",
)

# Test fixtures legitimately carry sample credentials — don't flag them here.
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

_TEST_PATH = re.compile(r"(^|/)(tests?/|test_[^/]*$|.*_test\.py$|conftest\.py$|fixtures?/)")
_ALLOWLIST_PRAGMA = re.compile(
    r"pragma:\s*allowlist\s+secret|secret-scan:\s*allow|nosec:\s*secret", re.I
)
#: Captured diffs (``*.patch``/``*.diff``) contain other files' *lines*, so the
#: context-dependent checks (is this a test fixture? is this a checksum?) cannot
#: be evaluated correctly inside them — a fixture's fake password looks identical
#: to a real one once the surrounding file path is gone. Only the self-contained
#: provider-shape patterns are applied there; that still catches a real token
#: pasted into a patch, without turning every captured diff into noise.
_CONTAINER_ARTIFACT = re.compile(r"\.(?:patch|diff)$", re.I)


# --------------------------------------------------------------------------- #
# ignore-file support
# --------------------------------------------------------------------------- #
def _load_ignore(root: Path) -> list[str]:
    """Path globs from ``.secretscanignore`` (one per line, ``#`` comments)."""
    path = root / ".secretscanignore"
    if not path.is_file():
        return []
    patterns: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        entry = line.split("#", 1)[0].strip()
        if entry:
            patterns.append(entry)
    return patterns


def _ignored(rel: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, pat.rstrip("/") + "/*") for pat in patterns)


# --------------------------------------------------------------------------- #
# scanning
# --------------------------------------------------------------------------- #
def _iter_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.name in _GENERATED_ARTIFACTS:
            # Outputs about findings, not inputs to scan. A red CI run went red a
            # second time because the working-tree scan re-reported the sample
            # credentials quoted inside the history report it had just written,
            # and inside the junit XML that archived the same text.
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


def _is_binary(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return b"\x00" in handle.read(4096)
    except OSError:
        return True


def entropy(value: str) -> float:
    """Shannon entropy in bits per character."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def _char_classes(value: str) -> int:
    return sum([
        bool(re.search(r"[a-z]", value)),
        bool(re.search(r"[A-Z]", value)),
        bool(re.search(r"\d", value)),
        bool(re.search(r"[^A-Za-z0-9]", value)),
    ])


def _looks_benign(value: str, line: str) -> bool:
    low = value.lower()
    if low in _PLACEHOLDER_LITERALS:
        return True
    if (
        _NATURAL_WORD.search(value)
        or _DOTTED_IDENT.match(value)
        or _DOTTED_PATH.match(value)
        or _MIME_TYPE.match(value)
    ):
        return True
    if low.startswith(("http", "https", "www.", "<", "{{", "${", "assets/", "/api/")):
        return True
    if any(hint in line.lower() for hint in _BENIGN_CONTEXT):
        return True
    if any(low.endswith(ext) for ext in (".png", ".jpg", ".svg", ".css", ".js", ".json", ".py", ".md")):
        return True
    # A long run of a single class with no digits is almost always prose or an
    # identifier (camelCase names score surprisingly high on Shannon entropy).
    if _char_classes(value) < 2:
        return True
    return False


def _is_charset_range(value: str) -> bool:
    """True for a character-class alphabet, e.g. ``"abc…zABC…Z0-9._-"``.

    Sanitisers, validators and CSP helpers legitimately carry these: they are
    long, multi-class and therefore score high on Shannon entropy, but their
    *sorted unique* characters form a couple of consecutive runs. A real secret's
    do not — random bytes leave a gap between nearly every pair. This removes the
    single largest class of false positives (four of them in this repository's
    other branches), which is what keeps the scan usable enough that nobody
    disables it.
    """
    chars = sorted(set(value))
    if len(chars) < 10 or len(chars) < 0.4 * len(value):
        return False
    gaps = sum(1 for a, b in zip(chars, chars[1:]) if ord(b) - ord(a) > 1)
    return gaps <= 6


def _high_entropy_secret(value: str, line: str) -> bool:
    if len(value) < 20 or not _TOKEN_CHARS.match(value):
        return False
    if _looks_benign(value, line):
        return False
    if _HEX_BLOB.match(value):        # 40+ hex chars: 160+ bits, not a checksum id
        return True
    if _is_charset_range(value):      # "abc…zABC…Z0-9" allowlist, not a credential
        return False
    return entropy(value) >= HIGH_ENTROPY_BITS


def _joined_literals(line: str) -> str:
    """Re-join split literals: ``"ghp_" + "abcdef…"`` / implicit adjacency.

    This is the anti-bypass for "chop the token in two so the regex misses it".
    """
    pieces = re.findall(r"""['"]([^'"\n]{2,})['"]""", line)
    if len(pieces) < 2:
        return ""
    return "".join(pieces)


#: Name-scoped strong names for :func:`_scan_line`. The shared pipeline searches
#: the *whole line* (where a bare `password` appears in every HTML autofill
#: attribute and must not count), but `_scan_line` evaluates the assignment's
#: NAME in isolation — there `password = "…"` in live code is exactly the shape
#: this whole module exists to catch, and its tests pin it.
_STRONG_NAMES_BY_NAME = re.compile(
    r"(?i)(client[_-]?secret|secret[_-]?key|api[_-]?key|apikey|access[_-]?token|"
    r"auth[_-]?token|refresh[_-]?token|private[_-]?key|app[_-]?secret|"
    r"signing[_-]?key|encryption[_-]?key|bearer[_-]?token|password|passwd|"
    r"db[_-]?password|smtp[_-]?pass|pepper|consumer[_-]?secret|twilio[_-]?token|"
    r"otp[_-]?pepper)"
)


def _scan_line(line: str, rel: str, lineno: int, is_test: bool) -> list[dict]:
    findings: list[dict] = []
    if _ALLOWLIST_PRAGMA.search(line):
        return findings
    for label, pattern in _PATTERNS:
        if pattern.search(line):
            findings.append({"file": rel, "line": lineno, "type": label,
                             "snippet": _redact(line)})
    joined = _joined_literals(line)
    if joined and joined != line:
        for label, pattern in _PATTERNS:
            if pattern.search(joined):
                findings.append({"file": rel, "line": lineno, "type": f"{label}_split",
                                 "snippet": _redact(line)})

    if _CONTAINER_ARTIFACT.search(rel):
        return findings

    candidates: list[tuple[str, str]] = []          # (name, literal)
    for match in _ASSIGN.finditer(line):
        candidates.append((match.group(1), match.group(2)))
    for match in _ENV_ASSIGN.finditer(line):
        candidates.append((match.group(1), match.group(2)))
    for match in _LITERAL.finditer(line):
        candidates.append(("", match.group(1)))

    seen_literals: set[str] = set()
    for name, literal in candidates:
        literal = literal.strip()
        if name.lower() in _HTTP_HEADER_NAMES:
            continue
        if not name and not _BARE_TOKEN.match(literal):
            continue  # an unattached short/prose string is not evidence
        if literal in seen_literals:
            continue
        seen_literals.add(literal)
        if "environ" in line or "getenv" in line or "os.env" in line:
            continue
        if "${" in literal or "{{" in literal or literal.startswith("$"):
            continue
        if is_test:
            continue  # sample credentials in tests are expected
        if name and _STRONG_NAMES_BY_NAME.search(name) and not _looks_benign(literal, line):
            findings.append({"file": rel, "line": lineno, "type": "assigned_secret",
                             "name": name, "snippet": _redact(line)})
            continue
        if _high_entropy_secret(literal, line):
            findings.append({"file": rel, "line": lineno, "type": "high_entropy",
                             "name": name or "(literal)", "snippet": _redact(line)})
    return findings


def scan(root: Path, extra_ignore: list[str] | None = None) -> list[dict]:
    findings: list[dict] = []
    ignore = _load_ignore(root if root.is_dir() else REPO) + list(extra_ignore or [])
    base = root if root.is_dir() else root.parent
    for path in _iter_files(root):
        try:
            rel = str(path.relative_to(base))
        except ValueError:  # pragma: no cover - defensive
            rel = str(path)
        if _ignored(rel, ignore) or _is_binary(path):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        is_test = bool(_TEST_PATH.search(rel))
        for lineno, line in enumerate(text.splitlines(), 1):
            findings.extend(_scan_line(line, rel, lineno, is_test))
    return _dedupe(findings)


def _dedupe(findings: list[dict]) -> list[dict]:
    seen: set[tuple] = set()
    unique: list[dict] = []
    for finding in findings:
        key = (finding["file"], finding["line"], finding["type"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def _iter_patch_additions(patch: str):
    """Yield ``(path, added_line)`` for every added line of a unified diff.

    Tracking the ``+++ b/<path>`` header matters for correctness, not cosmetics:
    without it every historical line is attributed to a synthetic filename, so
    the test-fixture exemption and `.secretscanignore` stop applying and the
    scan lights up on the fake credentials that tests legitimately contain.
    """
    current = "git-history"
    for line in patch.splitlines():
        if line.startswith("+++ "):
            target = line[4:].strip()
            current = target[2:] if target.startswith("b/") else target
            continue
        if line.startswith("+"):
            yield current, line[1:]


def scan_history(rev: str = "HEAD", limit: int = 4000, all_branches: bool = False) -> list[dict]:
    """Scan committed history — a deleted secret is still a leaked secret.

    Scope is the **current branch's lineage** by default: a PR gate must not fail
    because of somebody else's in-flight branch. ``all_branches=True`` (CLI:
    ``--all-branches``) is the deliberate whole-repository audit, and it will
    report the deliberately fake credentials that scanner test-suites across
    branches contain — hence opt-in.
    """
    args = ["git", "log", "-p", "--no-color", "-U0"]
    args += ["--all"] if all_branches else [rev]
    try:
        patch = subprocess.run(
            args, cwd=REPO, capture_output=True, text=True, timeout=180, check=False,
        ).stdout
    except (OSError, subprocess.SubprocessError):  # pragma: no cover - no git
        return []

    ignore = _load_ignore(REPO)
    findings: list[dict] = []
    for lineno, (path, content) in enumerate(_iter_patch_additions(patch), 1):
        if lineno > limit:
            break
        if path == "/dev/null" or _ignored(path, ignore):
            continue
        findings.extend(_scan_line(content, path, lineno, bool(_TEST_PATH.search(path))))
    return _dedupe(findings)


def check_ci_wiring(root: Path | None = None) -> list[str]:
    """Assert the control is still wired up — an unwired control is theatre."""
    root = root or REPO
    problems: list[str] = []
    workflow = root / ".github" / "workflows" / "ci.yml"
    if not workflow.is_file():
        return ["CI workflow .github/workflows/ci.yml is missing"]
    text = workflow.read_text(encoding="utf-8")
    if "agents.secret_scan" not in text:
        problems.append("CI does not run agents.secret_scan anymore")
    else:
        # Find the step that runs the scan and check its surroundings for a
        # silent-failure switch.
        for chunk in text.split("- name:"):
            if "agents.secret_scan" in chunk:
                if "continue-on-error: true" in chunk:
                    problems.append("the secret-scan step sets continue-on-error: true")
                if re.search(r"^\s*if:", chunk, re.M):
                    problems.append("the secret-scan step is conditional (if:)")
                break
        else:  # pragma: no cover - defensive
            problems.append("secret scan is referenced but not as a named step")
    if "agents.secret_scan --history" not in text and "secret_scan --history" not in text:
        problems.append("CI never scans git history for secrets (add --history)")
    ignore = root / ".gitignore"
    if ignore.is_file():
        gitignore = ignore.read_text(encoding="utf-8")
        for needed in (".env", "*.pem", "*.key", ".otp_pepper"):
            if needed not in gitignore:
                problems.append(f".gitignore no longer covers {needed}")
    else:
        problems.append(".gitignore is missing")
    return problems



def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


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
    """Never echo a suspected secret back in full — CI logs are public."""
    text = line.strip()
    text = re.sub(r"""(['"])([^'"]{12,})\1""", lambda m: f"{m.group(1)}{m.group(2)[:4]}…redacted{m.group(1)}", text)
    return text[:80] + ("…" if len(text) > 80 else "")


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


def _history_path_is_exempt(path: str, globs: list[str]) -> bool:
    """Would the working-tree scan have looked at this path at all?

    The ``--history`` mode used to skip only the *display* of a path, so every
    reason a file is not scanned for real (a test fixture that carries sample
    credentials on purpose, an ignore glob, the runtime directory, a virtualenv)
    was silently lost — and a branch carrying
    ``tests/fixtures/secret_scan_samples.py`` turned every other branch's CI red.
    History and working tree must agree on *what* is scanned, or the two gates
    argue with each other.
    """
    if any(part in _SKIP_DIRS for part in Path(path).parts):
        return True
    return _ignored(path, globs)


def scan_history(root: Path = REPO, *, all_branches: bool = False) -> list[dict]:
    """Scan added lines in this branch's history, not only the working tree.

    Deleting a file after it was committed used to clear the in-house scanner
    while the secret stayed in git history. gitleaks covers that independently;
    this is the same check in the scanner we ship, so disabling one job is not
    enough.

    Scope is the *checked-out* history (``HEAD``), deliberately not ``--all``:
    ``--all`` reaches every branch on the remote, so one open branch's
    deliberately fake ``tests/fixtures/secret_scan_samples.py`` turned unrelated
    branches' builds red — and the path-scoped waiver for such a file lives in
    the branch that owns it, not in everyone else's. An unmerged secret is still
    scanned where it matters: when that branch's own CI runs, and again against
    the pull request's merge commit, whose history contains those commits. The
    same path exemptions as the working-tree scan apply here too, so the two
    modes cannot disagree about what counts.
    """
    try:
        proc = subprocess.run(
            ["git", "log", "-p"] + (["--all"] if all_branches else ["HEAD"])
            + ["-U0", "--no-color"],
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
    if getattr(proc, "returncode", 0) != 0:
        return [{
            "file": "(git)",
            "line": 0,
            "type": "history_unscanned",
            "snippet": (proc.stderr or "git log failed")[:120],
        }]
    findings: list[dict] = []
    globs, _rejected = _load_ignore_globs(root)
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
        # Scan under the file's real path (that is what the exemptions match),
        # then label the finding as history so the report says where it is.
        if not _history_path_is_exempt(current, globs):
            for finding in _scan_text(current, line):
                finding["file"] = f"history:{finding['file']}"
                finding["line"] = lineno
                findings.append(finding)
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
  --history    scan added lines in this branch's history (HEAD), not only the
               working tree
  --all-branches
               with --history: scan every local branch (operator audit; the PR
               gate deliberately scans only this branch's lineage)
  --check-ci   assert the CI workflow still runs this scan unconditionally
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

    known = {"--path", "--json", "--annotate", "--staged", "--history",
             "--check-ci", "--all-branches"}
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

    as_json_arg = "--json" in argv
    json_path = None
    if as_json_arg:
        idx = argv.index("--json")
        if idx + 1 < len(argv) and not argv[idx + 1].startswith("--"):
            json_path = Path(argv[idx + 1])

    if "--check-ci" in argv:
        problems = check_ci_wiring(root)
        if json_path is not None:
            json_path.write_text(json.dumps({"ok": not problems, "problems": problems}, indent=2))
        elif as_json_arg:
            print(json.dumps({"ok": not problems, "problems": problems}, indent=2))
        else:
            print("== FeeFix Secret-Scan Wiring Check ==")
            if problems:
                for problem in problems:
                    print(f"  ✗ {problem}")
                return 1
                print("  ✓ CI runs the scan unconditionally, with history + gitignore intact")
        return 0 if not problems else 1

    if "--staged" in argv and "--history" in argv:
        print("--staged and --history cannot be combined", file=sys.stderr)
        return 2
    if "--staged" in argv:
        findings = scan_paths(_staged_files(root))
        scope = "staged files"
    elif "--history" in argv:
        findings = scan_history(root, all_branches="--all-branches" in argv)
        scope = "all branches" if "--all-branches" in argv else f"git history of {root}"
    else:
        findings = scan(root)
        scope = str(root)

    if json_path is not None:
        json_path.write_text(json.dumps({"scope": scope, "findings": findings}, indent=2))
    elif as_json_arg:
        print(json.dumps({"scope": scope, "findings": findings}, indent=2))

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
    if "--annotate" in argv:
        pass  # nothing to annotate on a clean run
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
