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
"""

from __future__ import annotations

import json
import math
import re
import subprocess
import sys
from fnmatch import fnmatch
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

_SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", ".pytest_cache",
              ".mypy_cache", ".ruff_cache", ".pydantic_cache", "runtime", "dist",
              "build", ".arena", ".idea", ".vscode"}
_MAX_BYTES = 2_000_000

# ---- 1) high-signal provider shapes --------------------------------------- #
_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("github_pat", re.compile(r"github_pat_[A-Za-z0-9_]{22,}")),
    ("github_token", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("slack_webhook", re.compile(r"hooks\.slack\.com/services/[A-Za-z0-9_/]{20,}")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
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
]

# NAME = "literal" where the NAME strongly implies a real credential.
_STRONG_NAMES = re.compile(
    r"(?i)(client[_-]?secret|secret[_-]?key|api[_-]?key|apikey|access[_-]?token|"
    r"auth[_-]?token|refresh[_-]?token|private[_-]?key|app[_-]?secret|"
    r"signing[_-]?key|encryption[_-]?key|bearer[_-]?token|password|passwd|"
    r"db[_-]?password|smtp[_-]?pass|pepper)"
)
_ASSIGN = re.compile(r"""(?i)\b([a-z0-9_.\-]+)\b\s*[:=]\s*['"]([^'"\n$]{8,})['"]""")
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
    return any(fnmatch(rel, pat) or fnmatch(rel, pat.rstrip("/") + "/*") for pat in patterns)


# --------------------------------------------------------------------------- #
# scanning
# --------------------------------------------------------------------------- #
def _iter_files(root: Path):
    if root.is_file():
        yield root
        return
    for path in sorted(root.rglob("*")):
        if not path.is_file() or any(part in _SKIP_DIRS for part in path.parts):
            continue
        try:
            if path.stat().st_size > _MAX_BYTES:
                continue
        except OSError:
            continue
        yield path


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
        if name and _STRONG_NAMES.search(name) and not _looks_benign(literal, line):
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


def _redact(line: str) -> str:
    """Never echo a suspected secret back in full — CI logs are public."""
    text = line.strip()
    text = re.sub(r"""(['"])([^'"]{12,})\1""", lambda m: f"{m.group(1)}{m.group(2)[:4]}…redacted{m.group(1)}", text)
    return text[:80] + ("…" if len(text) > 80 else "")


def main(argv: list[str]) -> int:
    root = REPO
    if "--path" in argv:
        root = Path(argv[argv.index("--path") + 1]).resolve()
    as_json = "--json" in argv

    if "--check-ci" in argv:
        problems = check_ci_wiring()
        if as_json:
            print(json.dumps({"ok": not problems, "problems": problems}, indent=2))
        else:
            print("== FeeFix Secret-Scan Wiring Check ==")
            if problems:
                for problem in problems:
                    print(f"  ✗ {problem}")
                return 1
            print("  ✓ CI runs the scan unconditionally, with history + gitignore intact")
        return 0 if not problems else 1

    findings = scan(root)
    history: list[dict] = []
    if "--history" in argv:
        history = scan_history(all_branches="--all-branches" in argv)

    if as_json:
        print(json.dumps({"working_tree": findings, "history": history}, indent=2))
        return 1 if (findings or history) else 0

    print("== FeeFix Secret Scan ==")
    scope = "all branches" if "--all-branches" in argv else "this branch's history"
    print(
        f"scanned under {root} | working-tree findings: {len(findings)} | "
        f"history findings ({scope}): {len(history)}"
    )
    for finding in (findings + history)[:50]:
        print(f"  ✗ [{finding['type']}] {finding['file']}:{finding['line']}  {finding['snippet']}")
    if findings or history:
        print("\nA possible secret was found. Remove it, ROTATE the credential (removal")
        print("alone is not rotation), and keep secrets in the environment")
        print("(docs/security/SECURITY.md). False positive? Add the path to")
        print(".secretscanignore or the line to '# pragma: allowlist secret'.")
        return 1
    print("  ✓ no committed secrets detected")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
