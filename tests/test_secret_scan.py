"""The secret scanner must catch real secrets *and* stay usable.

A scanner that cries wolf gets switched off, and a switched-off scanner protects
nothing — so both directions are tested here: true positives (provider tokens,
entropy, split literals, secrets hidden in unusual files) and true negatives
(test fixtures, character-class alphabets, dotted identifiers, documented fake
credentials).

The regression that motivated this file: the history scan attributed every
committed line to a synthetic filename, which silently disabled the test-fixture
exemption *and* `.secretscanignore`. It lit up on 36 lines, almost all of them in
**other branches'** test fixtures, and it failed CI on a PR that contained no
secret at all.
"""

from __future__ import annotations

import base64
import secrets
from pathlib import Path

import pytest

from agents.secret_scan import (
    _iter_patch_additions,
    _is_charset_range,
    _load_ignore,
    _scan_line,
    entropy,
    scan,
    scan_history,
)

REPO = Path(__file__).resolve().parents[1]

# Sample credentials are assembled from parts held on different lines, so this
# test file does not itself contain a literal provider-token shape (which the
# scanner flags even inside tests — correctly: a real key committed in a test is
# still a leaked key).
GH = "ghp_"
GH_BODY = "a1B2" * 9
SLACK = "xoxb-"
SLACK_BODY = "1234567890-abcdefghijkl"
AWS = "AKIA"
AWS_BODY = "IOSFODNN7EXAMPLE"
GOOGLE = "AIza"
GOOGLE_BODY = "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7"
PEM_HEAD = "-----BEGIN RSA "
PEM_TAIL = "PRIVATE KEY-----"


def findings(line: str, path: str = "module.py") -> list[dict]:
    return _scan_line(line, path, 1, path.startswith("tests/"))


# ------------------------------------------------------------------ true positives
@pytest.mark.parametrize("line,label", [
    (f'GITHUB_TOKEN = "{GH}{GH_BODY}"', "github token"),
    (f'SLACK = "{SLACK}{SLACK_BODY}"', "slack token"),
    (f'aws = "{AWS}{AWS_BODY}"', "aws access key"),
    (f'KEY = "{GOOGLE}{GOOGLE_BODY}"', "google api key"),
    (f"{PEM_HEAD}{PEM_TAIL}", "private key"),
    ('api_key = "8f3aC2b9D4e7F1a6B5c8D2e9F3a7B1c4"', "named secret"),
    ('client_secret = "s3cr3t-value-here-0123456789"', "assigned secret"),
    (f'token = "{GH}" + "{GH_BODY}"', "split provider token"),
])
def test_real_secret_shapes_are_caught(line, label):
    assert findings(line), f"{label} was not detected"


def test_high_entropy_catches_novel_formats():
    for blob in (
        base64.b64encode(secrets.token_bytes(24)).decode(),
        secrets.token_urlsafe(32),
        secrets.token_hex(32),
        "aGVsbG8gd29ybGQgdGhpcyBpcyBiYXNlNjQgZW5jb2RlZA==",
    ):
        assert findings(f'value = "{blob}"'), f"{blob[:12]}… not detected"


def test_secrets_are_scanned_in_unusual_file_types(tmp_path):
    """The old scanner only looked at an allowlist of extensions."""
    (tmp_path / "notes.unknownext").write_text('api_key = "8f3aC2b9D4e7F1a6B5c8D2e9F3a7B1c4"\n')
    assert scan(tmp_path)


def test_finding_snippets_are_redacted():
    line = 'API_KEY = "8f3aC2b9D4e7F1a6B5c8D2e9F3a7B1c4"'
    snippet = findings(line)[0]["snippet"]
    assert "8f3aC2b9D4e7F1a6B5c8D2e9F3a7B1c4" not in snippet, "CI logs are public"
    assert "redacted" in snippet


# ----------------------------------------------------------------- true negatives
@pytest.mark.parametrize("line,label", [
    ('payload = {"sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}', "checksum context"),
    ('i = "f47ac10b-58cc-4372-a567-0e02b2c3d479"', "uuid"),
    ('MODEL = "sentence-transformers/all-MiniLM-L6-v2"', "model name"),
    ('slug = "my-super-long-descriptive-slug-name"', "prose"),
    ('"Content-Type": "application/json"', "mime type"),
    ('db.audit(uid, "auth.token_replay_detected", None)', "dotted identifier"),
    ('REPO_NUMERALS = numerals.NUMERALS_PATH', "attribute path"),
    ('url = "https://api.example.com/v1/resources/list"', "url"),
    ('CHARSET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"', "sanitizer alphabet"),
    ('HEXCHARS = "0123456789abcdefABCDEF"', "hex alphabet"),
    ('API_KEY = os.environ["API_KEY"]', "env lookup"),
])
def test_benign_lines_are_not_flagged(line, label):
    assert findings(line) == [], f"false positive on {label}"


@pytest.mark.parametrize("marker", [
    "# pragma: allowlist secret",
    "# secret-scan: allow",
    "# nosec: secret",
])
def test_in_band_allowlist_prevents_disabling_the_job(marker):
    line = f'API_KEY = "8f3aC2b9D4e7F1a6B5c8D2e9F3a7B1c4"  {marker}'
    assert findings(line) == []


def test_fixtures_in_tests_are_not_flagged_but_live_code_is():
    line = 'client_secret = "s3cr3t-value-here-0123456789"'
    assert findings(line, "tests/test_something.py") == []
    assert findings(line, "backend/services/thing.py") != []


def test_secretscanignore_is_honoured(tmp_path):
    (tmp_path / ".secretscanignore").write_text("# fake creds in a demo\nvendor_demo/*.py\n")
    target = tmp_path / "vendor_demo"
    target.mkdir()
    (target / "sample.py").write_text('api_key = "8f3aC2b9D4e7F1a6B5c8D2e9F3a7B1c4"\n')
    assert scan(tmp_path) == []


def test_charset_range_detector_behaves():
    assert _is_charset_range("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
    assert _is_charset_range("0123456789abcdefABCDEF")
    assert not _is_charset_range("s3cr3t-V4lu3-th4t-l00ks-r4nd0m")
    assert not _is_charset_range(secrets.token_urlsafe(32))


def test_entropy_measure_is_sane():
    assert entropy("aaaaaaaa") < 1.0
    assert entropy("aB3$kL9!mN2@") > 3.0
    assert entropy("") == 0.0


# ------------------------------------------------------------- history scanning
def test_patch_additions_are_attributed_to_their_real_file():
    """The bug: every historical line looked like it came from 'git-history'."""
    patch = (
        "diff --git a/tests/fixtures/sample.py b/tests/fixtures/sample.py\n"
        "--- a/tests/fixtures/sample.py\n"
        "+++ b/tests/fixtures/sample.py\n"
        "@@ -1 +1 @@\n"
        '+client_secret = "s3cr3t-value-here-0123456789"\n'
        "diff --git a/backend/thing.py b/backend/thing.py\n"
        "--- a/backend/thing.py\n"
        "+++ b/backend/thing.py\n"
        "@@ -1 +1 @@\n"
        '+api_key = "8f3aC2b9D4e7F1a6B5c8D2e9F3a7B1c4"\n'
    )
    parsed = list(_iter_patch_additions(patch))
    assert [path for path, _ in parsed] == ["tests/fixtures/sample.py", "backend/thing.py"]

    # With the real path known, the fixture is exempt and the live code is not.
    hits = []
    for path, content in parsed:
        from agents.secret_scan import _TEST_PATH

        hits.extend(_scan_line(content, path, 1, bool(_TEST_PATH.search(path))))
    assert len(hits) == 1 and hits[0]["file"] == "backend/thing.py"


def test_history_scan_defaults_to_this_branch_only(monkeypatch):
    """A PR gate must not fail because of somebody else's in-flight branch."""
    import agents.secret_scan as module

    captured: dict = {}

    def fake_run(args, **kwargs):
        captured["args"] = args

        class Result:
            stdout = ""

        return Result()

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    scan_history()
    assert "--all" not in captured["args"]
    scan_history(all_branches=True)
    assert "--all" in captured["args"]


def test_clean_repository_history_and_worktree():
    assert scan(REPO) == []
    assert scan_history() == [], "this branch's history contains a possible secret"


def test_working_artifacts_are_gitignored():
    """Session artifacts (a full-repo .patch was once committed) must not return."""
    ignore = (REPO / ".gitignore").read_text(encoding="utf-8")
    for pattern in ("*.patch", "*.diff", "*.orig", "*.rej"):
        assert pattern in ignore, f"{pattern} is no longer ignored"


def test_ignore_file_loads_from_the_repository():
    # The repository may not ship one; loading must still be safe.
    assert isinstance(_load_ignore(REPO), list)
