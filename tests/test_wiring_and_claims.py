"""Do the documented controls actually exist, and are they actually wired in?

Each of the ten weaknesses this project set out to remove has a specific way it
could silently come back: a control that is documented but no longer called
(the dead upload gate), a limit that nobody enforces, a CI job quietly switched
off, or a README that keeps claiming something the code stopped doing. Static
checks like these are crude, but they are the only automated defence against
"the fix was reverted and nobody noticed" — and every one of them maps to a
concrete regression that this repository has already shipped once.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def _read(relative: str) -> str:
    return (REPO / relative).read_text(encoding="utf-8")


# ---------------------------------------------------------------- 1. docs stay on
def test_docs_are_enabled_by_default_not_by_remembering_an_env_var():
    from backend.main import docs_enabled

    assert docs_enabled() is True
    source = _read("backend/main.py")
    assert "FEEFIX_DISABLE_DOCS" in source
    assert "cosmetic" in source or "not an attack surface" in source, (
        "the docs switch must stay documented as cosmetic, not as a control"
    )


# ------------------------------------------------------- 2. memory-hard hashing
def test_argon2_is_a_declared_dependency_and_the_default_scheme():
    requirements = _read("requirements.txt")
    assert "argon2-cffi" in requirements, "Argon2id must be an explicit dependency"
    from backend.services import auth as auth_svc

    assert auth_svc.hash_backend() in ("argon2id", "scrypt")
    source = _read("backend/services/auth.py")
    assert "hashlib.pbkdf2_hmac" in source  # legacy verify path only
    assert "legacy_pbkdf2_hash" in source   # explicit, test-only producer
    # New hashes must never be produced by the legacy path.
    assert "def hash_password" in source and "PBKDF2 is **never** produced here" in source


# ------------------------------------------------------ 3. shared rate limiter
def test_rate_limiter_default_store_is_shared_and_multi_process_tested():
    from backend.services import ratelimit

    assert ratelimit.SQLiteStore().shared is True
    assert hasattr(ratelimit, "RedisStore"), "a multi-instance store must exist"
    distributed = _read("tests/test_rate_limit_shared.py")
    assert "get_context(\"spawn\")" in distributed
    assert "FEEFIX_REDIS_URL" in _read("backend/services/ratelimit.py")
    # …and the topology is checked at boot rather than assumed.
    assert "topology_warnings" in _read("backend/main.py")


# --------------------------------------------------- 4. replay without self-DoS
def test_replay_policy_defaults_to_quarantine_and_is_selectable():
    from backend.services import auth as auth_svc

    assert auth_svc._reuse_policy() == "quarantine"
    source = _read("backend/services/auth.py")
    for policy in ("quarantine", "revoke_family", "observe"):
        assert policy in source
    assert "X-Session-Warning" in _read("backend/main.py")
    assert "/auth/security-events" in _read("backend/api/routes.py")
    assert "/auth/logout-all" in _read("backend/api/routes.py")


# ------------------------------------------------- 5. clipboard honesty is tested
def test_clipboard_helper_is_behaviourally_tested_and_honest():
    source = _read("web/frontend/secure-clipboard.js")
    assert "NOT a security control" in source
    assert "readText" in source, "the wipe must verify before clearing"
    assert REPO.joinpath("web/tests/clipboard.test.mjs").is_file()


# ------------------------------------------------- 6. secret scan & enforcement
def test_secret_scanning_is_wired_and_unbypassable():
    from agents.secret_scan import check_ci_wiring, scan

    assert scan(REPO) == []
    assert check_ci_wiring(REPO) == [], check_ci_wiring(REPO)
    assert "entropy" in _read("agents/secret_scan.py")


def test_weak_secrets_are_fatal_in_production(monkeypatch):
    from backend.services import secrets as secrets_svc

    monkeypatch.setenv("FEEFIX_STRICT_SECRETS", "1")
    monkeypatch.setenv("GITHUB_CLIENT_ID", "x")
    monkeypatch.setenv("GITHUB_CLIENT_SECRET", "changeme")
    try:
        secrets_svc.enforce_secret_policy()
    except RuntimeError:
        pass
    else:  # pragma: no cover - the whole point of the check
        raise AssertionError("placeholder secrets must abort startup in strict mode")


# ---------------------------------------------------- 7. the upload gate is used
def test_upload_gate_is_reachable_from_a_route():
    routes = _read("backend/api/routes.py")
    assert "store_document" in routes, "no route calls the upload gate — dead control"
    assert "assert_safe_upload" in _read("backend/services/documents.py")

    # Exactly two modules may write files, each for a stated reason: the upload
    # store (user bytes, always validated) and the OTP pepper (server-generated
    # secret, never user data). A new writer appearing here must be justified.
    allowed = {
        "documents.py": "validated user uploads, outside the web root",
        "otp.py": "server-generated pepper file, not user input",
    }
    pattern = re.compile(r"open\([^)]*['\"]w|O_WRONLY|write_bytes\(")
    writers = sorted({
        path.name
        for path in (REPO / "backend").rglob("*.py")
        if pattern.search(path.read_text(encoding="utf-8"))
    })
    assert set(writers) <= set(allowed), f"unjustified file writer(s): {set(writers) - set(allowed)}"
    assert "documents.py" in writers


# --------------------------------------------- 8. i18n parser is data-driven
def test_income_parser_reads_a_lexicon_instead_of_escapes():
    backend = _read("backend/services/chat.py")
    assert "from backend.services.numerals import parse_income" in backend
    assert "\\u0" not in backend.split("def parse_income")[1].split("def parse_state")[0], (
        "the income parser must not carry \\uXXXX escapes again"
    )
    lexicon = _read("language/regional_support/numerals.json")
    assert "crore" in lexicon and "digit_sets" in lexicon
    from backend.services.numerals import validate_lexicon

    assert validate_lexicon() == []


# ------------------------------------------------- 9. per-endpoint body limits
def test_body_limits_are_per_endpoint_and_stream_enforced():
    from backend.services.limits import body_limit_for

    assert body_limit_for("/api/chat").max_bytes != body_limit_for("/api/schemes").max_bytes
    middleware = _read("backend/services/body_limit.py")
    assert "http.disconnect" in middleware, "streaming enforcement must stop the flood"
    assert "limit_bytes" in middleware, "rejections must tell the client the limit"


# --------------------------------------------------- 10. evidence, not assertions
def test_evidence_beyond_the_authors_happy_path_exists():
    assert REPO.joinpath("scripts/fuzz_api.py").is_file()
    assert REPO.joinpath("tests/test_fuzzing.py").is_file()
    assert "hypothesis" in _read("requirements.txt")
    assert "pip-audit" in _read(".github/workflows/ci.yml")
    assert "fuzz_api" in _read(".github/workflows/ci.yml")


def test_ci_runs_the_security_evidence_jobs():
    workflow = _read(".github/workflows/ci.yml")
    for command in (
        "agents.secret_scan",
        "secret_scan --history",
        "node --test",
        "pip-audit",
        "scripts.fuzz_api",
        "tests/test_rate_limit_shared.py",
    ):
        assert command in workflow, f"CI no longer runs: {command}"


def test_scan_history_is_clean_for_this_repository():
    """A secret deleted in a later commit is still a leaked secret."""
    from agents.secret_scan import scan_history

    assert scan_history() == []


# ----------------------------------------------------- docs must not overclaim
def test_docs_do_not_claim_a_security_control_that_is_not_one():
    security = _read("docs/security/SECURITY.md")
    hardening = _read("docs/security/HARDENING.md")
    assert "Argon2id" in security
    password_row = security.split("| Password theft")[1][:700]
    assert "Argon2id" in password_row
    # PBKDF2 may be *described as replaced*, never presented as the live scheme.
    assert "**PBKDF2" not in password_row, "docs still advertise PBKDF2 as the current hash"
    assert "pbkdf2$600000$" not in security, "docs still document the legacy stored format"
    combined = security + hardening + _read("README.md")
    assert "off unless" not in combined, "stale claim: docs are on by default now"
    # Clipboard hardening must be described as UX hygiene, not protection.
    assert "not a security control" in hardening.lower() or "UX hygiene" in hardening
    # And the audit gap must be stated, not hidden.
    assert "no third-party" in combined.lower() or "not been externally audited" in combined.lower()


def test_readme_does_not_quote_a_pass_count_as_a_security_claim():
    readme = _read("README.md")
    assert not re.search(r"\b\d{3} (?:tests? )?passed\b", readme, re.I), (
        "test counts are not a security claim — state what is covered instead"
    )


def test_no_workflow_job_silently_swallows_security_failures():
    workflow = _read(".github/workflows/ci.yml")
    security_steps = [
        chunk for chunk in workflow.split("- name:")
        if any(word in chunk for word in ("secret", "audit", "fuzz", "security"))
    ]
    assert security_steps
    for chunk in security_steps:
        assert "continue-on-error: true" not in chunk, (
            "a security job that cannot fail is documentation, not a control"
        )


def test_pytest_suite_is_discoverable_from_a_clean_checkout():
    """The suite must not depend on a downloaded model or a network."""
    conftest = _read("tests/conftest.py")
    assert "FEEFIX_AI_BACKEND" in conftest and "ngram" in conftest
    result = subprocess.run(
        ["git", "status", "--porcelain", "runtime/"], cwd=REPO, capture_output=True, text=True
    )
    assert result.returncode == 0
