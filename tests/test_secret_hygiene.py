"""Secrets — the audit blocks a production boot, and the scanner is harder to duck.

The review's point #6: the boot-time weak-secret check only logged a warning, so
a deploy still on ``CHANGE_ME`` served traffic happily; and the CI secret scan is
heuristic, so it misses base64'd, split and novel-format secrets.

Both halves are tested here:

* :func:`enforce_secret_hygiene` raises in strict/production mode and only warns
  elsewhere, and the app genuinely refuses to be created,
* the scanner finds provider tokens, base64-encoded tokens, concatenated
  literals, and high-entropy assignments under credential-ish names, while the
  repository itself stays clean (no false positives to train people to ignore).
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from backend.services import secrets as sec

REPO = Path(__file__).resolve().parents[1]


# Secrets are assembled at runtime on purpose: a scanner that flags provider
# tokens *anywhere* (including test files) would otherwise fail on this file.
def _ghp_token() -> str:
    return "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


def _stripe_key() -> str:
    return "sk_" + "live_" + "51H8xQ2Ks9dLp0QwErTyUiOpAsDfGhJkL"


def _aws_key_b64() -> str:
    import base64

    # Assembled at runtime: the literal would (correctly) trip the scanner.
    return base64.b64encode(b"AKIA" + b"IOSFODNN7EXAMPLE1234").decode()


def _dsn() -> str:
    return "postgres://" + "admin" + ":" + "hunter2secret" + "@db.internal:5432/app"


def _opaque(seed: int = 0) -> str:
    import hashlib

    return hashlib.sha256(f"fixture-{seed}".encode()).hexdigest()[:32]


@pytest.fixture()
def clean_secret_env(monkeypatch):
    for name in list(sec._EXPECTED_SECRETS) + list(sec._OTP_CHANNEL_HINTS):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("FEEFIX_ENV", raising=False)
    monkeypatch.delenv("FEEFIX_SECRETS_STRICT", raising=False)
    yield monkeypatch


# --------------------------------------------------------------------------- #
# boot-time enforcement
# --------------------------------------------------------------------------- #
def test_placeholder_secret_blocks_a_production_boot(clean_secret_env):
    clean_secret_env.setenv("FEEFIX_ENV", "production")
    clean_secret_env.setenv("GITHUB_CLIENT_ID", "Iv1.abc123")
    clean_secret_env.setenv("GITHUB_CLIENT_SECRET", "CHANGE_ME")
    with pytest.raises(sec.SecretHygieneError) as exc:
        sec.enforce_secret_hygiene()
    message = str(exc.value)
    assert "GITHUB_CLIENT_SECRET" in message
    assert "FEEFIX_SECRETS_STRICT=0" not in message, (
        "production must not advertise a switch that lets CHANGE_ME keep serving"
    )
    assert "will not start" in message.lower() or "rotate" in message.lower()


def test_placeholder_secret_only_warns_outside_production(clean_secret_env):
    clean_secret_env.setenv("GITHUB_CLIENT_ID", "Iv1.abc123")
    clean_secret_env.setenv("GITHUB_CLIENT_SECRET", "changeme")
    findings = sec.enforce_secret_hygiene()          # must not raise
    assert any("GITHUB_CLIENT_SECRET" in f for f in findings)
    assert all(f["level"] == "warning" for f in sec.assess_secrets())


def test_explicit_strict_flag_applies_everywhere(clean_secret_env):
    clean_secret_env.setenv("FEEFIX_SECRETS_STRICT", "1")
    clean_secret_env.setenv("OTP_TWILIO_SID", "AC123")
    clean_secret_env.setenv("OTP_TWILIO_TOKEN", "   ")
    with pytest.raises(sec.SecretHygieneError):
        sec.enforce_secret_hygiene()


def test_production_cannot_be_downgraded_to_a_warning(clean_secret_env):
    """The old hatch: FEEFIX_SECRETS_STRICT=0 let a production deploy on CHANGE_ME start."""
    clean_secret_env.setenv("FEEFIX_ENV", "production")
    clean_secret_env.setenv("FEEFIX_SECRETS_STRICT", "0")
    clean_secret_env.setenv("OTP_SMTP_PASS", "password")
    assert sec.strict_mode() is True
    with pytest.raises(sec.SecretHygieneError):
        sec.enforce_secret_hygiene()


def test_app_refuses_to_start_with_a_placeholder_secret(clean_secret_env):
    clean_secret_env.setenv("FEEFIX_ENV", "production")
    clean_secret_env.setenv("GITHUB_CLIENT_ID", "Iv1.abc")
    clean_secret_env.setenv("GITHUB_CLIENT_SECRET", "placeholder")
    from backend.main import create_app

    with pytest.raises(sec.SecretHygieneError):
        create_app()


def test_app_starts_when_secrets_are_absent_entirely(clean_secret_env):
    """No integrations configured → nothing to complain about."""
    from backend.main import create_app

    app = create_app()
    assert app.state.boot["password_hashing"]["algorithm"] in ("argon2id", "pbkdf2")


# --------------------------------------------------------------------------- #
# what counts as weak
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "value",
    ["", "changeme", "CHANGE-ME", "placeholder", "password", "aaaa", "xxxxxxxx"],
)
def test_placeholder_shapes_are_weak(value):
    assert sec._looks_weak(value, 16) is True


@pytest.mark.parametrize(
    "value",
    ["aaaaaaaaaaaaaaaaaaaa", "AAAaaa111", "short"],
)
def test_low_variety_values_are_weak(value):
    assert sec._looks_weak(value, 16) is True


def test_realistic_secrets_pass():
    for value in (
        "9f2b7c41d8e34a5fb6c07d1e2f8a3b45",
        "aGVsbG8td29ybGQtdGhpcy1pcy1hLWtleQ",
        "correct horse battery staple 42",
    ):
        assert sec._looks_weak(value, 16) is False, value


def test_otp_pepper_must_be_pinned_when_a_channel_is_configured(clean_secret_env):
    clean_secret_env.setenv("OTP_SMTP_HOST", "smtp.example.com")
    findings = sec.assess_secrets()
    assert any("FEEFIX_OTP_PEPPER" in f["message"] for f in findings)


def test_missing_companion_secret_is_reported(clean_secret_env):
    clean_secret_env.setenv("GITHUB_CLIENT_ID", "Iv1.abc")
    assert any("GITHUB_CLIENT_SECRET" in f["message"] for f in sec.assess_secrets())


def test_get_secret_never_invents_a_default(monkeypatch):
    monkeypatch.delenv("FEEFIX_NOPE", raising=False)
    assert sec.get_secret("FEEFIX_NOPE") is None
    with pytest.raises(RuntimeError):
        sec.get_secret("FEEFIX_NOPE", required=True)


# --------------------------------------------------------------------------- #
# the scanner: what it must catch
# --------------------------------------------------------------------------- #
@pytest.fixture()
def planted(tmp_path: Path) -> Path:
    """A non-test package with one secret per bypass technique."""
    pkg = tmp_path / "svc"
    pkg.mkdir()
    (pkg / "config.py").write_text(
        "\n".join(
            [
                f'GITHUB_CLIENT_SECRET = "{_opaque(1) + _opaque(2)[:8]}"',
                f'API_KEY = "{_opaque(3)}"',
                f'STRIPE = "{_stripe_key()}"',
                f'TOKEN = "ghp_" + "{_ghp_token()[4:]}"',
                f'ENCODED = "{_aws_key_b64()}"',
                f'DB = "{_dsn()}"',
            ]
        ),
        encoding="utf-8",
    )
    (pkg / "settings.yaml").write_text(
        f"service:\n  api_key: {_opaque(4)}\n",  # unquoted config form
        encoding="utf-8",
    )
    (pkg / "notes.txt").write_text(  # unusual extension: sniffed, not skipped
        f'client_secret = "{_opaque(5)}"\n',
        encoding="utf-8",
    )
    return tmp_path


def test_scanner_finds_every_bypass_technique(planted):
    from agents.secret_scan import scan

    findings = scan(planted)
    kinds = {f["type"] for f in findings}
    assert "assigned_secret" in kinds, "plain assignment missed"
    assert "split_secret" in kinds, "concatenated literal missed"
    assert any(k.startswith("encoded_") for k in kinds), "base64-encoded token missed"
    assert "stripe_key" in kinds and "dsn_with_password" in kinds
    # The unquoted YAML form and the unusual file extension are covered too.
    files = {f["file"] for f in findings}
    assert "svc/settings.yaml" in files
    assert "svc/notes.txt" in files


def test_scanner_reports_one_finding_per_line_and_type(planted):
    from agents.secret_scan import scan

    findings = scan(planted)
    keys = [(f["file"], f["line"], f["type"]) for f in findings]
    assert len(keys) == len(set(keys)), "duplicate findings make the report noisy"


def test_scanner_ignores_placeholders_and_references(tmp_path):
    from agents.secret_scan import scan

    (tmp_path / "ok.py").write_text(
        "\n".join(
            [
                'API_KEY = os.environ["API_KEY"]',
                'client_secret = "changeme"',
                'auth_token = "<your-token-here>"',
                'signing_key = "https://example.com/keys"',
                'checksum = "sha256:9f2b7c41d8e34a5fb6c07d1e2f8a3b45"',
            ]
        ),
        encoding="utf-8",
    )
    assert scan(tmp_path) == []


def test_scanner_is_clean_on_this_repository():
    from agents.secret_scan import scan

    findings = scan(REPO)
    assert findings == [], f"committed secrets detected: {findings[:5]}"


def test_inline_waiver_is_explicit_and_greppable(tmp_path):
    from agents.secret_scan import scan

    (tmp_path / "waived.py").write_text(
        f'API_KEY = "{_opaque(6)}"  # secret-scan: allow fixture for tests\n',
        encoding="utf-8",
    )
    assert scan(tmp_path) == [], "a documented waiver must silence the finding"


def test_scanner_entry_point_exits_nonzero_on_findings(planted, capsys):
    from agents import secret_scan

    code = secret_scan.main(["--path", str(planted)])
    assert code == 1
    assert "possible secret" in capsys.readouterr().out.lower()


def test_scanner_can_emit_json_for_ci(planted, tmp_path, capsys):
    import json

    from agents import secret_scan

    out = tmp_path / "report.json"
    secret_scan.main(["--path", str(planted), "--json", str(out)])
    payload = json.loads(out.read_text())
    assert payload["findings"], "the CI artifact must contain the findings"


def test_ignore_file_is_honoured(tmp_path):
    from agents.secret_scan import scan

    (tmp_path / ".secretscanignore").write_text("vendor/**\n", encoding="utf-8")
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    (vendor / "lib.py").write_text(f'API_KEY = "{_opaque(7)}"\n', encoding="utf-8")
    assert scan(tmp_path) == []


def test_ci_config_runs_the_scan_and_a_third_party_scanner():
    """Two independent scanners; one of them is not ours (self-review bias)."""
    ci = (REPO / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "agents.secret_scan" in ci
    assert "gitleaks" in ci.lower(), "add an independent secret scanner to CI"
    assert "bandit" in ci.lower(), "add static security analysis to CI"
    assert "pip-audit" in ci.lower(), "add dependency vulnerability scanning to CI"


def test_pre_commit_hook_configures_the_scanner():
    hook = (REPO / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    assert "agents.secret_scan" in hook
    assert "--staged" in hook


# --------------------------------------------------------------------------- #
# false-positive quality: a scanner people must waive is a scanner they disable
# --------------------------------------------------------------------------- #
def test_documented_placeholder_dsns_are_not_findings():
    """`postgres://user:password@host` in docs is not a leaked credential."""
    from agents.secret_scan import _scan_text

    for example in (
        "DATABASE_URL=postgres://feefix:password@db.internal:5432/app",
        "REDIS_URL=rediss://default:<your-password>@host:6379",
        "MONGO_URL=mongodb://app:changeme@mongo:27017/feefix",
        "MYSQL_URL=mysql://root:xxxxxx@localhost:3306/db",
    ):
        assert _scan_text("deploy/example.env", example) == [], example


def test_real_password_in_a_dsn_is_still_a_finding():
    """Placeholder tolerance must not blunt the detector it applies to."""
    from agents.secret_scan import _scan_text

    # Assembled at runtime so this file stays scan-clean (see the module note).
    password = "S7q2" + "Lm9Xz4Tb1Wk"
    findings = _scan_text(
        "deploy/prod.env",
        f"DATABASE_URL=postgres://feefix:{password}@db.internal:5432/app",
    )
    assert [f["type"] for f in findings] == ["dsn_with_password"]


def test_bare_waiver_and_overbroad_ignore_do_not_silence_a_secret(tmp_path):
    from agents.secret_scan import scan

    sample = "8f3a" + "1c7e5b2d80469af1c2"
    (tmp_path / "leaky.py").write_text(
        f'API_KEY = "{sample}"  # secret-scan: allow\n',
        encoding="utf-8",
    )
    assert scan(tmp_path), "a waiver without a reason must not hide a secret"
    (tmp_path / ".secretscanignore").write_text("**\n", encoding="utf-8")
    findings = scan(tmp_path)
    assert any(f["type"] == "overbroad_ignore" for f in findings)
    assert any(f["type"] == "assigned_secret" for f in findings)


def test_hex_and_unicode_escaped_provider_tokens_are_findings():
    from agents.secret_scan import _scan_text

    token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    hexed = token.encode().hex()
    escaped = "".join(f"\\u{ord(ch):04x}" for ch in token)
    assert any(f["type"].endswith("github_token") for f in _scan_text("cfg.py", f'KEY = "{hexed}"'))
    assert any(
        "github_token" in f["type"] for f in _scan_text("cfg.py", f'KEY = "{escaped}"')
    )


def test_inline_waiver_works_and_is_per_line():
    """The documented escape hatch must exist, and must not silence neighbours."""
    from agents.secret_scan import _scan_text

    sample = "8f3a" + "1c7e5b2d80469af1c2"
    text = "\n".join(
        [
            f'API_KEY = "{sample}"  # secret-scan: allow not a real credential',
            f'API_KEY = "{sample}"',
        ]
    )
    findings = _scan_text("config/limits.py", text)
    assert [f["line"] for f in findings] == [2], findings


# --------------------------------------------------------------------------- #
# CLI contract: the gate must be usable and must refuse to guess
# --------------------------------------------------------------------------- #
def test_cli_help_does_not_silently_run_the_scan():
    """`--help` printed nothing and scanned the repo instead, which is exactly
    how a tool teaches people not to trust its flags."""
    from agents.secret_scan import main

    assert main(["--help"]) == 0
    assert main(["-h"]) == 0


def test_cli_rejects_unknown_flags_instead_of_ignoring_them():
    """An ignored typo (`--jsn report.json`) would silently drop the artifact."""
    from agents.secret_scan import main

    assert main(["--jsn", "out.json"]) == 2


def test_cli_flags_used_by_ci_and_pre_commit_are_advertised():
    """The usage text is the contract CI relies on."""
    from agents.secret_scan import _USAGE

    for flag in ("--path", "--json", "--staged", "--history", "--help"):
        assert flag in _USAGE, f"{flag} is used but not documented"
