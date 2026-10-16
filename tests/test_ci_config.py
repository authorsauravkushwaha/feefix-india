"""CI configuration is a control, so it is tested like one.

Three failure modes this file exists to prevent, all of which have happened to
projects that assumed "CI is green":

1. **Silent rot.** A gate references a module that was renamed, a test file that
   moved, or an action input that no longer exists. Nothing fails until the day
   the gate is needed — which is the day it is missing.
2. **Security theatre.** A job that runs but cannot fail (bad `if:`, missing
   `continue-on-error`, a scanner invoked without its report path) reads as
   protection in the README without being one.
3. **Convenience over safety.** A job that quietly stops enforcing because an
   action's required token scope changed, or because someone demoted a blocking
   step to advisory.

So: the workflow and the pre-commit config are parsed as data, their commands
are resolved against the real modules, and the *cheap* commands are executed for
real. Anything that needs the network or the full test suite is asserted
structurally instead (the suite runs it end to end anyway).
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[1]
CI_PATH = REPO / ".github" / "workflows" / "ci.yml"
PRECOMMIT_PATH = REPO / ".pre-commit-config.yaml"
REQUIREMENTS = REPO / "requirements.txt"


@pytest.fixture(scope="module")
def ci() -> dict:
    assert CI_PATH.exists(), "the CI workflow is missing"
    return yaml.safe_load(CI_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def precommit() -> dict:
    assert PRECOMMIT_PATH.exists(), "the pre-commit config is missing"
    return yaml.safe_load(PRECOMMIT_PATH.read_text(encoding="utf-8"))


def _run_commands(workflow: dict) -> list[str]:
    """Every shell command the workflow executes."""
    commands = []
    for job in workflow["jobs"].values():
        for step in job.get("steps", []):
            if "run" in step:
                commands.extend(
                    line.strip()
                    for line in str(step["run"]).splitlines()
                    if line.strip() and not line.strip().startswith("#")
                )
    return commands


# --------------------------------------------------------------------------- #
# structure: the gates that are supposed to exist
# --------------------------------------------------------------------------- #
def test_workflow_parses_and_declares_the_expected_jobs(ci):
    assert set(ci["jobs"]) >= {
        "test",
        "secret-scan-third-party",
        "sast-and-dependencies",
        "dataset-liveness",
    }
    # Triggered where it matters: our work happens on arena/** branches.
    push_branches = ci[True]["push"]["branches"] if True in ci else ci["on"]["push"]["branches"]
    assert "main" in push_branches
    assert any(b.startswith("arena/") for b in push_branches), (
        "CI must run on the branch this work happens on, not only on main"
    )


def test_permissions_are_least_privilege(ci):
    """Security jobs should not be able to write to the repository."""
    assert ci["permissions"] == {"contents": "read"}, ci["permissions"]
    for name, job in ci["jobs"].items():
        assert job.get("permissions", {"contents": "read"}) == {"contents": "read"}, name


def test_third_party_scanner_is_independent_and_scans_full_history(ci):
    """One scanner is a single point of failure; a shallow clone hides history."""
    steps = ci["jobs"]["secret-scan-third-party"]["steps"]
    uses = [s["uses"] for s in steps if "uses" in s]
    action = next((u for u in uses if "gitleaks" in u), None)
    assert action, f"no independent scanner found in {uses}"
    # Pinned to a major tag, and not the outdated runtime.
    assert action.startswith("gitleaks/gitleaks-action@"), action
    assert not action.endswith("@v2"), f"{action} runs on the retired Node 20 runtime"

    checkout = next(s for s in steps if str(s.get("uses", "")).startswith("actions/checkout"))
    assert checkout["with"]["fetch-depth"] == 0, "a shallow clone cannot scan history"

    gitleaks_step = next(s for s in steps if "gitleaks" in str(s.get("uses", "")))
    # Read-only token: PR commenting needs a write scope, so it must be off.
    assert str(gitleaks_step["env"].get("GITLEAKS_ENABLE_COMMENTS", "")).lower() == "false"
    assert "GITHUB_TOKEN" in gitleaks_step["env"]


def test_sast_and_dependency_jobs_are_blocking(ci):
    """A scanner that cannot fail the build is not a gate."""
    for job_name in ("test", "secret-scan-third-party", "sast-and-dependencies"):
        job = ci["jobs"][job_name]
        assert not job.get("continue-on-error"), f"{job_name} can no longer block"
    commands = " ; ".join(_run_commands(ci))
    assert "bandit" in commands and "-ll" in commands, "bandit must fail on medium+ findings"
    assert "pip-audit -r requirements.txt" in commands


def test_liveness_job_is_advisory_and_off_the_critical_path(ci):
    """Portal outages must be information, not a red build."""
    job = ci["jobs"]["dataset-liveness"]
    assert job.get("continue-on-error") is True
    assert "schedule" in job["if"], job["if"]


def test_jobs_have_timeouts(ci):
    """A hung job burns runner minutes and hides behind a 'pending' badge."""
    for name, job in ci["jobs"].items():
        assert job.get("timeout-minutes"), f"{name} has no timeout"


def test_ci_runs_both_directions_of_the_secret_scan(ci):
    """Scan the tree *and* emit the machine-readable report CI archives."""
    commands = _run_commands(ci)
    assert "python -m agents.secret_scan --json secret-scan-report.json" in commands
    upload = [
        s
        for s in ci["jobs"]["test"]["steps"]
        if str(s.get("uses", "")).startswith("actions/upload-artifact")
    ]
    assert upload and upload[0]["with"]["path"] == "secret-scan-report.json"
    assert upload[0].get("if") == "always()", "the report is most useful when the scan fails"


# --------------------------------------------------------------------------- #
# rot: do the commands reference things that still exist?
# --------------------------------------------------------------------------- #
def test_every_ci_python_module_resolves(ci):
    """`python -m X` for a module that no longer exists is a gate that is gone."""
    modules = re.findall(r"python -m ([a-zA-Z0-9_.]+)", " ".join(_run_commands(ci)))
    assert modules, "no module invocations found — did the workflow change shape?"
    missing = [m for m in modules if importlib.util.find_spec(m) is None]
    assert not missing, f"CI runs modules that do not exist: {missing}"


def test_every_path_referenced_by_ci_exists(ci):
    """Scripts and test files named in the workflow must be on disk."""
    text = CI_PATH.read_text(encoding="utf-8")
    for candidate in re.findall(r"\b(?:tests?|scripts?|data|agents|backend)/[\w./-]+", text):
        assert (REPO / candidate).exists(), f"CI references a missing path: {candidate}"


def test_pre_commit_hooks_reference_existing_tests(precommit):
    hooks = [h for repo in precommit["repos"] for h in repo["hooks"]]
    assert hooks, "pre-commit config has no hooks"
    for hook in hooks:
        entry = hook["entry"]
        assert entry, hook["id"]
        for match in re.findall(r"tests/[\w./-]+", entry):
            assert (REPO / match).exists(), f"{hook['id']} runs a missing test file: {match}"
        if "--staged" in entry:
            assert entry.startswith("python -m agents.secret_scan"), (
                "staged scanning belongs to the secret scanner"
            )


def test_pre_commit_covers_commit_and_push(precommit):
    """Cheap checks before the commit exists; the full suite before the push."""
    hooks = [h for repo in precommit["repos"] for h in repo["hooks"]]
    stages = {h["id"]: h.get("stages", ["pre-commit"]) for h in hooks}
    assert any("pre-commit" in s for s in stages.values())
    push_hooks = [h for h in hooks if "pre-push" in stages.get(h["id"], [])]
    assert push_hooks, "nothing runs the full suite before a push"
    assert any("python -m pytest" == h["entry"].split(" -q")[0] or h["entry"].startswith("python -m pytest")
               for h in push_hooks)


def test_requirements_cover_every_test_dependency():
    """CI installs `-r requirements.txt`; the suite must not need anything else."""
    declared = REQUIREMENTS.read_text(encoding="utf-8").lower()
    for distribution in (
        "fastapi", "uvicorn", "argon2-cffi", "redis", "python-multipart",
        "fastembed", "pytest", "httpx", "hypothesis", "fakeredis",
    ):
        assert distribution in declared, f"{distribution} is imported but not declared"


# --------------------------------------------------------------------------- #
# execution: the cheap commands must actually work
# --------------------------------------------------------------------------- #
#: Commands too slow or too network-dependent to run here. The full suite runs
#: in the same CI job anyway (and locally as `python -m pytest`), so re-running
#: it inside the suite would be circular; URL probing needs the public internet.
_EXCLUDED = ("pytest", "--check-urls")


def _cheap_ci_commands(ci: dict) -> list[str]:
    commands = []
    for command in _run_commands(ci):
        if any(token in command for token in _EXCLUDED):
            continue
        if command.startswith("pip install") or command.startswith("uses"):
            continue
        commands.append(command)
    return commands


def test_cheap_ci_commands_execute_successfully(ci, tmp_path):
    """Run the workflow's own commands: green CI must not be a guess.

    This is what catches "the agent flag was renamed", "the report path moved"
    or "the module import now needs an env var" *before* a red build does.
    """
    commands = _cheap_ci_commands(ci)
    assert commands, "expected the workflow to run some cheap commands"

    env = {
        # Same layout as CI: pip installs the scanners into the running
        # interpreter's bin directory, which is therefore on PATH.
        "PATH": os.pathsep.join([str(Path(sys.executable).parent), "/usr/bin", "/bin"]),
        "FEEFIX_AI_BACKEND": "ngram",
        "FEEFIX_DB": str(tmp_path / "ci.db"),
        "HOME": str(tmp_path),
        "PYTHONPATH": str(REPO),
    }
    for command in commands:
        # Redirect the report into the sandbox so the repo stays untouched.
        actual = command.replace("secret-scan-report.json", str(tmp_path / "scan.json"))
        result = subprocess.run(
            [sys.executable, *actual.split()[1:]] if actual.startswith("python ") else actual,
            shell=not actual.startswith("python "),
            cwd=REPO,
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
        )
        assert result.returncode == 0, (
            f"CI command failed locally: {command}\n"
            f"--- stdout ---\n{result.stdout[-1500:]}\n"
            f"--- stderr ---\n{result.stderr[-1500:]}"
        )


def test_secret_scan_report_is_machine_readable(tmp_path):
    """The archived artifact is parsed by humans *and* by future tooling."""
    report = tmp_path / "scan.json"
    result = subprocess.run(
        [sys.executable, "-m", "agents.secret_scan", "--json", str(report)],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=300,
        env={**os.environ, "PYTHONPATH": str(REPO)},
    )
    assert result.returncode == 0, result.stderr[-1000:]
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["findings"] == []
    assert payload["scope"]
