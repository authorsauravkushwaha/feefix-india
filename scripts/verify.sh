#!/usr/bin/env bash
# FeeFix India — run every gate that CI runs, in one command.
#
#   ./scripts/verify.sh          → all gates, fail on the first problem
#   ./scripts/verify.sh --quick  → skip the repeated (flake) pass
#
# This exists because a gate that only runs on someone else's machine is a gate
# that quietly rots: the CI workflow is executed here with the same commands, so
# a red build is reproducible locally in one step. Keep it in sync with
# .github/workflows/ci.yml — tests/test_ci_config.py asserts that the commands
# below cover the workflow's.
set -euo pipefail
cd "$(dirname "$0")/.."

# Interpreter resolution: an explicit $PYTHON wins, then the project venv that
# ./scripts/dev.sh creates, then whatever python3 is on PATH. The gates need the
# project's dependencies, so a bare system interpreter fails with a clear
# instruction rather than a stack trace from pytest's own import machinery.
PY="${PYTHON:-}"
if [ -z "$PY" ]; then
  if [ -x .venv/bin/python ]; then
    PY=.venv/bin/python
  else
    PY=python3
  fi
fi

if ! "$PY" -c "import pytest, fastapi, hypothesis" >/dev/null 2>&1; then
  printf '\033[1;31m✗ %s cannot import the project dependencies.\033[0m\n' "$PY"
  echo "  Run ./scripts/dev.sh once to create .venv, or point PYTHON at one:"
  echo "    PYTHON=/path/to/venv/bin/python ./scripts/verify.sh"
  exit 2
fi

# The AI layer must not try to download model weights during a verification run
# (slow, and impossible on an air-gapped machine): the deterministic in-process
# embedder is used instead.
export FEEFIX_AI_BACKEND="${FEEFIX_AI_BACKEND:-ngram}"

step() { printf '\n\033[1m▸ %s\033[0m\n' "$1"; }

step "Test suite (pytest)"
$PY -m pytest

step "Secret scan (in-house)"
$PY -m agents.secret_scan
$PY -m agents.secret_scan --history

step "Static security analysis (bandit, medium+)"
$PY -m bandit -q -r backend agents ai ml -x tests -ll

step "Dependency vulnerability audit (pip-audit)"
$PY -m pip_audit -r requirements.txt

step "Dataset verification agent"
$PY -m agents.verify_dataset

step "ML ranking experiment (sanity)"
$PY -m ml.experiments.simulate_outcomes

step "Reminder scheduler agent (dry run)"
$PY -m agents.reminder_scheduler --dry-run

if [ "${1:-}" != "--quick" ]; then
  # The concurrency/property/migration suites, repeated: the same thing CI's
  # flake-watch job does, because that is what turned an intermittent red badge
  # into a reproduced, named production defect (a concurrent-open crash).
  for pass in 1 2 3; do
    step "Repeat run $pass of 3 (concurrency, property, migrations)"
    $PY -m pytest tests/test_ratelimit_distributed.py \
      tests/test_fuzz_security.py tests/test_schema_migrations.py -q -p no:cacheprovider
  done
fi

printf '\n\033[1;32m✓ all gates passed\033[0m\n'
