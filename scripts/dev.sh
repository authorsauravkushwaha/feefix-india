#!/usr/bin/env bash
# FeeFix India — one-command developer bootstrap.
#   ./scripts/dev.sh          → serve at http://0.0.0.0:8000
#   ./scripts/dev.sh --test   → run the test suite and exit
set -euo pipefail
cd "$(dirname "$0")/.."

if [ ! -d .venv ]; then
  echo "▸ creating virtualenv…"
  python3 -m venv .venv
fi
PY=.venv/bin/python

if [ -z "$($PY -c 'import fastapi' 2>/dev/null && echo ok)" ]; then
  echo "▸ installing dependencies…"
  $PY -m pip install --quiet -r requirements.txt
fi

if [ "${1:-}" = "--test" ]; then
  $PY -m pytest
  exit $?
fi

echo "▸ FeeFix India → http://0.0.0.0:8000"
exec .venv/bin/uvicorn backend.main:app --host 0.0.0.0 --port "${PORT:-8000}" "$@"
