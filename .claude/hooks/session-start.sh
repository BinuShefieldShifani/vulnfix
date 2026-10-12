#!/bin/bash
# Installs Python dependencies for Claude Code cloud sessions so the
# test suite (pytest + semgrep + bandit + javac) runs without skips.
set -euo pipefail

if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

cd "${CLAUDE_PROJECT_DIR:-$(dirname "$0")/../..}"

# CI runs on Python 3.11; match it when available.
PYTHON="$(command -v python3.11 || command -v python3)"
VENV=".venv"

if [ ! -x "$VENV/bin/python" ]; then
  "$PYTHON" -m venv "$VENV"
fi

if command -v uv >/dev/null 2>&1; then
  uv pip install --python "$VENV/bin/python" -r requirements-dev.txt
else
  "$VENV/bin/pip" install -q -r requirements-dev.txt
fi

if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
  echo "export VIRTUAL_ENV=\"$PWD/$VENV\"" >> "$CLAUDE_ENV_FILE"
  echo "export PATH=\"$PWD/$VENV/bin:\$PATH\"" >> "$CLAUDE_ENV_FILE"
  # Semgrep phones home on every run; behind a restrictive network policy
  # each call stalls until it times out.
  echo "export SEMGREP_ENABLE_VERSION_CHECK=0" >> "$CLAUDE_ENV_FILE"
  echo "export SEMGREP_SEND_METRICS=off" >> "$CLAUDE_ENV_FILE"
  # p/default is fetched from semgrep.dev; fall back to the local rules
  # when the registry is not reachable from this environment.
  if ! curl -sSf -m 10 -o /dev/null https://semgrep.dev/c/p/default 2>/dev/null; then
    echo "semgrep.dev unreachable; using local Semgrep rules only" >&2
    echo "export SEMGREP_CONFIG=vulnfix_rules.yml" >> "$CLAUDE_ENV_FILE"
  fi
fi
