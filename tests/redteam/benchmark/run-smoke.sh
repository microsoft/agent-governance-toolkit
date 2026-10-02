#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

pick_python() {
  if [ -n "${PYTHON:-}" ]; then
    "$PYTHON" -c 'import sys' >/dev/null 2>&1 && printf '%s\n' "$PYTHON"
    return
  fi
  local candidate
  for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys' >/dev/null 2>&1; then
      printf '%s\n' "$candidate"
      return
    fi
  done
  return 1
}

PY="$(pick_python)" || {
  echo "[redteam-smoke] FAIL: no working Python interpreter" >&2
  exit 1
}
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "[redteam-smoke] 1/3 validate 24-scenario contract"
"$PY" "$HERE/benchmark.py" validate --scenarios "$HERE/smoke-scenarios.json"

echo "[redteam-smoke] 2/3 run side-effect-free L2 harness"
"$PY" "$HERE/benchmark.py" run \
  --scenarios "$HERE/smoke-scenarios.json" \
  --out "$TMP"

echo "[redteam-smoke] 3/3 enforce metadata-only artifact hygiene"
"$PY" "$HERE/benchmark.py" hygiene \
  --scenarios "$HERE/smoke-scenarios.json" \
  --report "$TMP/report.json" \
  --traces "$TMP/traces.jsonl"

echo "[redteam-smoke] OK"
