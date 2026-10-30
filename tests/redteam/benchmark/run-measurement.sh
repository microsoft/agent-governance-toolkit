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
  echo "[redteam-measurement] FAIL: no working Python interpreter" >&2
  exit 1
}
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "[redteam-measurement] 1/3 verify generated fixtures are not stale"
"$PY" "$HERE/generate_measurement_scenarios.py" --check

echo "[redteam-measurement] 2/3 validate 240-scenario contract"
"$PY" "$HERE/measurement.py" validate --scenarios "$HERE/measurement-scenarios.json"

echo "[redteam-measurement] 3/3 run measurement benchmark with detector evidence"
"$PY" "$HERE/measurement.py" run \
  --scenarios "$HERE/measurement-scenarios.json" \
  --probes "$HERE/measurement-probes.json" \
  --out "$TMP"

echo "[redteam-measurement] OK"
