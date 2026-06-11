#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# AGT stock Cedar library test runner. Invokes `cedar run-tests` against
# every `.cedar` library file and its sibling `_test.json` in this
# directory. Returns a non-zero exit code when any test fails so CI can
# gate on the result. Mirrors the shape of the sibling Rego runner
# `policy/lib/run_tests.sh`.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

CEDAR_BIN="${CEDAR_BIN:-cedar}"
if ! command -v "$CEDAR_BIN" >/dev/null 2>&1; then
  if [ -x "$HOME/.cargo/bin/cedar" ]; then
    CEDAR_BIN="$HOME/.cargo/bin/cedar"
  else
    echo "error: cedar executable not found on PATH" >&2
    echo "install with: cargo install cedar-policy-cli --version '^4'" >&2
    exit 127
  fi
fi

status=0
shopt -s nullglob
for policy_file in *.cedar; do
  base="${policy_file%.cedar}"
  test_file="${base}_test.json"
  if [ ! -f "$test_file" ]; then
    echo "skip: ${policy_file} has no matching ${test_file}" >&2
    continue
  fi
  echo "== ${policy_file} =="
  if ! "$CEDAR_BIN" check-parse --policies "$policy_file" 2>&1; then
    status=1
  fi
  if ! "$CEDAR_BIN" run-tests --policies "$policy_file" --tests "$test_file" 2>&1; then
    status=1
  fi
done

exit "$status"
