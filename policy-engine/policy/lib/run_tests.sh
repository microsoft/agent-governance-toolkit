#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# AGT stock Rego library test runner. Invokes `opa test` against every
# library file and its sibling _test.rego in this directory. Returns a
# non-zero exit code when any test fails so CI can gate on the result.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

OPA_BIN="${OPA_BIN:-opa}"
if ! command -v "$OPA_BIN" >/dev/null 2>&1; then
  if [ -x "$HOME/.local/bin/opa" ]; then
    OPA_BIN="$HOME/.local/bin/opa"
  else
    echo "error: opa executable not found on PATH" >&2
    exit 127
  fi
fi

exec "$OPA_BIN" test . -v
