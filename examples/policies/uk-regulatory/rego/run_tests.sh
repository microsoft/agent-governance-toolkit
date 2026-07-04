#!/usr/bin/env bash
# agt-policies-uk - OPA test runner for UK regulatory Rego policies.
# Loads UK packs plus the shared jurisdiction router from african-regulatory.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"
AFRICA_REGO="$REPO_ROOT/examples/policies/african-regulatory/rego"
UK_REGO="$SCRIPT_DIR"

OPA_BIN="${OPA_BIN:-opa}"
if ! command -v "$OPA_BIN" >/dev/null 2>&1; then
  echo "error: opa executable not found on PATH" >&2
  exit 127
fi

exec "$OPA_BIN" test "$AFRICA_REGO" "$UK_REGO" -v
