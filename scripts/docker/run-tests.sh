#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
set -uo pipefail

packages=(
  "agent-governance-python/agent-primitives"
  "agent-governance-python/agent-mcp-governance"
  "agent-governance-python/agent-os"
  "agent-governance-python/agent-mesh"
  "agent-governance-python/agent-hypervisor"
  "agent-governance-python/agent-runtime"
  "agent-governance-python/agent-sre"
  "agent-governance-python/agent-compliance"
  "agent-governance-python/agent-marketplace"
  "agent-governance-python/agent-lightning"
)

overall=0
for package_dir in "${packages[@]}"; do
  echo
  echo "==> Testing ${package_dir}"
  if [ ! -d "/workspace/${package_dir}/tests" ]; then
    echo "    skipping: no tests/ directory"
    continue
  fi
  if ! bash -euo pipefail -c '
    cd "$1"
    pytest tests/ -q --tb=short
  ' bash "/workspace/${package_dir}"; then
    overall=1
    if [ "${CI:-}" != "true" ]; then
      exit 1
    fi
  fi
done
exit "$overall"