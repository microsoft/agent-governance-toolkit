#!/usr/bin/env bash
set -euo pipefail

packages=(
  "packages/agent-os"
  "packages/agent-mesh"
  "packages/agent-hypervisor"
  "packages/agent-sre"
  "packages/agent-compliance"
)

for package_dir in "${packages[@]}"; do
    echo
    echo "==> Testing ${package_dir}"
    cd "/workspace/${package_dir}"
    pytest tests/ -q --tb=short
done