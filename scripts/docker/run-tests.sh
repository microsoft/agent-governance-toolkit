#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
set -euo pipefail

packages=(
  "agent-governance-python/agent-os"
  "agent-governance-python/agent-mesh"
  "agent-governance-python/agent-hypervisor"
  "agent-governance-python/agent-sre"
  "agent-governance-python/agent-compliance"
)

for package_dir in "${packages[@]}"; do
    echo
    echo "==> Testing ${package_dir}"
    cd "/workspace/${package_dir}"
    pytest tests/ -q --tb=short
done