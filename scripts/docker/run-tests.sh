#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
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