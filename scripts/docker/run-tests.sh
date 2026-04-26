#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
set -euo pipefail

packages=(
  "agent-os"
  "agent-mesh"
  "agent-hypervisor"
  "agent-sre"
  "agent-compliance"
)

for package_dir in "${packages[@]}"; do
    echo
    echo "==> Testing ${package_dir}"
    cd "/workspace/${package_dir}"
    pytest tests/ -q --tb=short
done