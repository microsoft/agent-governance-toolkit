#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
set -euo pipefail

sdk_dir="/workspace/agent-governance-typescript"

if [[ -f "${sdk_dir}/package.json" && ! -d "${sdk_dir}/node_modules" ]]; then
    echo "Installing TypeScript SDK dependencies..."
    cd "${sdk_dir}"
    npm ci
    cd /workspace
fi

exec "$@"
