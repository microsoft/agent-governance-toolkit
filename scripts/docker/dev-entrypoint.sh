#!/usr/bin/env bash
set -euo pipefail

sdk_dir="/workspace/packages/agent-mesh/sdks/typescript"

if [[ -f "${sdk_dir}/package.json" && ! -d "${sdk_dir}/node_modules" ]]; then
    echo "Installing TypeScript SDK dependencies..."
    cd "${sdk_dir}"
    npm ci
    cd /workspace
fi

exec "$@"
