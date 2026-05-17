#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

set -euo pipefail

copilot_home="${COPILOT_HOME:-$HOME/.copilot}"
force_policy="${FORCE_POLICY:-false}"
agt_command="${AGT_COPILOT_COMMAND:-install}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
example_root="$(cd "$script_dir/.." && pwd)"
repo_root="${AGT_REPO_ROOT:-$(cd "$example_root/../.." && pwd)}"
package_root="$repo_root/agent-governance-copilot-cli"
package_manifest="$package_root/package.json"
sdk_manifest="$package_root/node_modules/@microsoft/agent-governance-sdk/package.json"

if [[ "$agt_command" != "install" && "$agt_command" != "update" ]]; then
  printf 'AGT_COPILOT_COMMAND must be install or update, got %s\n' "$agt_command" >&2
  exit 1
fi

if [[ ! -f "$package_manifest" ]]; then
  printf 'Could not find agent-governance-copilot-cli at %s\n' "$package_root" >&2
  exit 1
fi

cd "$package_root"
if [[ ! -f "$sdk_manifest" ]]; then
  npm install --no-fund --no-audit
fi

extra_args=()
if [[ "$agt_command" == "update" ]]; then
  extra_args+=(--replace-unmanaged)
fi
if [[ "$force_policy" == "true" ]]; then
  node ./bin/agt-copilot.mjs "$agt_command" --copilot-home "$copilot_home" "${extra_args[@]}" --force-policy
else
  node ./bin/agt-copilot.mjs "$agt_command" --copilot-home "$copilot_home" "${extra_args[@]}"
fi
