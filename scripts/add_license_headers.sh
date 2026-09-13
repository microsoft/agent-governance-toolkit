#!/usr/bin/env bash
set -euo pipefail
HEADER='# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.'
find agent-governance-python/agent-decisionassure -name "*.py" -type f | while read -r f; do
  if ! head -1 "$f" | grep -q "Copyright (c) Microsoft"; then
    printf '%s\n\n' "$HEADER" | cat - "$f" > "$f.tmp" && mv "$f.tmp" "$f"
  fi
done
