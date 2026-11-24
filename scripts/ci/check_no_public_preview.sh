#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#
# ci/check_no_public_preview.sh — Fail if the "Public Preview" release-stage
# label comes back anywhere outside the historical records.
#
# "Public Preview" names a product release stage. This repository is an MIT
# open-source project, not a product release, so the label does not apply
# (issue #4373). Semver and BREAKING_CHANGES.md say how API changes are
# handled. Dated release history keeps the wording it shipped with.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# Files allowed to carry the phrase: dated historical records only.
ALLOW=(
  ':!CHANGELOG.md'
  ':!BREAKING_CHANGES.md'
  ':!docs/releases/'
  ':!docs/dependency-audits/'
  ':!scripts/ci/check_no_public_preview.sh'
)

# git grep exits 0 on a match, 1 on no match, and 2 (or another non-zero
# code) when it could not run. Capture the status so a Git failure never
# passes as a clean tree.
set +e
HITS=$(git grep -n -i -E 'public[[:space:]-]+preview' -- . "${ALLOW[@]}")
STATUS=$?
set -e

case "$STATUS" in
  0)
    echo "❌ check_no_public_preview: the release-stage label is back:"
    echo "$HITS"
    echo ""
    echo "Fix: drop the label. If a sentence says a feature is incomplete, keep"
    echo "the factual part and remove the stage wording (see issue #4373)."
    exit 1
    ;;
  1)
    echo "✅ check_no_public_preview: no release-stage label outside release history"
    ;;
  *)
    echo "❌ check_no_public_preview: git grep failed with exit status $STATUS;" \
      "the check did not complete (see the git error above)." >&2
    exit "$STATUS"
    ;;
esac
