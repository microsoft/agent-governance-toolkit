#!/usr/bin/env bash
# ci/no-stubs.sh — Fail if new code introduces TODO/FIXME/HACK/stub markers
#
# Scans only ADDED lines in the diff (so existing debt doesn't block PRs).
# Inspired by AzureClaw's Phase 0 CI gates.
set -euo pipefail

BASE_REF="${1:-origin/main}"
FORBIDDEN=(
  'TODO'
  'FIXME'
  'HACK'
  'XXX'
  'raise NotImplementedError'
  'NotImplementedException'
  'unimplemented!()'
  'todo!()'
  'throw new Error.*not implemented'
  '// stub'
  '# stub'
  'pass  #'
)

# Build a combined grep pattern
PATTERN=$(IFS='|'; echo "${FORBIDDEN[*]}")
CONFLICT_PATTERN='^(<<<<<<< .*$|=======$|>>>>>>> .*$)'

# Get only added lines from the diff, excluding test files and this script
ADDED=$(git diff "$BASE_REF"...HEAD --diff-filter=ACMR -U0 -- \
  '*.py' '*.ts' '*.rs' '*.cs' '*.go' '*.sh' \
  ':!*test*' ':!*spec*' ':!ci/no-stubs.sh' \
  | grep -E '^\+[^+]' || true)

if [ -z "$ADDED" ]; then
  echo "✅ no-stubs: no new production lines to check"
  exit 0
fi

# Detect unresolved git merge conflict markers in added lines only.
# Use content-only lines (strip leading diff '+') so patterns remain anchored.
ADDED_CONTENT=$(echo "$ADDED" | sed 's/^+//')
CONFLICT_HITS=$(echo "$ADDED_CONTENT" | grep -E "$CONFLICT_PATTERN" || true)

if [ -n "$CONFLICT_HITS" ]; then
  echo "❌ no-stubs: found unresolved merge conflict markers in new code:"
  echo "$CONFLICT_HITS"
  echo ""
  echo "Fix: resolve the conflict and remove marker lines before committing."
  exit 1
fi

HITS=$(echo "$ADDED" | grep -iE "$PATTERN" || true)

if [ -n "$HITS" ]; then
  echo "❌ no-stubs: found stub/TODO markers in new code:"
  echo "$HITS"
  echo ""
  echo "Fix: implement the code now, or track as a GitHub issue instead of a comment."
  exit 1
fi

echo "✅ no-stubs: no stub markers found in new code"
