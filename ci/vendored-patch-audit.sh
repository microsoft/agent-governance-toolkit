#!/usr/bin/env bash
# ci/vendored-patch-audit.sh — Require audit trail when dependency locks change.
#
# When lockfiles or vendored content changes, a corresponding entry must exist
# in docs/dependency-audits/ explaining what changed and why.
set -euo pipefail

BASE_REF="${1:-origin/main}"

# Lockfile patterns across all SDK ecosystems
LOCK_PATTERNS=(
  'requirements*.txt'
  'poetry.lock'
  'Pipfile.lock'
  'Cargo.lock'
  'package-lock.json'
  'pnpm-lock.yaml'
  'yarn.lock'
  'go.sum'
  'packages.lock.json'
)

CHANGED_FILES=$(git diff --name-only "$BASE_REF"...HEAD)
LOCK_TOUCHED=false

for pattern in "${LOCK_PATTERNS[@]}"; do
  if echo "$CHANGED_FILES" | grep -qE "(^|/)$pattern$"; then
    LOCK_TOUCHED=true
    MATCHED=$(echo "$CHANGED_FILES" | grep -E "(^|/)$pattern$")
    echo "⚡ Lockfile changed: $MATCHED"
  fi
done

# Also check vendored content
if echo "$CHANGED_FILES" | grep -q "^vendor/"; then
  LOCK_TOUCHED=true
  echo "⚡ Vendored content changed"
fi

if [ "$LOCK_TOUCHED" = false ]; then
  echo "✅ vendored-patch-audit: no lockfiles or vendored content changed"
  exit 0
fi

# Check for an audit doc
AUDIT_DOC=$(echo "$CHANGED_FILES" | grep -E '^docs/dependency-audits/[0-9]{4}-[0-9]{2}-[0-9]{2}-.+\.md$' || true)

if [ -z "$AUDIT_DOC" ]; then
  echo "❌ vendored-patch-audit: lockfiles changed but no dependency audit doc found."
  echo ""
  echo "Please add: docs/dependency-audits/$(date +%Y-%m-%d)-<description>.md"
  echo ""
  echo "The audit doc should cover:"
  echo "  - Which dependencies changed and why"
  echo "  - Security advisory relevance (CVE numbers if applicable)"
  echo "  - Breaking change risk assessment"
  exit 1
fi

echo "✅ vendored-patch-audit: audit doc found: $AUDIT_DOC"
