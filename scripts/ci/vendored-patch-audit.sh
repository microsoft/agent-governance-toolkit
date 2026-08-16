#!/usr/bin/env bash
# ci/vendored-patch-audit.sh — Require audit trail when dependency locks change.
#
# When lockfiles or vendored content changes, a corresponding entry must exist
# in docs/dependency-audits/ explaining what changed and why.
#
# Exception (issue #2975): routine Dependabot patch/minor bumps cannot author
# that doc by construction, so they are exempt when the caller sets
# PR_ACTOR=dependabot[bot] and DEPENDABOT_UPDATE_TYPE to a non-major update.
# This mirrors auto-merge-dependabot.yml, which already auto-merges exactly that
# set. Human PRs and Dependabot major bumps still require the doc.
set -euo pipefail

BASE_REF="${1:-origin/main}"
PR_ACTOR="${PR_ACTOR:-}"
DEPENDABOT_UPDATE_TYPE="${DEPENDABOT_UPDATE_TYPE:-}"

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
  if grep -qE "(^|/)$pattern$" <<< "$CHANGED_FILES"; then
    LOCK_TOUCHED=true
    MATCHED=$(grep -E "(^|/)$pattern$" <<< "$CHANGED_FILES")
    echo "⚡ Lockfile changed: $MATCHED"
  fi
done

# Also check vendored content
if grep -q "^vendor/" <<< "$CHANGED_FILES"; then
  LOCK_TOUCHED=true
  echo "⚡ Vendored content changed"
fi

if [ "$LOCK_TOUCHED" = false ]; then
  echo "✅ vendored-patch-audit: no lockfiles or vendored content changed"
  exit 0
fi

# Exempt routine Dependabot patch/minor bumps (issue #2975). "Not major"
# matches the auto-merge policy in auto-merge-dependabot.yml. Human PRs (no
# PR_ACTOR match) and Dependabot major bumps fall through and still need a doc.
if [ "$PR_ACTOR" = "dependabot[bot]" ] && \
   [ -n "$DEPENDABOT_UPDATE_TYPE" ] && \
   [ "$DEPENDABOT_UPDATE_TYPE" != "version-update:semver-major" ]; then
  echo "✅ vendored-patch-audit: exempt — Dependabot $DEPENDABOT_UPDATE_TYPE bump (#2975)"
  exit 0
fi

# Check for an audit doc
AUDIT_DOC=$(grep -E '^docs/dependency-audits/[0-9]{4}-[0-9]{2}-[0-9]{2}-.+\.md$' <<< "$CHANGED_FILES" || true)

emit_audit_template() {
  local audit_path audit_date template
  audit_date=$(date +%Y-%m-%d)
  audit_path="docs/dependency-audits/${audit_date}-<description>.md"
  template=$(cat <<EOF
## Dependency audit template

Create \`${audit_path}\` with:

\`\`\`markdown
---
title: <dependency change summary>
last_reviewed: ${audit_date}
owner: <github-handle>
---

# <dependency change summary>

## Which Dependencies Changed And Why

- <dependency>: <old version> -> <new version>
- Reason: <why this update is needed>

## Security Advisory Relevance

- <CVE / advisory relevance, or "No known advisory addressed">

## Breaking Change Risk Assessment

- <compatibility risk and validation performed>
\`\`\`
EOF
)

  printf '%s\n' "$template"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    printf '%s\n' "$template" >> "$GITHUB_STEP_SUMMARY"
  fi
}

if [ -z "$AUDIT_DOC" ]; then
  echo "❌ vendored-patch-audit: lockfiles changed but no dependency audit doc found."
  echo ""
  emit_audit_template
  exit 1
fi

echo "✅ vendored-patch-audit: audit doc found: $AUDIT_DOC"
