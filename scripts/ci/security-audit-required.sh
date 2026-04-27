#!/usr/bin/env bash
# ci/security-audit-required.sh — Require a security audit doc when
#                                   capability-introducing paths change.
#
# If a PR touches core security surfaces (policy engine, identity, trust,
# encryption, execution rings, kill switch), it must include a corresponding
# docs/security-audits/YYYY-MM-DD-*.md file.
set -euo pipefail

BASE_REF="${1:-origin/main}"

# Paths that trigger the security audit requirement
CAPABILITY_PATHS=(
  'agent-governance-python/agent-os/src/agent_os/policies/'
  'agent-governance-python/agent-os/src/agent_os/mcp_gateway'
  'agent-governance-python/agent-os/src/agent_os/approvals'
  'agent-governance-python/agent-mesh/src/agentmesh/identity/'
  'agent-governance-python/agent-mesh/src/agentmesh/trust/'
  'agent-governance-python/agent-mesh/src/agentmesh/encryption/'
  'agent-governance-python/agent-runtime/src/agent_runtime/rings/'
  'agent-governance-python/agent-runtime/src/agent_runtime/kill_switch'
  'agent-governance-python/agent-runtime/src/agent_runtime/saga'
  'agent-governance-rust/src/'
  'agent-governance-typescript/src/encryption/'
  'agent-governance-dotnet/src/Security/'
)

# Check if any capability paths are touched
CHANGED_FILES=$(git diff --name-only "$BASE_REF"...HEAD)
CAPABILITY_TOUCHED=false

for path in "${CAPABILITY_PATHS[@]}"; do
  if echo "$CHANGED_FILES" | grep -q "^$path"; then
    CAPABILITY_TOUCHED=true
    echo "⚡ Capability path touched: $path"
  fi
done

if [ "$CAPABILITY_TOUCHED" = false ]; then
  echo "✅ security-audit-required: no capability paths changed"
  exit 0
fi

# Check for a security audit doc in this PR
AUDIT_DOC=$(echo "$CHANGED_FILES" | grep -E '^docs/security-audits/[0-9]{4}-[0-9]{2}-[0-9]{2}-.+\.md$' || true)

if [ -z "$AUDIT_DOC" ]; then
  echo "❌ security-audit-required: capability paths changed but no security audit doc found."
  echo ""
  echo "This PR touches core security surfaces. Please add a security audit document:"
  echo "  docs/security-audits/$(date +%Y-%m-%d)-<description>.md"
  echo ""
  echo "The audit doc should cover:"
  echo "  - What changed and why"
  echo "  - Threat model impact (new attack surfaces, mitigations)"
  echo "  - Test coverage for security-relevant behavior"
  exit 1
fi

echo "✅ security-audit-required: audit doc found: $AUDIT_DOC"
