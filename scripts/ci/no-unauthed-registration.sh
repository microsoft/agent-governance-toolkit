#!/usr/bin/env bash
# ci/no-unauthed-registration.sh — Block registration endpoints without auth.
#
# Scans Python files touched by a PR for HTTP endpoints that accept
# public_key or verification_key without corresponding proof-of-possession
# verification (VerifyKey, BadSignatureError, proof). Catches CWE-306
# regressions: unauthenticated key registration.
set -euo pipefail

BASE_REF="${1:-origin/main}"

CHANGED_PY=$(git diff --name-only "$BASE_REF"...HEAD -- '*.py' || true)

if [ -z "$CHANGED_PY" ]; then
  echo "✅ no-unauthed-registration: no Python files changed"
  exit 0
fi

FAIL=false

# Pattern 1: Pydantic model with public_key/verification_key field in a file
# that also defines an HTTP route (app.post, app.put, router.post, router.put)
# but does NOT import or call VerifyKey anywhere.
for f in $CHANGED_PY; do
  [ -f "$f" ] || continue

  # Only check files that define HTTP endpoints
  if ! grep -qE '@(app|router)\.(post|put)' "$f" 2>/dev/null; then
    continue
  fi

  # Only check files that accept a public key field
  if ! grep -qE 'public_key|verification_key' "$f" 2>/dev/null; then
    continue
  fi

  # Check if the file has proof-of-possession verification
  HAS_VERIFY=$(grep -cE 'VerifyKey|BadSignatureError|proof_of_possession|verify.*proof' "$f" 2>/dev/null || echo 0)

  if [ "$HAS_VERIFY" -eq 0 ]; then
    echo "❌ $f: defines HTTP endpoint accepting public_key/verification_key but has no proof-of-possession verification"
    echo "   Every registration endpoint that accepts a public key MUST verify"
    echo "   the caller controls the corresponding private key (Ed25519 PoP)."
    echo "   See: agentmesh/registry/app.py for the reference implementation."
    FAIL=true
  fi
done

if [ "$FAIL" = true ]; then
  echo ""
  echo "❌ no-unauthed-registration: FAILED — unauthenticated key registration detected"
  echo "   All endpoints accepting public keys must require proof-of-possession."
  echo "   Reference: CWE-306 (Missing Authentication for Critical Function)"
  exit 1
fi

echo "✅ no-unauthed-registration: all key-accepting endpoints have auth verification"
