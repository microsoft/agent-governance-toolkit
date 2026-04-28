#!/usr/bin/env bash
# ci/no-custom-crypto.sh — Fail if new code introduces direct crypto usage
#                           outside the designated security modules.
#
# AGT's crypto belongs in:
#   agent-governance-python/agent-mesh/  (identity, encryption, trust)
#   agent-governance-rust/src/crypto/
#   agent-governance-typescript/src/encryption/
#   agent-governance-dotnet/src/Security/
#
# Everything else should use the SDK's public API, not raw primitives.
set -euo pipefail

BASE_REF="${1:-origin/main}"

# Patterns that indicate direct crypto usage
CRYPTO_PATTERNS=(
  'from cryptography'
  'from Crypto\.'
  'import hashlib'
  'import hmac'
  'crypto\.subtle'
  'crypto\.createHash'
  'crypto\.createHmac'
  'crypto\.createSign'
  'crypto\.createCipher'
  'use ring::'
  'use ed25519_dalek'
  'use x25519_dalek'
  'use sha2::'
  'use hmac::'
  'use aes_gcm::'
  'System\.Security\.Cryptography'
  'crypto/ed25519'
  'crypto/aes'
  'crypto/hmac'
  'golang\.org/x/crypto'
)

# Paths where crypto is allowed
ALLOWED_PATHS=(
  'agent-governance-python/agent-mesh/'
  'agent-governance-rust/src/'
  'agent-governance-typescript/src/encryption/'
  'agent-governance-dotnet/src/'
  'agent-governance-golang/'
)

PATTERN=$(IFS='|'; echo "${CRYPTO_PATTERNS[*]}")

# Get added lines from non-allowed paths
ADDED=$(git diff "$BASE_REF"...HEAD --diff-filter=ACMR -U0 -- \
  '*.py' '*.ts' '*.rs' '*.cs' '*.go' \
  ':!agent-governance-python/agent-mesh/**' \
  ':!agent-governance-rust/**' \
  ':!agent-governance-typescript/src/encryption/**' \
  ':!agent-governance-dotnet/**' \
  ':!agent-governance-golang/**' \
  ':!*test*' ':!*spec*' ':!ci/no-custom-crypto.sh' \
  | grep -E '^\+[^+]' || true)

if [ -z "$ADDED" ]; then
  echo "✅ no-custom-crypto: no new lines outside crypto modules"
  exit 0
fi

HITS=$(echo "$ADDED" | grep -E "$PATTERN" || true)

if [ -n "$HITS" ]; then
  echo "❌ no-custom-crypto: direct crypto usage found outside designated modules:"
  echo "$HITS"
  echo ""
  echo "Fix: use the SDK's public crypto API, or move this code into the appropriate security module."
  exit 1
fi

echo "✅ no-custom-crypto: no unauthorized crypto usage"
