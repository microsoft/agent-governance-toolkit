#!/usr/bin/env bash
# Generate Ed25519 cryptographic identity (DID)
set -euo pipefail

NAME="" CAPABILITIES=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --name)         NAME="$2"; shift 2;;
    --capabilities) CAPABILITIES="$2"; shift 2;;
    *) echo "Unknown arg: $1" >&2; exit 1;;
  esac
done

python3 -c "
import json, hashlib, base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption

key = Ed25519PrivateKey.generate()
pub = key.public_key()
pub_bytes = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
did = 'did:agentmesh:' + hashlib.sha256(pub_bytes).hexdigest()[:16]

caps = [c.strip() for c in '${CAPABILITIES}'.split(',') if c.strip()]

result = {
    'name': '$NAME',
    'did': did,
    'public_key': base64.b64encode(pub_bytes).decode(),
    'capabilities': caps,
    'key_type': 'Ed25519',
    'note': 'Store your private key securely. Share only the DID and public key.'
}
print(json.dumps(result, indent=2))
"
