#!/usr/bin/env bash
# View and verify Merkle audit log
set -euo pipefail

LAST="10" AGENT="" VERIFY=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --last)   LAST="$2"; shift 2;;
    --agent)  AGENT="$2"; shift 2;;
    --verify) VERIFY="true"; shift;;
    *) echo "Unknown arg: $1" >&2; exit 1;;
  esac
done

python3 -c "
import json
try:
    from agentmesh.audit import MerkleAuditChain
    chain = MerkleAuditChain()
    entries = chain.get_entries(agent='$AGENT' or None, last=int('$LAST'))
    if '$VERIFY' == 'true':
        valid = chain.verify_integrity()
        print(json.dumps({'integrity': 'valid' if valid else 'TAMPERED', 'entries': len(entries)}, indent=2))
    else:
        print(json.dumps([e.to_dict() for e in entries], indent=2))
except ImportError:
    result = {
        'entries': [],
        'note': 'Install agentmesh for audit logging: pip install agentmesh'
    }
    print(json.dumps(result, indent=2))
"
