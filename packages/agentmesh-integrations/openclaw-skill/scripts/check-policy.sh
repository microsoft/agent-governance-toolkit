#!/usr/bin/env bash
# Check action against governance policy
set -euo pipefail

ACTION="" TOKENS="" POLICY="policy.yaml"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --action)  ACTION="$2"; shift 2;;
    --tokens)  TOKENS="$2"; shift 2;;
    --policy)  POLICY="$2"; shift 2;;
    *) echo "Unknown arg: $1" >&2; exit 1;;
  esac
done

python3 -c "
import json, yaml, re, sys

with open('$POLICY') as f:
    p = yaml.safe_load(f)

violations = []
action = '$ACTION'
tokens = int('${TOKENS:-0}' or '0')

if p.get('max_tokens') and tokens > p['max_tokens']:
    violations.append(f'Token limit exceeded: {tokens} > {p[\"max_tokens\"]}')

if p.get('allowed_tools') and action and action not in p['allowed_tools']:
    violations.append(f'Tool not in allowlist: {action}')

if p.get('blocked_tools') and action in p['blocked_tools']:
    violations.append(f'Tool is blocked: {action}')

if p.get('blocked_patterns'):
    for pat in p['blocked_patterns']:
        if re.search(pat, action, re.IGNORECASE):
            violations.append(f'Blocked pattern matched: {pat}')

result = {
    'allowed': len(violations) == 0,
    'action': action,
    'tokens': tokens,
    'violations': violations,
    'policy': p.get('name', 'unnamed'),
    'require_human_approval': p.get('require_human_approval', False)
}
print(json.dumps(result, indent=2))
sys.exit(0 if result['allowed'] else 1)
"
