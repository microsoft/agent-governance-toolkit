# OpenClaw - AgentMesh Skill

## What This Is

Zero-trust governance skill for OpenClaw agents, enabling policy enforcement, identity verification, and trust scoring.

## Files

- `skill.md` — Skill specification and behavior description
- `scripts/` — Supporting scripts for the skill

## Usage

Register this skill with your OpenClaw agent:

```bash
pip install agentmesh-governance
```

Then use the scripts in `scripts/` to enforce governance from your agent:

```bash
# Check policy before a tool call
scripts/check-policy.sh --action "web_search" --tokens 1500 --policy policy.yaml

# Verify a peer agent's identity
scripts/verify-identity.sh --did "did:mesh:abc123" --message "hello" --signature "base64sig"

# Check trust score before delegation
scripts/trust-score.sh --agent "research-agent"
```

## Related

- Agent Marketplace
