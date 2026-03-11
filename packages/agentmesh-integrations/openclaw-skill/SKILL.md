---
name: agentmesh-governance
description: >
  AI agent governance, trust scoring, and policy enforcement powered by AgentMesh.
  Activate when: (1) user wants to enforce token limits, tool restrictions, or content
  policies on agent actions, (2) checking an agent's trust score before delegation or
  collaboration, (3) verifying agent identity with Ed25519 cryptographic DIDs,
  (4) auditing agent actions with tamper-evident hash chain logs,
  (5) user asks about agent safety, governance, compliance, or trust.
  Enterprise-grade: 1,600+ tests, merged into Dify (65K★), LlamaIndex (47K★),
  Microsoft Agent-Lightning (15K★).
version: 1.0.0
metadata:
  openclaw:
    requires:
      bins:
        - python3
        - pip
    emoji: "🛡️"
    homepage: https://github.com/imran-siddique/agentmesh-integrations/tree/master/openclaw-skill
---

# AgentMesh Governance — Trust & Policy for OpenClaw Agents

Zero-trust governance layer for OpenClaw agents. Enforce policies, verify identities,
score trust, and maintain tamper-evident audit logs — all from your agent's command line.

## Setup

Install the AgentMesh governance CLI:

```bash
pip install agentmesh-governance
```

> If `agentmesh-governance` is not yet on PyPI, install directly from source:
> ```bash
> pip install "agentmesh @ git+https://github.com/imran-siddique/agent-mesh.git"
> ```

## Scripts

All scripts are in `scripts/`. They wrap the governance engine and output JSON results.

### Check Policy Compliance

Evaluate an action against a governance policy before execution:

```bash
scripts/check-policy.sh --action "web_search" --tokens 1500 --policy policy.yaml
```

Returns JSON with `allowed: true/false`, any violations, and recommendations.
Use this **before** executing any tool call to enforce limits.

### Get Trust Score

Check an agent's current trust score (0.0 – 1.0):

```bash
scripts/trust-score.sh --agent "research-agent"
```

Returns the composite trust score with breakdown across 5 dimensions:
policy compliance, resource efficiency, output quality, security posture,
collaboration health.

### Verify Agent Identity

Verify an agent's Ed25519 cryptographic identity before trusting its output:

```bash
scripts/verify-identity.sh --did "did:agentmesh:abc123" --message "hello" --signature "base64sig"
```

Returns `verified: true/false`. Use when receiving data from another agent.

### Record Interaction

Update trust scores after collaborating with another agent:

```bash
scripts/record-interaction.sh --agent "writer-agent" --outcome success
scripts/record-interaction.sh --agent "writer-agent" --outcome failure --severity 0.1
```

Success adds +0.01 to trust score. Failure subtracts the severity value.
Agents dropping below the minimum threshold (default 0.5) are auto-blocked.

### Audit Log

View tamper-evident audit trail with hash chain verification:

```bash
scripts/audit-log.sh --last 20
scripts/audit-log.sh --agent "research-agent" --verify
```

The `--verify` flag checks hash chain integrity — any tampering is detected.

### Generate Identity

Create a new Ed25519 cryptographic identity (DID) for your agent:

```bash
scripts/generate-identity.sh --name "my-agent" --capabilities "search,summarize,write"
```

Returns your agent's DID, public key, and capability manifest.

## Policy File Format

Create a `policy.yaml` to define governance rules:

```yaml
name: production-policy
max_tokens: 4096
max_tool_calls: 10
allowed_tools:
  - web_search
  - file_read
  - summarize
blocked_tools:
  - shell_exec
  - file_delete
blocked_patterns:
  - "rm -rf"
  - "DROP TABLE"
  - "BEGIN CERTIFICATE"
confidence_threshold: 0.7
require_human_approval: false
```

## When to Use This Skill

- **Before tool execution**: Run `check-policy.sh` to enforce limits
- **Before trusting another agent's output**: Run `verify-identity.sh`
- **After collaboration**: Run `record-interaction.sh` to update trust
- **Before delegation**: Check `trust-score.sh` — don't delegate to agents below 0.5
- **For compliance**: Run `audit-log.sh --verify` to prove execution integrity
- **On setup**: Run `generate-identity.sh` to create your agent's DID

## What It Enforces

| Policy | Description |
|--------|-------------|
| Token limits | Cap per-action and per-session token usage |
| Tool allowlists | Only explicitly permitted tools can execute |
| Tool blocklists | Dangerous tools are blocked regardless |
| Content patterns | Block regex patterns (secrets, destructive commands, PII) |
| Trust thresholds | Minimum trust score required for delegation |
| Human approval | Gate critical actions behind human confirmation |

## Architecture

This skill bridges the OpenClaw agent runtime with the [AgentMesh](https://github.com/imran-siddique/agent-mesh)
governance engine:

```
OpenClaw Agent → SKILL.md scripts → AgentMesh Engine
                                     ├── GovernancePolicy (enforcement)
                                     ├── TrustEngine (5-dimension scoring)
                                     ├── AgentIdentity (Ed25519 DIDs)
                                     └── hash-chainAuditChain (tamper-evident logs)
```

Part of the [Agent Ecosystem](https://imran-siddique.github.io):
[AgentMesh](https://github.com/imran-siddique/agent-mesh) ·
[Agent OS](https://github.com/imran-siddique/agent-os) ·
[Agent SRE](https://github.com/imran-siddique/agent-sre)
