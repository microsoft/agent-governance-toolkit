# Tutorial: Policy-as-Code for AI Agents

A step-by-step guide to governing AI agents with declarative policies, progressing
from basic allow/deny rules to production-grade policy management.

**Prerequisites:** Python 3.9+, basic YAML and Python familiarity.

## Installation

```bash
pip install agent-os-kernel[full]
```

## Chapters

| Chapter | Topic | What You'll Learn |
|---------|-------|-------------------|
| [01 — Your First Policy](01-your-first-policy.md) | Allow/deny basics | Write a YAML policy and evaluate it with Python |
| [02 — Capability Scoping](02-capability-scoping.md) | Restricting tool access by agent role | Give different agents different permissions |
| [03 — Rate Limiting](03-rate-limiting.md) | Preventing runaway agents | Set limits on how many actions an agent can take |
| [04 — Conditional Policies](04-conditional-policies.md) | Policy composition and conflict resolution | Layer base + environment policies with conflict strategies |
| [05 — Approval Workflows](05-approval-workflows.md) | Human-in-the-loop for sensitive actions | Route dangerous actions to a human before execution |
| [06 — Policy Testing](06-policy-testing.md) | Systematic validation with test matrices | Test every role + action + environment combination |
| [07 — Policy Versioning](07-policy-versioning.md) | Safe rollout of policy changes | Compare v1 vs v2 behavior, catch regressions before deploying |

## Running Examples

Every chapter has a matching Python script in [`examples/`](examples/) that you
can run directly:

```bash
cd docs/tutorials/policy-as-code
python examples/01_first_policy.py
```

## Related Resources

- [Tutorial 01 — Policy Engine](../01-policy-engine.md) — Full YAML syntax and operator reference
- [Policy Schema Source](../../../agent-governance-python/agent-os/src/agent_os/policies/schema.py) — PolicyDocument and PolicyRule models
- [QUICKSTART.md](../../../QUICKSTART.md) — 10-minute getting started guide

## Supplemental Guides

- [MCP Governance Policies](mcp-governance.md) — Governing MCP tool access with the MCP proxy, trust-gated components, and OWASP-aligned rules
