# Anthropic — Governance Integrations

**Submissions:**
- [anthropics/skills#424](https://github.com/anthropics/skills/pull/424) — Agent governance skill (Open PR)
- [anthropics/claude-plugins-official#415](https://github.com/anthropics/claude-plugins-official/issues/415) — Claude plugin proposal (Open Issue)
- [anthropics/claude-cookbooks#384](https://github.com/anthropics/claude-cookbooks/issues/384) — Governance cookbook (Open Issue)
**Date Submitted:** March 2, 2026

---

## Overview

Three complementary submissions to the Anthropic ecosystem providing governance patterns for Claude-based agent systems. Each targets a different integration point.

---

## 1. Agent Governance Skill (PR #424)

**Status:** Open PR — awaiting review
**Closes:** [anthropics/skills#412](https://github.com/anthropics/skills/issues/412) (invited by @BennyTheBuilder)

### What's Included

| Pattern | Description |
|---------|-------------|
| **Governance Policy Model** | Deny-by-default, tri-state decisions (allow/deny/review), YAML-based |
| **Policy Composition** | Org → Team → Agent layering, stricter always wins |
| **Threat Detection** | 5 categories: data exfiltration, prompt injection, privilege escalation, credential harvesting, destructive operations |
| **Trust Scoring** | Decay-based scores with asymmetric reward/penalty for multi-agent delegation |
| **Audit Trail** | Append-only, tamper-evident SHA-256 Merkle chain |
| **Tool-Level Governance** | Single decorator adds policy enforcement + audit to any tool function |
| **Framework Integration** | Examples for PydanticAI, CrewAI, OpenAI Agents SDK, Google ADK |

### Design Decisions (per @BennyTheBuilder feedback)
- Leads with the **policy model** (not frameworks or decorators)
- Includes a **minimal working example** (copy-paste YAML + Python)
- Audit trail design is **front-and-center** (Merkle chain with what/who/when/why)
- **Fail-closed everywhere** — any evaluation error returns deny

---

## 2. Claude Plugin Proposal (Issue #415)

**Status:** Open issue — concept validation stage

### Plugin Structure
```
agent-governance/
├── .claude-plugin/plugin.json
├── .mcp.json                    # Governance MCP server
├── commands/
│   ├── governance-check.md      # /governance-check — audit current project
│   └── policy-init.md           # /policy-init — scaffold governance config
├── agents/
│   └── governance-reviewer.md   # Agent that reviews code for governance
├── skills/
│   └── agent-governance/SKILL.md
└── README.md
```

### MCP Server Tools
- `governance/check_policy` — Validate tool calls against policies
- `governance/detect_threats` — Scan code/prompts for threat patterns
- `governance/audit_query` — Query audit trail for compliance

---

## 3. Governance Cookbook (Issue #384)

**Status:** Open issue — awaiting approval

### Proposed Notebook: `misc/agent_governance.ipynb`

**Sections:**
1. Introduction: Why Agent Governance Matters
2. Defining a Governance Policy (YAML-based, composable)
3. Tool Policy Enforcement (allowlists, blocklists, argument validation)
4. Threat Detection Patterns (5 categories with Claude-based classification)
5. Trust Scoring for Multi-Agent Delegation
6. Building Append-Only Audit Trails
7. Putting It Together: A Governed Agent Pipeline

### Code Preview
```python
import anthropic

async def governed_tool_use(client, policy, messages, tools):
    response = await client.messages.create(
        model="claude-sonnet-4-20250514",
        messages=messages, tools=tools,
    )
    for block in response.content:
        if block.type == "tool_use":
            if block.name in policy.blocked_tools:
                raise GovernanceViolation(f"Tool '{block.name}' blocked")
            if policy.threat_detection:
                threats = detect_threats(block.input)
                if threats:
                    raise GovernanceViolation(f"Threat: {threats}")
    return response
```

## Links

- [Anthropic Skills](https://github.com/anthropics/skills)
- [Claude Plugins](https://github.com/anthropics/claude-plugins-official)
- [Claude Cookbooks](https://github.com/anthropics/claude-cookbooks)
- [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)
