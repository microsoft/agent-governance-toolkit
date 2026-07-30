# Microsoft AutoGen — Governance Extension

**Submission:** [microsoft/autogen#7212](https://github.com/microsoft/autogen/pull/7212)
**Status:** Open PR — awaiting review
**Type:** Contrib module (`autogen_ext.governance`)
**Date Submitted:** March 2, 2026

---

## Summary

Kernel-level governance extension for AutoGen multi-agent conversations using Agent-OS. Adds policy enforcement, content filtering, tool control, rate limiting, and audit trails as a drop-in extension.

## Problem

AutoGen enables powerful multi-agent conversations, but lacks built-in policy enforcement. Without governance:
- Agents can generate dangerous content (SQL injection, shell commands)
- No limits on tool calls or message volume per session
- No audit trail for compliance and debugging
- No way to restrict which tools specific agents can access

## Solution

Three classes in `autogen_ext.governance`:

### GovernancePolicy
Declarative configuration for all governance rules:
```python
policy = GovernancePolicy(
    max_tool_calls=10,
    blocked_patterns=["DROP TABLE", "rm -rf"],
    blocked_tools=["shell_execute"],
)
```

### GovernedAgent
Wraps any AutoGen agent with content filtering and tool control:
- Scans all messages against blocked patterns
- Enforces tool allowlists/blocklists
- Tracks tool call counts against limits
- Logs violations to audit trail

### GovernedTeam
Wraps multi-agent teams with session-level governance:
- Rate limits across entire conversation
- Aggregated audit log across all agents
- Violation callbacks for custom handling

## Example Usage

```python
from autogen_ext.governance import GovernedTeam, GovernancePolicy
from autogen_agentchat.agents import AssistantAgent

policy = GovernancePolicy(
    max_tool_calls=10,
    blocked_patterns=["DROP TABLE", "rm -rf"],
    blocked_tools=["shell_execute"],
)

team = GovernedTeam(agents=[analyst, reviewer], policy=policy)
result = await team.run("Analyze Q4 sales")
audit = team.get_audit_log()
```

## Value Proposition

| Feature | Without Extension | With Agent-OS |
|---------|------------------|---------------|
| Content Filtering | Manual | Automatic |
| Tool Limits | None | Configurable |
| Audit Trail | DIY | Built-in |
| Policy Violations | Runtime errors | Controlled handling |

## Integration Path

The extension works standalone, but can also integrate with the full Agent-OS kernel for:
- GDPR/HIPAA compliance policies
- Cost control limits
- Human-in-the-loop approval flows
- Cross-framework governance (same policies across AutoGen + CrewAI + ADK)

## Files Added

```
python/packages/autogen-ext/src/autogen_ext/governance/
├── __init__.py        # Public exports
├── _governance.py     # GovernedAgent, GovernedTeam, GovernancePolicy
└── README.md          # Documentation and examples
```

## Links

- [AutoGen](https://github.com/microsoft/autogen)
- [Agent OS](https://github.com/microsoft/agent-governance-toolkit)
- [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)
