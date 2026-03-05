# CrewAI — Governance Integration

**Submissions:**
- [crewAIInc/crewAI#4384](https://github.com/crewAIInc/crewAI/pull/4384) — Core governance module (Open PR)
- [crewAIInc/crewAI-examples#300](https://github.com/crewAIInc/crewAI-examples/pull/300) — Safety governance example (Open PR)
**Type:** Contrib module (`crewai.governance`)
**Date Submitted:** March 2, 2026

---

## Summary

Kernel-level governance for CrewAI workflows using Agent-OS. Adds content filtering, tool control, iteration limits, and audit trails. Includes both a core module PR and a worked example PR.

## Problem

CrewAI enables powerful multi-agent crews, but lacks built-in policy enforcement:
- Agents can call any tool without restriction
- No iteration or tool call limits per crew run
- Output sanitization is manual
- No compliance-grade audit logging

## Solution: `crewai.governance` Module

### GovernancePolicy
```python
policy = GovernancePolicy(
    max_tool_calls=20,
    max_iterations=15,
    blocked_patterns=["DROP TABLE", "rm -rf"],
    blocked_tools=["shell_tool"],
)
```

### GovernedCrew
Wraps any CrewAI `Crew` with governance enforcement:
```python
from crewai.governance import GovernedCrew, GovernancePolicy

governed_crew = GovernedCrew(crew, policy)
result = governed_crew.kickoff()
print(f"Violations: {len(governed_crew.violations)}")
```

### Key Features
- **Content filtering** — Blocked regex patterns checked on all agent output
- **Tool control** — Allow/deny lists per policy, unknown tool blocking
- **Iteration limits** — Cap total iterations to prevent runaway crews
- **Output sanitization** — Max length limits, blocked output patterns
- **Audit trail** — Full logging of all governance decisions
- **Violation callbacks** — Custom handling (log, block, or escalate)
- **Post-run timeout recording** — Detects and logs timeout violations

## Value Proposition

| Feature | Without Module | With Agent-OS |
|---------|---------------|---------------|
| Content Filtering | Manual | Automatic |
| Tool Limits | None | Configurable |
| Audit Trail | DIY | Built-in |
| Violation Handling | Runtime errors | Controlled callbacks |

## Files Added (Core PR #4384)

```
src/crewai/governance/
├── __init__.py    # Public exports
├── _kernel.py     # GovernedAgent, GovernedCrew, GovernancePolicy
└── README.md      # Documentation
```

## Example PR (#300)

End-to-end example in `crewAI-examples` demonstrating:
- YAML policy configuration
- Governed crew with 3 agents
- Tool restriction enforcement
- Audit trail generation
- Violation handling

## Links

- [CrewAI](https://github.com/crewAIInc/crewAI)
- [Agent OS](https://github.com/microsoft/agent-governance-toolkit)
- [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)
