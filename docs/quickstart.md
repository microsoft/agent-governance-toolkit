---
title: Quick Start
last_reviewed: 2026-07-15
owner: docs-team
---

# Quick Start

Get from zero to governed AI agents in under 5 minutes.

!!! important "Public Preview"
    APIs may change before general availability. The canonical package names
    and extras below match the current published package family.

## Install

```bash
pip install agent-governance-toolkit[full]
```

Use the `[full]` extra for these examples. The base `agent-governance-toolkit`
wheel installs the compliance CLI only; the governance modules shown below come
from the consolidated core distribution. The `agentmesh` examples remain the
current wrapper API. The advanced `agent_os.policies` example is legacy
compatibility: importing `agent_os` currently emits a `DeprecationWarning`
because the old `agent-os-kernel` distribution is deprecated. Use
`agent-governance-toolkit-core` (or the `[full]` extra that includes it) as the
replacement distribution, and prefer the AGT 5 `agt-policies`/ACS APIs for new
policy-engine host code.

!!! info "Other languages"
    **TypeScript:** `npm install @microsoft/agent-governance-sdk` ·
    **.NET:** `dotnet add package Microsoft.AgentGovernance` ·
    **Rust:** `cargo add agentmesh` ·
    **Go:** `go get github.com/microsoft/agent-governance-toolkit/agent-governance-golang`

## Govern any tool in 2 lines

```python
from agentmesh.governance import govern

safe_tool = govern(my_tool, policy="policy.yaml")
```

That's it. `safe_tool` evaluates your YAML policy on every call, logs the
decision to an audit trail, and raises `GovernanceDenied` if the action is
blocked.

## Write a policy

Create `policy.yaml`:

```yaml
apiVersion: governance.toolkit/v1
name: agent-safety
default_action: allow
rules:
  - name: block-dangerous-tools
    condition: "action.type in ['delete_file', 'shell_exec', 'drop_table']"
    action: deny
    description: "Destructive operations are blocked"
    priority: 100

  - name: block-pii
    condition: "input_text matches '\\b\\d{3}-\\d{2}-\\d{4}\\b'"
    action: deny
    description: "SSN pattern detected"
    priority: 90

  - name: approve-sends
    condition: "action.type == 'send_email'"
    action: require_approval
    approvers: ["security-team"]
    priority: 50
```

## Try it

```python
from agentmesh.governance import govern

def web_search(query: str) -> str:
    return f"Results for: {query}"

def delete_file(path: str) -> str:
    return f"Deleted: {path}"

safe_search = govern(web_search, policy="policy.yaml")
safe_delete = govern(delete_file, policy="policy.yaml")

# This works
print(safe_search(query="AI governance news"))

# This raises GovernanceDenied
print(safe_delete(path="/etc/passwd"))
```

```
Results for: AI governance news

GovernanceDenied: Action denied by policy rule 'block-dangerous-tools':
  Destructive operations are blocked
```

## Use with your framework

AGT works with any agent framework. The stable starting point is the `govern()`
wrapper on tool functions:

```python
from agentmesh.governance import govern
safe_tool = govern(my_langchain_tool.run, policy="policy.yaml")
```

Install an optional adapter extra when you need framework-specific hooks.
Canonical extras currently cover **LangChain**, **CrewAI**, **OpenAI Agents**,
**LangGraph**, **LlamaIndex**, **Haystack**, **PydanticAI**, and **Google ADK**.

```bash
pip install "agent-governance-toolkit[langchain]"
pip install "agent-governance-toolkit[crewai]"
pip install "agent-governance-toolkit[openai-agents]"
pip install "agent-governance-toolkit[adk]"
```

See the [package guide](packages/index.md#framework-integrations) for direct
integration-package installs and the complete extra list.

## Verify OWASP coverage

Check your deployment covers the OWASP Agentic Security Threats:

```bash
agt verify
```

```
Agent Governance Toolkit — OWASP ASI 2026 Compliance
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ASI-01 Agent Goal Hijack             ✅ Covered
  ASI-02 Tool Misuse & Exploitation    ✅ Covered
  ASI-03 Identity & Privilege Abuse    ✅ Covered
  ...
  10/10 risks covered
```

## Full example: PolicyEvaluator API

For teams that need fine-grained control beyond YAML, the `PolicyEvaluator`
API gives you programmatic policy construction:

```python
from agent_os.policies import PolicyEvaluator
from agent_os.policies.schema import (
    PolicyDocument, PolicyRule, PolicyCondition,
    PolicyAction, PolicyOperator, PolicyDefaults,
)

policy = PolicyDocument(
    name="agent-safety",
    version="1.0",
    description="Safety policy for the research agent",
    defaults=PolicyDefaults(action=PolicyAction.ALLOW),
    rules=[
        PolicyRule(
            name="block-dangerous-tools",
            condition=PolicyCondition(
                field="tool_name",
                operator=PolicyOperator.IN,
                value=["delete_file", "shell_exec", "execute_code"],
            ),
            action=PolicyAction.DENY,
            message="Tool is blocked by safety policy",
            priority=100,
        ),
    ],
)

evaluator = PolicyEvaluator(policies=[policy])
decision = evaluator.evaluate({"tool_name": "delete_file", "agent_id": "my-agent"})
print(f"Allowed: {decision.allowed}")  # False
print(f"Reason: {decision.reason}")    # Tool is blocked by safety policy
```

## Next steps

| What | Where |
|------|-------|
| Learn policy writing | [Policy Engine Basics](tutorials/01-policy-engine.md) |
| Add identity & trust | [Trust & Identity](tutorials/02-trust-and-identity.md) |
| Integrate your framework | [Framework Integrations](tutorials/03-framework-integrations.md) |
| Govern MCP servers | [MCP Security Gateway](tutorials/07-mcp-security-gateway.md) |
| Add SLOs and monitoring | [Agent Reliability](tutorials/05-agent-reliability.md) |
| Full tutorial catalog | [All Tutorials](tutorials/index.md) |
