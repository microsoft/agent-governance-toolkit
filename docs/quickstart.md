# Quick Start

Get from zero to governed AI agents in under 5 minutes.

## Install

```bash
pip install agent-governance-toolkit
```

!!! info "Other languages"
    **TypeScript:** `npm install @microsoft/agent-governance-sdk` ·
    **.NET:** `dotnet add package Microsoft.AgentGovernance` ·
    **Rust:** `cargo add agent-governance` ·
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

AGT works with any agent framework. Use the `govern()` wrapper on tool
functions, or use framework-specific adapters for deeper integration:

```python
# Option A: wrap any tool function (works everywhere)
from agentmesh.governance import govern
safe_tool = govern(my_langchain_tool.run, policy="policy.yaml")

# Option B: use a framework adapter (deeper integration)
from agent_os.integrations import LangChainKernel
kernel = LangChainKernel(policy_directory="policies/")
```

Framework adapters available for: **LangChain**, **OpenAI Agents SDK**,
**AutoGen**, **CrewAI**, **Google ADK**, **Semantic Kernel**, **LlamaIndex**,
**Anthropic**, **Gemini**, **Mistral**, **PydanticAI**, **smolagents**, and more.

```bash
pip install agentmesh-langchain       # LangChain
pip install openai-agents-agentmesh   # OpenAI Agents SDK
pip install crewai-agentmesh          # CrewAI
pip install adk-agentmesh             # Google ADK
```

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
