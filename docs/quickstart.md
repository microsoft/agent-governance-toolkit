---
title: Quick Start
last_reviewed: 2026-07-31
owner: docs-team
---

# Quick Start

Govern an AI agent in under five minutes.

!!! important "Public Preview"
    APIs may change before general availability. The canonical package names
    and extras below match the current published package family.

## Install

```bash
pip install agent-governance-toolkit[full]
```

The `[full]` extra supplies the convenience wrapper and framework integrations
used below. The base `agent-governance-toolkit` wheel installs the compliance
CLI only.

For the canonical AGT 5 policy host API, also install `agt-policies`. It
includes the Agent Control Specification Python SDK:

```bash
pip install agt-policies
```

## Choose your policy path

| Path | Use it when | Runtime |
|---|---|---|
| `agentmesh.governance.govern()` | You want the shortest working application integration | AgentMesh convenience policy engine |
| `agt.policies.AgtRuntime` | You are building new host, adapter, gateway, or platform enforcement | ACS, the canonical AGT 5 policy decision layer |

The APIs use different runtimes. The current `govern()` wrapper does not call
ACS. Existing applications can keep the wrapper; new policy hosts should use ACS
through its portable snapshot and verdict contract.

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

On each call, `safe_tool` evaluates the YAML policy, logs the decision to an
audit trail, and raises `GovernanceDenied` when the policy blocks the action.

## Write a convenience-wrapper policy

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

## Use ACS for new policy host code

ACS is stateless. At each intervention point, the host sends a complete
snapshot, receives a normalized verdict, and applies it:

```python
from agt.policies import SnapshotBuilder
from agt.policies.runtime import AgtRuntime

runtime = AgtRuntime("manifest.yaml")
session = SnapshotBuilder(agent_id="researcher", session_id="session-1")

result = runtime.evaluate_intervention_point(
    "pre_tool_call",
    session.pre_tool_call(
        tool_name="send_email",
        args={"to": "partner@example.net", "body": "Status update"},
    ),
)

if not result.allowed:
    raise PermissionError(result.reason)
```

The manifest binds a policy and target to `pre_tool_call`. ACS returns `allow`,
`warn`, `deny`, `escalate`, or `transform`; the host executes, blocks, requests
approval, or applies a transformed target.

Run `examples/acs-email-tool` from a repository checkout, or follow the
[ACS tutorial](tutorials/55-agent-control-specification.md).

## Use with your framework

For framework tools, `govern()` remains the stable starting point and accepts
any callable:

```python
from agentmesh.governance import govern
safe_tool = govern(my_langchain_tool.run, policy="policy.yaml")
```

AGT works with any agent framework through the callable wrapper. Install an
adapter extra when you need framework-specific hooks. Canonical extras cover
**LangChain**, **CrewAI**, **OpenAI Agents**, **LangGraph**, **LlamaIndex**,
**Haystack**, **PydanticAI**, and **Google ADK**.

```bash
pip install "agent-governance-toolkit[langchain]"
pip install "agent-governance-toolkit[crewai]"
pip install "agent-governance-toolkit[openai-agents]"
pip install "agent-governance-toolkit[adk]"
```

See the [package guide](packages/index.md#framework-integrations) for direct
integration-package installs and the complete extra list.

## Verify OWASP coverage

Run the OWASP Agentic Security Threats compliance check:

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

## Next steps

| What | Where |
|------|-------|
| Build on the canonical decision layer | [Agent Control Specification](tutorials/55-agent-control-specification.md) |
| Learn policy writing | [Policy Engine Basics](tutorials/01-policy-engine.md) |
| Add identity & trust | [Trust & Identity](tutorials/02-trust-and-identity.md) |
| Integrate your framework | [Framework Integrations](tutorials/03-framework-integrations.md) |
| Govern MCP servers | [MCP Security Gateway](tutorials/07-mcp-security-gateway.md) |
| Add SLOs and monitoring | [Agent Reliability](tutorials/05-agent-reliability.md) |
| Full tutorial catalog | [All Tutorials](tutorials/index.md) |
