# ADK AgentMesh — Governance for Google ADK Agents

> [!IMPORTANT]
> **Public Preview** — The `adk-agentmesh` package on PyPI is a Microsoft-signed
> public preview release. APIs may change before GA.

Policy enforcement, trust verification, and audit trails for
[Google ADK](https://github.com/google/adk-python) agents — powered by the
[Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit).

## What It Does

`adk-agentmesh` implements the `PolicyEvaluator` protocol
([google/adk-python#4897](https://github.com/google/adk-python/issues/4897))
backed by the Agent Governance Toolkit's deterministic policy engine.

- **Tool-level governance** — block, allow-list, or require approval for any ADK tool call
- **Rate limiting** — cap tool calls per agent per session
- **Delegation scope** — monotonic narrowing ensures sub-agents never exceed parent permissions
- **Structured audit** — every decision is logged with verdict, rule, and timestamp

## Installation

```bash
pip install adk-agentmesh
```

## Quick Start

### 1. Define a governance policy

Create a YAML policy file (see [`examples/policies/adk-governance.yaml`](../../../examples/policies/adk-governance.yaml)):

```yaml
adk_governance:
  blocked_tools:
    - execute_shell
    - delete_database
  max_tool_calls: 100
  require_approval_for:
    - send_email
    - deploy_service
```

### 2. Wire into your ADK agent

```python
from adk_agentmesh import ADKPolicyEvaluator, GovernanceCallbacks

# Load policy
evaluator = ADKPolicyEvaluator.from_config("policies/adk-governance.yaml")
callbacks = GovernanceCallbacks(evaluator)

# Attach to ADK agent
from google.adk.agents import LlmAgent

agent = LlmAgent(
    model="gemini-2.0-flash",
    name="my-governed-agent",
    before_tool_callback=callbacks.before_tool,
    after_tool_callback=callbacks.after_tool,
    before_agent_callback=callbacks.before_agent,
    after_agent_callback=callbacks.after_agent,
)
```

### 3. Or use the evaluator directly

```python
import asyncio
from adk_agentmesh import ADKPolicyEvaluator

evaluator = ADKPolicyEvaluator(
    blocked_tools=["execute_shell"],
    max_tool_calls=50,
    require_approval_for=["send_email"],
)

decision = asyncio.run(
    evaluator.evaluate_tool_call(
        tool_name="search_web",
        tool_args={"query": "latest news"},
        agent_name="research-agent",
    )
)
print(decision.verdict)  # Verdict.ALLOW
```

## ADK Lifecycle Mapping

| ADK Hook | Governance Check |
|----------|-----------------|
| `before_tool_callback` | Policy evaluation, rate limiting, tool blocking |
| `after_tool_callback` | Audit logging |
| `before_agent_callback` | Delegation scope check |
| `after_agent_callback` | Delegation audit |

## Delegation Scope Narrowing

Sub-agents automatically receive narrowed permissions:

```python
from adk_agentmesh import DelegationScope

parent_scope = DelegationScope(
    allowed_tools=["search_web", "read_file", "write_file"],
    max_tool_calls=100,
    max_depth=3,
)

# Child gets strictly fewer permissions
child_scope = parent_scope.narrow(
    allowed_tools=["search_web", "read_file"],
    read_only=True,
)
# child_scope.max_depth == 2 (always decrements)
# child_scope.read_only == True (once set, cannot be unset)
```

## Audit Events

Every governance decision is recorded:

```python
evaluator = ADKPolicyEvaluator(blocked_tools=["dangerous_tool"])

# ... after agent runs ...

for entry in evaluator.get_audit_log():
    print(entry["event"], entry["timestamp"])
```

For structured audit handling:

```python
from adk_agentmesh import AuditEvent, LoggingAuditHandler

handler = LoggingAuditHandler()
event = AuditEvent(
    event_type="tool_call_denied",
    agent_name="my-agent",
    tool_name="execute_shell",
    verdict="deny",
    reason="Tool is blocked by policy",
)
handler.handle(event)
```

## Sample Policy

See the full sample policy at
[`examples/policies/adk-governance.yaml`](../../../examples/policies/adk-governance.yaml).

## Links

- [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)
- [Google ADK](https://github.com/google/adk-python)
- [PolicyEvaluator proposal (google/adk-python#4897)](https://github.com/google/adk-python/issues/4897)

## License

MIT
