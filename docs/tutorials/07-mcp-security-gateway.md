---
title: MCP Security Gateway
last_reviewed: 2026-07-12
owner: docs-team
---

# MCP Security Gateway

`MCPGateway` combines native ACS policy evaluation with MCP-specific host
controls.

## Create the gateway

```python
from agt.policies import AgtRuntime
from agent_os.mcp_gateway import MCPGateway

runtime = AgtRuntime("policies/mcp-manifest.yaml")
gateway = MCPGateway(
    runtime,
    denied_tools=["shell"],
    sensitive_tools=["deploy"],
    rate_limit=100,
)
```

The manifest controls policy bindings and the tool catalog. Gateway arguments
control host deny lists, approval routing, sanitization, rate limiting, metrics,
response scanning, and audit sinks.

## Evaluate a call

```python
allowed, reason = gateway.intercept_tool_call(
    agent_id="agent-1",
    tool_name="search",
    params={"query": "status"},
)
```

The gateway applies host checks and native `pre_tool_call` evaluation before
the tool side effect. Unexpected evaluation or approval errors fail closed.

## Sensitive tools

Provide an approval callback for tools listed in `sensitive_tools`.

```python
from agent_os.mcp_gateway import ApprovalStatus

def approve(agent_id: str, tool_name: str, parameters: dict) -> ApprovalStatus:
    if tool_name == "deploy" and parameters.get("environment") == "production":
        return ApprovalStatus.DENIED
    return ApprovalStatus.APPROVED

gateway = MCPGateway(
    runtime,
    sensitive_tools=["deploy"],
    approval_callback=approve,
)
```

## Response scanning

Pass an `MCPResponseScanner` and choose `ResponsePolicy.BLOCK`,
`ResponsePolicy.SANITIZE`, or `ResponsePolicy.LOG`. Credential and PII leaks
remain blocked when sanitization cannot safely remove them.

## Wrap server configuration

```python
config = MCPGateway.wrap_mcp_server(
    {"command": "python", "args": ["-m", "my_server"]},
    denied_tools=["shell"],
    sensitive_tools=["deploy"],
    rate_limit=50,
)
```

`wrap_mcp_server` does not embed policy. Construct the gateway with the native
runtime when starting the governed proxy.

## Audit

Persisted audit payloads are redacted. Native policy details are available
through the restricted `PolicyEvaluation.audit_record()` contract.

See [MCP Trust Guide](../integrations/mcp-trust-guide.md) and
[MCP Governance](policy-as-code/mcp-governance.md).
