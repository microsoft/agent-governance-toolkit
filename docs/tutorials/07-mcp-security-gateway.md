---
title: MCP Security Gateway
last_reviewed: 2026-11-25
owner: docs-team
---

# MCP Security Gateway

`MCPGateway` combines native ACS policy evaluation with MCP-specific host
controls.

## Create the gateway

```python
from agent_control_specification import AgentControl
from agent_os.mcp_gateway import MCPGateway

runtime = AgentControl.from_path("policies/mcp-manifest.yaml")
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

## MCP 2026-07-28 requests

MCP `2026-07-28` is stateless: every request carries its protocol version,
client info and client capabilities in `params._meta`, and Streamable HTTP
mirrors the method, the tool/prompt name or resource URI, and any
`x-mcp-header` tool parameters into `Mcp-Method`, `Mcp-Name` and
`Mcp-Param-*` headers. A proxy that routes on headers but evaluates the body
must reject any disagreement. Pass the raw request to `intercept_request`:

```python
allowed, reason = gateway.intercept_request(
    agent_id="agent-1",
    message=jsonrpc_request,          # the parsed JSON-RPC body
    headers=dict(http_request.headers),  # or None for stdio
    tool_input_schema=tool["inputSchema"],
)
```

The gateway rejects an unsupported protocol version, missing `_meta` fields,
missing or mismatched `MCP-Protocol-Version` / `Mcp-Method` / `Mcp-Name` /
`Mcp-Param-*` headers (Base64-encoded values are decoded first) and header
values with control characters, before any policy evaluation. For
`tools/call` it then runs `intercept_tool_call` and records the validated W3C
`traceparent` from `_meta` on the audit entry. Legacy `2025-11-25` requests are
still accepted. The helpers are in `agent_os.mcp_stateless`.

### Multi round-trip (`input_required`) results

Servers no longer send sampling, elicitation or roots requests to the client.
They return `resultType: "input_required"` with `inputRequests`. Check those
results before the client acts on them:

```python
decision = gateway.intercept_input_required("agent-1", "search", result)
if not decision.allowed:
    raise PermissionError(decision.reason)
```

- `sampling/createMessage` and `roots/list` are denied unless the gateway was
  created with `allow_sampling_requests=True` / `allow_roots_requests=True`
  (both features are deprecated in `2026-07-28`).
- Form-mode elicitation that asks for a password, token, API key or similar
  field is denied; its text is scanned like a tool response.
- URL-mode elicitation needs `approval_callback` to approve the URL; without a
  callback it is denied.
- `requestState` is opaque and is never inspected or modified.

## Audit

Persisted audit payloads are redacted. Native policy details are available
through the restricted `PolicyEvaluation.audit_record()` contract.

See [MCP Trust Guide](../integrations/mcp-trust-guide.md) and
[MCP Governance](policy-as-code/mcp-governance.md).
