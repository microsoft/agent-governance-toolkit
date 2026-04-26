# MCP Trust Proxy

MCP proxy server that wraps any MCP tool with AgentMesh trust verification.

Agents must present a valid identity (DID) and meet trust thresholds before accessing tools.

## Features

- **TrustProxy**: Intercepts MCP tool calls and verifies agent identity
- **ToolPolicy**: Per-tool trust score thresholds and capability requirements
- **AuditLog**: Full audit trail of all tool access attempts

## Quick Start

```python
from mcp_trust_proxy import TrustProxy, ToolPolicy

proxy = TrustProxy(
    default_min_trust=300,
    tool_policies={
        "file_write": ToolPolicy(min_trust=800, required_capabilities=["fs_write"]),
        "shell_exec": ToolPolicy(min_trust=900, blocked=True),
    },
)

# Agent requests tool access
result = proxy.authorize(
    agent_did="did:mesh:agent-1",
    agent_trust_score=600,
    agent_capabilities=["fs_read", "search"],
    tool_name="file_read",
)
assert result.allowed
```
