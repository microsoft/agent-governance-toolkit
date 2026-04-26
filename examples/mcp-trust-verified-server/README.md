<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# MCP Trust-Verified Server

> **DEMO ONLY.** This example accepts `agent_did` and `trust_score` as
> client-supplied tool arguments. In production, agent identity and trust
> scores must come from a verified source (identity registry, trust server)
> — never from the calling agent itself.

A standalone MCP server where every tool call is gated by AgentMesh trust verification. Demonstrates how to use `TrustProxy` and `MCPSecurityScanner` to enforce per-tool trust thresholds, capability requirements, and rate limits.

## What it shows

- Three tools with escalating trust requirements (300 / 600 / 800)
- Capability-based access control (`fs_write`, `db_query`)
- Rate limiting on sensitive tools (10 calls/min for `query_database`)
- Tool fingerprinting via `MCPSecurityScanner` for rug-pull detection
- Fail-closed authorization (errors default to deny)
- Audit logging of every authorization decision

## Prerequisites

```bash
pip install mcp mcp-trust-proxy agent-os-kernel
```

## How to run

```bash
python examples/mcp-trust-verified-server/server.py
```

## MCP client configuration

Add the server to your MCP client configuration (Claude Desktop, Cursor, etc.):

```json
{
  "mcpServers": {
    "trust-verified": {
      "command": "python",
      "args": ["examples/mcp-trust-verified-server/server.py"]
    }
  }
}
```

## Related

- [MCP Trust Integration Guide](../../docs/integrations/mcp-trust-guide.md)
- [MCP Trust Proxy](../../agent-governance-python/agentmesh-integrations/mcp-trust-proxy/)
- [MCP Trust Server](../../agent-governance-python/agent-mesh/packages/mcp-trust-server/)
