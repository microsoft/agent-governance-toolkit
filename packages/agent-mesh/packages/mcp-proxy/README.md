# 🛡️ AgentMesh MCP Proxy

> **Anthropic built the USB port. AgentMesh is the Firewall.**

A security proxy for Model Context Protocol (MCP) servers. Adds authentication, rate limiting, policy enforcement, and audit logging to any MCP server with **zero code changes**.

## 🎯 The Problem

MCP is brilliant for connecting AI agents to tools, but it currently has:
- ❌ No authentication
- ❌ No rate limiting
- ❌ No access control
- ❌ No audit logging

**Any prompt injection can call any tool with any arguments.**

## ✅ The Solution

```bash
# Before (vulnerable)
npx @anthropic/mcp-server-filesystem /path/to/files

# After (secured)
npx agentmesh-mcp-proxy protect @anthropic/mcp-server-filesystem /path/to/files
```

That's it. One command wraps any MCP server with enterprise security.

## 🚀 Quick Start

### Installation

```bash
npm install -g agentmesh-mcp-proxy
```

### Protect Any MCP Server

```bash
# Wrap the filesystem MCP server
agentmesh protect @anthropic/mcp-server-filesystem /home/user/documents

# Wrap a custom MCP server
agentmesh protect ./my-custom-mcp-server.js

# With a policy file
agentmesh protect --policy=strict.yaml @anthropic/mcp-server-filesystem /tmp
```

### Claude Desktop Configuration

```json
{
  "mcpServers": {
    "secure-filesystem": {
      "command": "npx",
      "args": [
        "agentmesh-mcp-proxy",
        "protect",
        "--policy=strict",
        "@anthropic/mcp-server-filesystem",
        "/home/user/documents"
      ]
    }
  }
}
```

## 🔒 Security Features

### 1. Policy Enforcement

Define which tools can be called and with what arguments:

```yaml
# policies/strict.yaml
version: "1.0"
mode: enforce  # or "shadow" for testing

rules:
  # Block dangerous tools
  - tool: "run_shell"
    action: deny
    reason: "Shell access not permitted"

  # Restrict file access
  - tool: "read_file"
    action: allow
    conditions:
      - path_starts_with: "/home/user/documents"
      - path_not_contains: [".env", "secrets", "credentials"]

  # Rate limit expensive operations
  - tool: "web_search"
    action: allow
    rate_limit:
      requests: 10
      per: minute
```

### 2. Audit Logging

Every tool invocation is logged with:
- Timestamp
- Tool name and arguments
- Agent identity (if available)
- Policy decision (allow/deny)
- Response summary

```json
{
  "specversion": "1.0",
  "type": "ai.agentmesh.tool.invoked",
  "source": "urn:mcp-proxy:secure-filesystem",
  "time": "2026-02-03T10:30:00Z",
  "data": {
    "tool": "read_file",
    "arguments": { "path": "/home/user/documents/report.txt" },
    "decision": "allow",
    "latency_ms": 45
  }
}
```

### 3. Rate Limiting

Prevent resource exhaustion:

```yaml
rate_limits:
  global:
    requests: 100
    per: minute
  
  per_tool:
    write_file:
      requests: 10
      per: minute
    web_search:
      requests: 5
      per: minute
```

### 4. Input Sanitization

Automatically detect and block:
- Prompt injection attempts
- Path traversal attacks (`../../../etc/passwd`)
- Command injection (`; rm -rf /`)
- PII in tool arguments

### 5. Shadow Mode

Test policies without blocking:

```bash
agentmesh protect --mode=shadow ./my-mcp-server
```

In shadow mode:
- All requests pass through
- Policy violations are logged (not blocked)
- Use to tune policies before enforcement

## 📊 Built-in Policies

| Policy | Description |
|--------|-------------|
| `minimal` | Allow all tools, log everything |
| `standard` | Block known-dangerous tools |
| `strict` | Allowlist only, deny by default |
| `enterprise` | Full audit, PII detection, rate limits |

```bash
agentmesh protect --policy=strict ./my-mcp-server
```

## 🔧 CLI Reference

### `agentmesh protect`

Wrap an MCP server with security controls.

```bash
agentmesh protect [options] <mcp-command> [args...]

Options:
  --policy <name|file>   Policy to apply (default: standard)
  --mode <mode>          enforce | shadow (default: enforce)
  --log <path>           Audit log file path
  --log-format <fmt>     json | cloudevents (default: cloudevents)
  --rate-limit <n/m>     Global rate limit (e.g., 100/minute)
  --no-sanitize          Disable input sanitization
  --verbose              Verbose logging
```

### `agentmesh audit`

Analyze audit logs.

```bash
agentmesh audit <logfile>

# Show policy violations
agentmesh audit --violations-only audit.log

# Export to CSV
agentmesh audit --format=csv audit.log > report.csv
```

### `agentmesh policy`

Manage policies.

```bash
# Validate a policy file
agentmesh policy validate my-policy.yaml

# Generate policy from audit log
agentmesh policy generate audit.log > learned-policy.yaml
```

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Claude / AI Agent                        │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼ MCP Protocol
┌─────────────────────────────────────────────────────────────┐
│                   AgentMesh MCP Proxy                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   Policy    │  │    Rate     │  │    Audit Logger     │ │
│  │   Engine    │  │   Limiter   │  │  (CloudEvents)      │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   Input     │  │  Identity   │  │    hash chain Chain     │ │
│  │ Sanitizer   │  │  Resolver   │  │  (Tamper Detection) │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼ MCP Protocol (unchanged)
┌─────────────────────────────────────────────────────────────┐
│              Original MCP Server (unchanged)                 │
│     (filesystem, github, database, custom servers...)       │
└─────────────────────────────────────────────────────────────┘
```

## 🔌 Integration

### With Claude Desktop

See [Claude Desktop Configuration](#claude-desktop-configuration) above.

### With Cursor

```json
{
  "mcp": {
    "servers": {
      "secure-fs": {
        "command": "agentmesh",
        "args": ["protect", "--policy=strict", "@anthropic/mcp-server-filesystem", "/tmp"]
      }
    }
  }
}
```

### With Custom Applications

```typescript
import { MCPProxy } from 'agentmesh-mcp-proxy';

const proxy = new MCPProxy({
  target: '@anthropic/mcp-server-filesystem',
  targetArgs: ['/tmp'],
  policy: 'strict',
  onViolation: (event) => {
    alertSecurityTeam(event);
  }
});

await proxy.start();
```

## 📈 Roadmap

- [x] Basic policy enforcement
- [x] CloudEvents audit logging
- [x] Rate limiting
- [x] Input sanitization
- [ ] OPA/Rego policy support
- [ ] mTLS authentication
- [ ] Prometheus metrics
- [ ] Web dashboard

## 🤝 Contributing

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for guidelines.

## 📄 License

Apache 2.0 - See [LICENSE](../../LICENSE)

## 🔗 Links

- **AgentMesh**: https://github.com/microsoft/agent-governance-toolkit
- **MCP Specification**: https://modelcontextprotocol.io
- **MCP Security Discussion**: https://github.com/anthropics/anthropic-cookbook/discussions

---

*"Running an MCP server without AgentMesh is like running a web server without a firewall."*
