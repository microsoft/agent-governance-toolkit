# MCP Tool Server with AgentMesh Governance

This example demonstrates how to secure an MCP (Model Context Protocol) tool server with AgentMesh governance, identity, and policy enforcement.

## What is MCP?

MCP (Model Context Protocol) is Anthropic's protocol for connecting AI models to external tools and data sources. It's widely adopted by Claude, and other LLMs are adding support.

## What This Example Shows

- **Identity Management:** Each MCP server gets a cryptographic identity
- **Tool Registration:** Tools are registered with capability scoping
- **Policy Enforcement:** Rate limiting, access control, and output sanitization
- **Audit Logging:** Every tool invocation is logged to a tamper-evident audit trail
- **Trust Scoring:** Server trust score adapts based on behavior

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        AI Model (Claude)                     │
└────────────────────────┬────────────────────────────────────┘
                         │ MCP Protocol
                         │
┌────────────────────────▼────────────────────────────────────┐
│                  AgentMesh-Secured                           │
│                   MCP Tool Server                            │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ AgentMesh Governance Layer                           │  │
│  │ • Identity: did:agentmesh:mcp-tool-server           │  │
│  │ • Policies: Rate limits, access control              │  │
│  │ • Audit: Every tool call logged                      │  │
│  └──────────────────────────────────────────────────────┘  │
│                         │                                    │
│  ┌──────────┬──────────┼──────────┬──────────────────────┐ │
│  │ Database │ Filesystem│  API     │  Code Execution      │ │
│  │ Query    │ Read      │ Call     │  (sandboxed)         │ │
│  └──────────┴──────────┴──────────┴──────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Run the MCP Server

```bash
python main.py
```

### 3. Connect Claude Desktop

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "agentmesh-example": {
      "command": "python",
      "args": ["/path/to/this/example/main.py"],
      "env": {}
    }
  }
}
```

### 4. Test in Claude

```
Try asking Claude:
"Can you read the file /etc/hosts?"
"Can you query the database for user records?"
"Can you call the weather API?"
```

Watch the console for AgentMesh governance in action:
- Policy checks (✓ allowed / ✗ blocked)
- Audit log entries
- Trust score updates

## Key Features Demonstrated

### 1. Tool Registration with Capabilities

```python
from agentmesh import AgentIdentity, CapabilityScope

# Create identity for MCP server
identity = AgentIdentity.create(
    name="mcp-tool-server",
    sponsor="devops@company.com"
)

# Register tool with specific capabilities
scope = CapabilityScope(
    resources=["filesystem:/data/*"],
    actions=["read"],
    ttl_minutes=15
)
```

### 2. Rate Limiting Policy

```yaml
policies:
  - name: "rate-limit-api-calls"
    rules:
      - condition: "tool == 'api_call'"
        limit: "100/hour"
        action: "block"
```

### 3. Output Sanitization

```yaml
policies:
  - name: "sanitize-sensitive-data"
    rules:
      - condition: "output contains 'password' or output contains 'api_key'"
        action: "redact"
        message: "Sensitive data detected and redacted"
```

### 4. Audit Trail

Every tool invocation creates an audit entry:

```json
{
  "timestamp": "2026-01-31T10:15:00Z",
  "agent": "did:agentmesh:mcp-tool-server",
  "action": "tool_invocation",
  "tool": "filesystem_read",
  "params": {"path": "/data/users.json"},
  "result": "allowed",
  "trust_score": 847
}
```

## Policy Files

### `policies/default.yaml`
- Basic security policies
- Rate limiting
- Output sanitization

### `policies/filesystem.yaml`
- Filesystem access control
- Path-based restrictions
- Read/write permissions

### `policies/api.yaml`
- API rate limiting
- Endpoint restrictions
- Response validation

## Security Features

| Feature | Implementation |
|---------|----------------|
| **Identity** | Ed25519 cryptographic identity for MCP server |
| **Credentials** | 15-minute TTL with auto-rotation |
| **Rate Limiting** | Per-tool, per-hour limits enforced |
| **Path Restrictions** | Filesystem access limited to approved paths |
| **Output Sanitization** | Automatic redaction of sensitive data |
| **Audit Logging** | hash-chained tamper-evident logs |
| **Trust Scoring** | Adaptive scoring; access revoked if score drops |

## Monitoring

View real-time status:

```bash
# Check server status and trust score
agentmesh status .

# View audit logs
agentmesh audit --agent did:agentmesh:mcp-tool-server --limit 50

# Validate policies
agentmesh policy policies/default.yaml --validate
```

## Extending This Example

### Add a New Tool

1. Implement the tool in `main.py`
2. Register with appropriate capabilities
3. Add policy rules in `policies/`
4. Test and monitor

### Integrate with Your MCP Server

1. Copy `agentmesh.yaml` to your MCP server directory
2. Wrap your tool handlers with AgentMesh governance:

```python
from agentmesh import PolicyEngine, AuditLog

policy_engine = PolicyEngine.from_file("policies/default.yaml")
audit_log = AuditLog()

@mcp_server.tool("your_tool")
async def your_tool(params):
    # Policy check
    result = policy_engine.check(action="tool_call", tool="your_tool", params=params)
    if not result.allowed:
        audit_log.log("blocked", tool="your_tool", reason=result.reason)
        raise PermissionError(result.reason)
    
    # Execute tool
    output = await execute_your_tool(params)
    
    # Audit
    audit_log.log("success", tool="your_tool", output=output)
    
    return output
```

## Troubleshooting

**Issue:** Claude can't connect to the MCP server

**Solution:** Check the Claude Desktop config path and ensure Python is in your PATH

---

**Issue:** All tool calls are blocked

**Solution:** Check `policies/default.yaml` and ensure your use case is allowed

---

**Issue:** Trust score is dropping

**Solution:** Check audit logs for policy violations or unusual behavior

## Next Steps

- Add custom tools specific to your use case
- Configure compliance frameworks (SOC 2, HIPAA) in `agentmesh.yaml`
- Set up monitoring and alerting for policy violations
- Deploy to production with proper secret management

## Learn More

- [AgentMesh Documentation](../../README.md)
- [MCP Protocol Specification](https://spec.modelcontextprotocol.io/)
- [Policy Engine Reference](../../docs/policy-engine.md)

---

**Production Readiness:** This example is production-ready for internal tools. For external deployments, add:
- Secret management for credentials
- Network security controls
- Backup and disaster recovery
- Enterprise audit integration
