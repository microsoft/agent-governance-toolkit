# MCP Kernel Server

> **Part of [Agent OS](https://github.com/microsoft/agent-governance-toolkit)** - Kernel-level governance for AI agents

**Native Safety for Claude Desktop - Agent OS kernel primitives via Model Context Protocol (MCP)**

This server exposes Agent OS capabilities through MCP, enabling Claude Desktop and other MCP-compatible clients to use kernel-level AI agent governance.

## The Problem

Claude generates code without safety guarantees. It can suggest:
- `DROP TABLE users` - deleting production data
- Hardcoded API keys and secrets
- `rm -rf /` - destructive file operations

## The Solution

Agent OS MCP Server provides safety verification that Claude calls **before** executing code:

```
[Claude generates code]
        ↓
[Calls verify_code_safety tool]
        ↓
[Agent OS returns: BLOCKED - Destructive SQL]
        ↓
[Claude explains why and suggests safer alternative]
```

## Quick Start

### Claude Desktop Integration (60 seconds)

1. Install the server:
```bash
pip install agent-os-kernel[mcp]
```

2. Add to Claude Desktop config:

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "agent-os": {
      "command": "mcp-kernel-server",
      "args": ["--stdio"]
    }
  }
}
```

3. Restart Claude Desktop. You now have access to 8 safety tools!

## Available Tools

### `verify_code_safety` - Code Safety Check ⭐ NEW
**The primary tool for Claude Desktop.** Checks if code is safe before execution.

```json
{
  "name": "verify_code_safety",
  "arguments": {
    "code": "await db.query('DROP TABLE users')",
    "language": "javascript"
  }
}
```

Returns:
```json
{
  "safe": false,
  "violations": [
    {
      "rule": "drop_table",
      "severity": "critical",
      "message": "Destructive SQL: DROP operation detected",
      "alternative": "Consider using soft delete or archiving instead of DROP"
    }
  ],
  "blocked_reason": "Destructive SQL: DROP operation detected"
}
```

### `cmvk_review` - Multi-Model Code Review ⭐ NEW
Review code across multiple AI models for bugs, security, and best practices.

```json
{
  "name": "cmvk_review",
  "arguments": {
    "code": "function processPayment(userId, amount) {...}",
    "language": "javascript",
    "focus": ["security", "bugs"]
  }
}
```

Returns:
```json
{
  "consensus": 0.67,
  "reviews": [
    {"model": "gpt-4", "passed": true, "issues": []},
    {"model": "claude-sonnet-4", "passed": false, "issues": [...]},
    {"model": "gemini-pro", "passed": true, "issues": []}
  ],
  "recommendation": "Based on multi-model review:\n1. Missing error handling..."
}
```

### `get_audit_log` - Retrieve Audit Trail ⭐ NEW
Get the safety audit trail for compliance and debugging.

```json
{
  "name": "get_audit_log",
  "arguments": {
    "limit": 20,
    "filter": {"type": "blocked"}
  }
}
```

### `cmvk_verify` - Claim Verification
Verify claims across multiple AI models to detect hallucinations.

```json
{
  "name": "cmvk_verify",
  "arguments": {
    "claim": "The capital of France is Paris",
    "threshold": 0.85
  }
}
```

### `kernel_execute` - Governed Execution
Execute actions through the kernel with policy enforcement.

```json
{
  "name": "kernel_execute",
  "arguments": {
    "action": "database_query",
    "params": {"query": "SELECT * FROM users"},
    "agent_id": "analyst-001",
    "policies": ["read_only", "no_pii"]
  }
}
```

### `iatp_sign` - Trust Attestation
Sign agent outputs for inter-agent trust.

### `iatp_verify` - Trust Verification
Verify trust before agent-to-agent communication.

### `iatp_reputation` - Reputation Network
Query or modify agent reputation.

## Demo: Using with Claude Desktop

After installation, try this in Claude Desktop:

**You:** "Write a script to clean up old user data"

**Claude:** (generates code, then calls `verify_code_safety`)

**Agent OS returns:** BLOCKED - Destructive SQL detected

**Claude:** "I generated the code, but Agent OS blocked it for safety. The DELETE statement would remove data permanently. Here's a safer approach using soft deletes..."

## Available Resources

| URI Template | Description |
|-------------|-------------|
| `vfs://{agent_id}/mem/working/{key}` | Ephemeral working memory |
| `vfs://{agent_id}/mem/episodic/{session}` | Experience logs |
| `vfs://{agent_id}/policy/{name}` | Policies (read-only) |
| `audit://{agent_id}/log` | Audit trail (read-only) |

## Available Prompts

### `governed_agent`
Instructions for operating as a governed agent.

### `verify_claim`
Template for CMVK verification.

### `safe_execution`
Template for safe action execution.

## Stateless Design (MCP June 2026 Compliant)

This server is **stateless by design** for horizontal scaling:

- ✅ No session state maintained
- ✅ All context passed in each request
- ✅ State externalized to backend storage
- ✅ Horizontally scalable

## Configuration Options

```bash
mcp-kernel-server --stdio                    # Claude Desktop (default)
mcp-kernel-server --http --port 8080         # Development
mcp-kernel-server --policy-mode strict       # Policy mode: strict|permissive|audit
mcp-kernel-server --cmvk-threshold 0.90      # CMVK confidence threshold
```

## Development Mode

```bash
# HTTP transport for testing
mcp-kernel-server --http --port 8080

# List available tools
mcp-kernel-server --list-tools

# List available prompts
mcp-kernel-server --list-prompts
```

## Python Integration

```python
from mcp import ClientSession

async with ClientSession() as session:
    await session.connect("http://localhost:8080")
    
    # Verify code safety
    result = await session.call_tool("verify_code_safety", {
        "code": "import os; os.system('rm -rf /')",
        "language": "python"
    })
    print(result["safe"])  # False
    
    # Multi-model code review
    result = await session.call_tool("cmvk_review", {
        "code": "...",
        "focus": ["security", "bugs"]
    })
```

## Part of Agent OS

This MCP server is part of the [Agent OS](https://github.com/microsoft/agent-governance-toolkit) ecosystem:

- **Kernel-level safety** - Not just prompts, real enforcement
- **POSIX-style signals** - SIGKILL, SIGSTOP, SIGCONT for agents
- **Verification** - Consensus across GPT-4, Claude, Gemini
- **Zero violations** - Deterministic policy enforcement

## License

MIT
