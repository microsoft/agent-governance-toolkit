# AgentMesh for Claude Desktop

**The "Day 0" Integration: Make every Claude user realize their local tool use is unsafe, then fix it with one command.**

## The Problem

When you connect Claude Desktop to a local MCP server (like the Filesystem server), Claude has **unfettered access** to your files. One hallucination could:
- Delete critical files
- Expose sensitive data
- Modify system configurations
- Access credentials

**Claude Desktop has no governance layer by default.**

## The Solution: AgentMesh MCP Proxy

AgentMesh provides a transparent proxy that sits between Claude Desktop and any MCP server, adding:

- 🔒 **Policy Enforcement** - Block dangerous operations before they happen
- 📊 **Trust Scoring** - Continuous behavioral monitoring
- 📝 **Audit Logging** - Tamper-evident logs of every action
- ✅ **Verification Footers** - Visual confirmation that governance is active

## Quick Start

### 1. Install AgentMesh

```bash
pip install agentmesh-platform
```

### 2. Set Up Claude Desktop Integration

```bash
agentmesh init-integration --claude
```

This command will:
- Locate your `claude_desktop_config.json`
- Backup the existing configuration
- Add an example AgentMesh-protected filesystem server
- Provide next steps

### 3. Restart Claude Desktop

After restarting, Claude will connect to MCP servers through AgentMesh.

## Manual Configuration

If you prefer to configure manually, edit your `claude_desktop_config.json`:

### Before (Unsafe)

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/me"]
    }
  }
}
```

### After (Protected by AgentMesh)

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "agentmesh",
      "args": [
        "proxy",
        "--target", "npx",
        "--target", "-y",
        "--target", "@modelcontextprotocol/server-filesystem",
        "--target", "/Users/me"
      ]
    }
  }
}
```

## Policy Levels

AgentMesh supports three policy levels:

### Strict (Default)
- **Blocks** all write/delete operations
- **Blocks** access to sensitive paths (`/etc`, `/root`, `/.ssh`)
- **Allows** read operations only
- Best for: Production environments, shared machines

```json
{
  "args": ["proxy", "--policy", "strict", "--target", "..."]
}
```

### Moderate
- **Warns** on write operations but allows them
- **Blocks** access to critical system paths
- **Allows** most operations with logging
- Best for: Development environments

```json
{
  "args": ["proxy", "--policy", "moderate", "--target", "..."]
}
```

### Permissive
- **Allows** all operations
- **Logs** everything for audit
- Best for: Testing, controlled environments

```json
{
  "args": ["proxy", "--policy", "permissive", "--target", "..."]
}
```

## Verification Footers

Every tool response from Claude will include a verification footer:

```
> 🔒 Verified by AgentMesh (Trust Score: 980/1000)
> Agent: did:agentmesh:mcp-proxy:abc123...
> Policy: strict | Audit: Enabled
```

This provides:
- **Visual confirmation** that AgentMesh is active
- **Trust score** showing behavioral health
- **Audit status** for compliance

### Disable Footers

If you prefer cleaner output:

```json
{
  "args": ["proxy", "--no-footer", "--target", "..."]
}
```

## Examples

### Protect Multiple MCP Servers

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "agentmesh",
      "args": [
        "proxy",
        "--policy", "strict",
        "--target", "npx",
        "--target", "-y",
        "--target", "@modelcontextprotocol/server-filesystem",
        "--target", "/Users/me/safe-directory"
      ]
    },
    "database": {
      "command": "agentmesh",
      "args": [
        "proxy",
        "--policy", "moderate",
        "--target", "python",
        "--target", "my_db_server.py"
      ]
    }
  }
}
```

## Support

- **Documentation:** https://github.com/microsoft/agent-governance-toolkit
- **Issues:** https://github.com/microsoft/agent-governance-toolkit/issues

---

> "You wouldn't run a website without SSL; don't run an agent without AgentMesh."
