# AgentMesh MCP Proxy Examples

This directory contains example configurations for using AgentMesh as a proxy for MCP servers.

## Claude Desktop Configuration

### Basic Filesystem Protection

Protect the filesystem MCP server with strict policy:

```json
{
  "mcpServers": {
    "filesystem-safe": {
      "command": "agentmesh",
      "args": [
        "proxy",
        "--policy", "strict",
        "--target", "npx",
        "--target", "-y",
        "--target", "@modelcontextprotocol/server-filesystem",
        "--target", "/Users/yourname/safe-directory"
      ]
    }
  }
}
```

### Multiple Servers with Different Policies

```json
{
  "mcpServers": {
    "filesystem-strict": {
      "command": "agentmesh",
      "args": [
        "proxy",
        "--policy", "strict",
        "--target", "npx",
        "--target", "-y",
        "--target", "@modelcontextprotocol/server-filesystem",
        "--target", "/Users/yourname/work"
      ]
    },
    "filesystem-moderate": {
      "command": "agentmesh",
      "args": [
        "proxy",
        "--policy", "moderate",
        "--target", "npx",
        "--target", "-y",
        "--target", "@modelcontextprotocol/server-filesystem",
        "--target", "/Users/yourname/experiments"
      ]
    },
    "database": {
      "command": "agentmesh",
      "args": [
        "proxy",
        "--policy", "strict",
        "--target", "python",
        "--target", "my_database_server.py"
      ]
    }
  }
}
```

### Without Verification Footers

If you prefer cleaner outputs without trust verification messages:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "agentmesh",
      "args": [
        "proxy",
        "--policy", "strict",
        "--no-footer",
        "--target", "npx",
        "--target", "-y",
        "--target", "@modelcontextprotocol/server-filesystem",
        "--target", "/Users/yourname"
      ]
    }
  }
}
```

## Policy Levels

### Strict (Recommended)
- **Blocks**: All write/delete operations
- **Blocks**: Access to sensitive paths (/etc, /root, /.ssh)
- **Allows**: Read operations only
- Best for: Production, shared machines, untrusted environments

### Moderate
- **Warns**: On write operations but allows them
- **Blocks**: Critical system paths
- **Allows**: Most operations with logging
- Best for: Development, personal machines

### Permissive
- **Allows**: All operations
- **Logs**: Everything for audit
- Best for: Testing, debugging, controlled environments

## Standalone Proxy Usage

You can also run the proxy standalone without Claude Desktop:

```bash
# Start a proxied MCP server
agentmesh proxy \
  --policy strict \
  --target npx \
  --target -y \
  --target @modelcontextprotocol/server-filesystem \
  --target /path/to/directory

# The proxy accepts JSON-RPC on stdin and outputs to stdout
# Connect any MCP client to it
```

## Example: Testing the Proxy

```bash
# Terminal 1: Start the proxy
agentmesh proxy \
  --policy strict \
  --target echo \
  --target '{"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "Hello"}]}}'

# Terminal 2: Send a test JSON-RPC message
echo '{"jsonrpc": "2.0", "method": "tools/call", "id": 1, "params": {"name": "test_tool", "arguments": {}}}' | \
  agentmesh proxy --target cat
```

## Viewing Logs

AgentMesh logs proxy activity to stderr. To capture logs:

```bash
# Redirect logs to a file
agentmesh proxy --target ... 2> agentmesh-proxy.log

# Or view logs in real-time
agentmesh proxy --target ... 2>&1 | tee agentmesh-proxy.log
```

## Custom Identity

Give your proxy a custom identity name:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "agentmesh",
      "args": [
        "proxy",
        "--identity", "claude-filesystem-proxy",
        "--target", "..."
      ]
    }
  }
}
```

## Troubleshooting

### Claude doesn't start
- Check that `agentmesh` is in your PATH: `which agentmesh`
- Test the proxy command manually first
- Look at Claude's logs (usually in `~/Library/Logs/Claude/`)

### Operations are blocked unexpectedly
- Try `--policy moderate` instead of `--policy strict`
- Check the proxy logs (stderr output)
- Review which rule is blocking in the logs

### No verification footers appearing
- Make sure you didn't use `--no-footer`
- Footers only appear on tool responses with content
- Some MCP servers may not include content in responses

## Next Steps

- Read the [full Claude Desktop integration guide](./claude-desktop.md)
- Learn about [custom policies](../../examples/policies/)
- View [audit logs](../../examples/audit-logs/)
