# MCP Trust Server for AgentMesh

MCP server that exposes AgentMesh trust management as tools for AI agents via the [Model Context Protocol](https://modelcontextprotocol.io). Compatible with Claude, GPT, and any MCP-capable client.

## What it does

Provides six trust-management tools over MCP:

| Tool | Description |
|------|-------------|
| `check_trust` | Check if an agent is trusted — returns trust score |
| `get_trust_score` | Detailed trust score breakdown |
| `establish_handshake` | Initiate a cryptographic trust handshake with a peer |
| `verify_delegation` | Verify a scope chain is valid |
| `record_interaction` | Record an interaction outcome to update trust |
| `get_identity` | Get this server's DID, public key, and capabilities |

Trust is scored across multiple dimensions (0–1000 each).

## Installation

```bash
pip install mcp-trust-server
```

Or install from the repository:

```bash
cd packages/mcp-trust-server
pip install -e ".[dev]"
```

## Configuration

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `AGENTMESH_AGENT_NAME` | Agent name for this server instance | `mcp-trust-agent` |
| `AGENTMESH_MIN_TRUST_SCORE` | Minimum trust threshold (0–1000) | `500` |
| `AGENTMESH_STORAGE_BACKEND` | Storage backend (`memory` or `redis`) | `memory` |

## Usage

### Run directly

```bash
python -m mcp_trust_server
```

Or via the console script:

```bash
mcp-trust-server
```

### Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "agentmesh-trust": {
      "command": "python",
      "args": ["-m", "mcp_trust_server"],
      "env": {
        "AGENTMESH_AGENT_NAME": "my-trust-server",
        "AGENTMESH_MIN_TRUST_SCORE": "500"
      }
    }
  }
}
```

### Using with `pip install`

```json
{
  "mcpServers": {
    "agentmesh-trust": {
      "command": "mcp-trust-server"
    }
  }
}
```

## Tool Details

### `check_trust(agent_did: str) -> dict`

Quick trust check. Returns whether the agent meets the minimum trust threshold, overall score, and trust level.

### `get_trust_score(agent_did: str) -> dict`

Full trust breakdown — overall score, trust level, interaction count, and last-updated timestamp.

### `establish_handshake(peer_did: str, capabilities: list[str]) -> dict`

Creates a challenge for a trust handshake. Returns handshake ID, signature, and status.

### `verify_delegation(agent_did: str, delegator_did: str, capability: str) -> dict`

Validates that a delegation from `delegator_did` to `agent_did` for the given capability is trustworthy.

### `record_interaction(peer_did: str, outcome: str, details: str) -> dict`

Records an interaction with a peer and adjusts trust scores. Valid outcomes: `success` (+10), `failure` (−20), `timeout` (−10), `partial` (+5).

### `get_identity() -> dict`

Returns this server instance's DID, name, Ed25519 public key, and granted capabilities.

## Example Interaction

```
User: Check if agent did:mesh:abc123 is trusted

Claude calls check_trust(agent_did="did:mesh:abc123")
→ {
    "agent_did": "did:mesh:abc123",
    "trusted": true,
    "overall_score": 500,
    "trust_level": "standard",
    "dimensions": {
      "competence": 500,
      "integrity": 500,
      "availability": 500,
      "predictability": 500,
      "transparency": 500
    },
    "min_trust_threshold": 500
  }
```

## Development

```bash
cd packages/mcp-trust-server
pip install -e ".[dev]"
pytest tests/ -v
```

## License

Apache-2.0
