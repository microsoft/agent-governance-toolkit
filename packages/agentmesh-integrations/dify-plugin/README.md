# AgentMesh Trust Layer - Dify Plugin

Cryptographic trust verification for multi-agent Dify workflows using verification (Ed25519) identities.

## Features

- **Peer Verification**: Verify other agents' identities and capabilities before trusting their data
- **Workflow Step Authorization**: Ensure agents have required permissions for each step
- **Trust Score Tracking**: Dynamic trust scores based on interaction history
- **Audit Logging**: Complete audit trail of all trust decisions

## Installation

1. Clone this repository or download the plugin folder
2. Package the plugin:
   ```bash
   cd dify-plugin
   zip -r agentmesh-plugin.zip .
   ```
3. Upload to Dify via Settings → Plugins → Install from Package

## Configuration

When configuring the plugin in Dify, you can set:

| Parameter | Description | Default |
|-----------|-------------|---------|
| Minimum Trust Score | Score (0-1) required for verification | 0.5 |
| Cache TTL | Seconds to cache verification results | 900 |
| Identity Name | Name for this agent's identity | dify-agent |
| Capabilities | Comma-separated list of capabilities | (empty) |

## Tools

### Verify Peer Agent

Verify another agent's identity before trusting their data or delegating tasks.

**Parameters:**
- `peer_did` (required): The DID of the peer agent (e.g., `did:verification:abc123`)
- `peer_public_key` (required): Base64-encoded Ed25519 public key
- `required_capabilities`: Capabilities the peer must have
- `peer_capabilities`: Capabilities the peer claims to have

### Verify Workflow Step

Check if the current agent has permission to execute a workflow step.

**Parameters:**
- `workflow_id` (required): Workflow identifier
- `step_id` (required): Step identifier within workflow
- `step_type` (required): Type of step (llm, tool, code, etc.)
- `required_capability`: Specific capability to check

### Get Agent Identity

Get this agent's cryptographic identity to share with other agents.

**Parameters:**
- `include_capabilities`: Whether to include capabilities list

### Record Interaction

Record successful or failed interactions to update trust scores.

**Parameters:**
- `peer_did` (required): DID of the peer agent
- `success` (required): Whether the interaction succeeded
- `severity`: For failures, how much to decrease trust (0-1)

## Example Workflow

```
1. Agent A calls "Get Agent Identity" to get its DID and public key
2. Agent A shares identity with Agent B
3. Agent B calls "Verify Peer Agent" with A's DID and public key
4. If verified, Agent B proceeds with collaboration
5. After interaction, Agent B calls "Record Interaction" to update trust score
```

## License

MIT License - See [AgentMesh](https://github.com/imran-siddique/agent-mesh) for details.
