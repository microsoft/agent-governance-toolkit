# Agent Veil Protocol Integration for AgentMesh

Trust scoring for AgentMesh agents using [Agent Veil Protocol](https://agentveil.dev) — EigenTrust reputation, sybil resistance, and DID-based identity.

## Features

- **EigenTrust Scores** — Map AVP reputation scores to AgentMesh trust engine
- **Identity Verification** — Verify agents via AVP's DID registry
- **Full Reputation Profile** — Access confidence, risk factors, attestation history
- **Graceful Fallback** — Returns safe defaults when AVP API is unreachable

## Installation

```bash
pip install agentmesh-avp
```

## Usage

```python
from agentmesh.trust import TrustEngine
from agentmesh_avp import AVPProvider

# Create provider pointing to AVP API
provider = AVPProvider(
    base_url="https://agentveil.dev",
    # Optional: map agent IDs to AVP DIDs
    did_resolver=my_resolver,
)

# Register with AgentMesh trust engine
engine = TrustEngine(external_providers=[provider])

# Get composite trust score (AgentMesh + AVP EigenTrust)
score = await engine.get_trust_score("did:key:z6MkAgent...")
```

## API Reference

### `AVPProvider`

| Method | Description |
|---|---|
| `get_trust_score(agent_id)` | Returns EigenTrust score (0.0-1.0) |
| `get_reputation(agent_id)` | Returns full profile (score, confidence, tier, risk) |
| `verify_identity(agent_id, credentials)` | Verifies agent via AVP DID registry |

### Constructor Arguments

| Argument | Default | Description |
|---|---|---|
| `base_url` | `https://agentveil.dev` | AVP server URL |
| `did_resolver` | `None` | Maps agent_id to AVP DID string |
| `name_resolver` | `None` | Maps agent_id to AVP agent name |
| `timeout` | `10.0` | HTTP timeout in seconds |
| `min_score_threshold` | `0.3` | Minimum score for score-based verification |

## Limitations

- **DID method**: Only `did:key` identifiers are supported. Other DID methods (`did:web`, `did:ion`, etc.) will be rejected by the DID format validator.
- **Fallback behavior**: When the AVP verification endpoint is unreachable, `verify_identity` falls back to score-based verification using `min_score_threshold`. This is logged as a warning.

## About Agent Veil Protocol

AVP is an open reputation layer for AI agents. 110+ agents in production, daily IPFS anchors, MIT-licensed SDK.

- [agentveil.dev](https://agentveil.dev)
- [SDK on PyPI](https://pypi.org/project/agentveil/) — `pip install agentveil`
- [GitHub](https://github.com/creatorrmode-lead/avp-sdk)

## Contributing

See the main [CONTRIBUTING.md](../../../CONTRIBUTING.md) for guidelines.