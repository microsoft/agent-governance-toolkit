# Nostr Web of Trust Integration for AgentMesh

Trust scoring for AgentMesh agents using [MaximumSats](https://github.com/joelklabo/maximumsats-mcp) Nostr Web of Trust (NIP-85).

## Features

- **WoT Trust Scores** — Map Nostr pubkey trust scores to AgentMesh trust engine
- **Sybil Detection** — Detect potential Sybil attacks on agent identities
- **Trust Circles** — Discover direct trust connections for agents
- **Transitive Trust** — Support depth 1-3 transitive trust scoring

## Installation

```bash
pip install agentmesh-nostr-wot
```

## Usage

```python
from agentmesh.trust import TrustEngine
from agentmesh_nostr_wot import NostrWoTProvider

# Create provider pointing to WoT API
provider = NostrWoTProvider(
    wot_api="https://wot.klabo.world",
    # Optional: map agent IDs to Nostr pubkeys
    pubkey_resolver=my_resolver
)

# Register with AgentMesh trust engine
engine = TrustEngine(external_providers=[provider])

# Get composite trust score (AgentMesh verification + Nostr WoT)
score = await engine.get_trust_score("agent-123")
```

## API Reference

### `NostrWoTProvider`

| Method | Description |
|---|---|
| `get_trust_score(agent_id)` | Returns WoT-derived trust score (0.0-1.0) |
| `check_sybil(agent_id)` | Returns sybil risk assessment |
| `get_trust_circle(agent_id)` | Returns direct trust connections |
| `verify_identity(agent_id, credentials)` | Verifies agent via Nostr pubkey |

## Contributing

This integration is maintained by the community. PRs welcome!

See the [MaximumSats API docs](https://maximumsats.com/api/dvm) for endpoint details.

## Credits

- [MaximumSats MCP](https://github.com/joelklabo/maximumsats-mcp) by @joelklabo
- [AgentMesh](https://github.com/imran-siddique/agent-mesh) trust framework
