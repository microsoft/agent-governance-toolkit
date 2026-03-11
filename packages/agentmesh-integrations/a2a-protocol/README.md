# A2A AgentMesh

A2A protocol bridge for AgentMesh — trust-verified agent-to-agent communication via the [A2A standard](https://a2a-protocol.org/).

## Features

- **AgentCard**: Convert AgentMesh identities to A2A-compliant discovery cards
- **TaskEnvelope**: Trust-verified task lifecycle (submitted → working → complete/failed)
- **TrustGate**: Policy enforcement for A2A task negotiations (trust scores, rate limits, DID allow/deny)

## Quick Start

```python
from a2a_agentmesh import AgentCard, TaskEnvelope, TrustGate, TrustPolicy

# Publish your agent as an A2A card
card = AgentCard.from_identity(
    did="did:mesh:my-agent",
    name="TranslationAgent",
    capabilities=["translate", "summarize"],
    trust_score=800,
)

# Create a trust-verified task
task = TaskEnvelope.create(
    skill_id="translate",
    source_did="did:mesh:requester",
    target_did=card.agent_did,
    source_trust_score=600,
    input_text="Translate 'hello' to Spanish",
)

# Gate the request
gate = TrustGate(TrustPolicy(min_trust_score=500))
result = gate.evaluate(task)
assert result.allowed
```
