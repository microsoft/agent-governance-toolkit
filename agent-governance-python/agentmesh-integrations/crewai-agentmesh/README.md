# CrewAI AgentMesh

AgentMesh trust layer for CrewAI — trust-verified crew member selection and capability-gated task assignment.

## Features

- **TrustedCrew**: Trust-verified crew member selection based on agent capabilities and trust scores
- **CapabilityGate**: Ensures agents can only be assigned tasks matching their verified capabilities
- **TrustTracker**: Tracks trust scores across crew runs with decay and reward

## Quick Start

```python
from crewai_agentmesh import TrustedCrew, AgentProfile

# Define trusted agents
agents = [
    AgentProfile(did="did:mesh:researcher", name="Researcher", capabilities=["research", "analysis"], trust_score=800),
    AgentProfile(did="did:mesh:writer", name="Writer", capabilities=["writing", "editing"], trust_score=700),
]

# Create trust-gated crew
crew = TrustedCrew(agents=agents, min_trust_score=500)

# Select agents for a task
selected = crew.select_for_task(required_capabilities=["research"])
assert len(selected) == 1
assert selected[0].name == "Researcher"
```
