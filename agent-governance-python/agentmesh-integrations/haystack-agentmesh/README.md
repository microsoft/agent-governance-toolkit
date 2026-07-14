# haystack-agentmesh

AgentMesh governance components for [Haystack](https://haystack.deepset.ai/) pipelines — policy enforcement, trust scoring, and tamper-evident audit trails.

## Installation

```bash
pip install haystack-agentmesh
```

With Haystack:

```bash
pip install "haystack-agentmesh[haystack]"
```

## Components

### TrustGate

Trust scoring with time-based decay and routing decisions.

```python
from haystack_agentmesh import TrustGate

gate = TrustGate(pass_threshold=0.7, review_threshold=0.4)

gate.record_success("agent-1")
result = gate.run(agent_id="agent-1")
# {"trusted": False, "score": 0.55, "action": "review"}
```

Actions: `pass` (trusted), `review` (marginal), `block` (below threshold).

### AuditLogger

Append-only audit log with SHA-256 hash chain hashing for tamper evidence.

```python
from haystack_agentmesh import AuditLogger

logger = AuditLogger()
result = logger.run(action="search", agent_id="agent-1", decision="allow")
# {"entry_id": "a1b2c3d4e5f67890", "chain_hash": "sha256..."}

assert logger.verify_chain()  # Verify integrity
logger.export_jsonl("audit.jsonl")  # Export for analysis
```

## Pipeline Example

```python
from haystack import Pipeline
from haystack_agentmesh import TrustGate, AuditLogger

pipe = Pipeline()
pipe.add_component("trust_gate", TrustGate())
pipe.add_component("audit", AuditLogger())
```

## Component Reference

| Component | Inputs | Outputs |
|-----------|--------|---------|
| `TrustGate` | `agent_id: str`, `min_score: Optional[float]` | `trusted: bool`, `score: float`, `action: str` |
| `AuditLogger` | `action: str`, `agent_id: str`, `decision: str`, `metadata: Optional[dict]` | `entry_id: str`, `chain_hash: str` |

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## License

Apache-2.0
