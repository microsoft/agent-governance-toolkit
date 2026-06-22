# flowise-agentmesh

**AGT governance nodes for [Flowise](https://github.com/FlowiseAI/Flowise)** -- policy enforcement, trust gating, audit logging, and rate limiting for visual AI flows.

> Deterministic, LLM-independent governance that plugs into any Flowise chatflow or agentflow.

## Integration Model

Flowise is a Node.js application. AGT governance logic runs in Python. The integration uses a **FastAPI sidecar**: a small Python HTTP server that Flowise calls over HTTP before each tool invocation.

```
[Flowise UI] --> [HTTP Request node] --> [AGT Sidecar :8000] --> allow/block --> [LLM or block message]
```

**Working example with a ready-to-import Flowise flow:**
[`examples/flowise-governance/`](../../../../examples/flowise-governance/)

```bash
cd examples/flowise-governance
pip install -r requirements.txt
uvicorn governance_server:app --port 8000
```

Then import `flowise-flow.json` into Flowise and you have a governed chatflow in under five minutes.

## What It Does

This package provides four governance nodes used inside the sidecar server:

| Node | Purpose |
|------|---------|
| **GovernanceNode** | Evaluate tool calls against YAML policy (allowlist/blocklist, content patterns, argument scanning) |
| **TrustGateNode** | Route agents to trust tiers (trusted / review / blocked) based on score thresholds |
| **AuditNode** | Log all actions to a hash-chain audit trail with SHA-256 tamper evidence |
| **RateLimiterNode** | Token bucket rate limiting per agent and per action |

All nodes are **zero-dependency on LLMs**, fully deterministic, and composable.

## Installation

```bash
pip install flowise-agentmesh
```

Or install from source:

```bash
git clone https://github.com/microsoft/agent-governance-toolkit.git
cd agent-governance-python/agentmesh-integrations/flowise-agentmesh
pip install -e ".[dev]"
```

## Sidecar Server (Flowise Integration)

The sidecar exposes a `/govern` endpoint. Flowise sends a POST with the tool call details; the sidecar returns `{"allowed": true/false, "reason": "..."}`.

Minimal sidecar:

```python
# governance_server.py
from pathlib import Path
from fastapi import FastAPI
from flowise_agentmesh import GovernanceNode, AuditNode, RateLimiterNode

app = FastAPI()
gov     = GovernanceNode(policy_path="policy.yaml", strict_mode=False)
audit   = AuditNode(storage="file", file_path="audit.jsonl", export_format="jsonl")
limiter = RateLimiterNode(max_requests=100, window_seconds=60)

@app.post("/govern")
def govern(data: dict) -> dict:
    rate = limiter.run({"agent_id": data.get("agent_id"), "action": data.get("tool")})
    if not rate["allowed"]:
        return {"allowed": False, "reason": "Rate limit exceeded.", "tool": data.get("tool")}
    result = gov.run(data)
    audit.run({**data, "decision": "allowed" if result["allowed"] else "blocked"})
    return {"allowed": result["allowed"], "reason": result.get("reason"), "tool": data.get("tool")}
```

```bash
pip install flowise-agentmesh fastapi "uvicorn[standard]"
uvicorn governance_server:app --port 8000
```

Payload shape from Flowise:

```json
{
  "tool": "search_web",
  "content": "{{ user input }}",
  "agent_id": "flowise-agent"
}
```

See [`examples/flowise-governance/`](../../../../examples/flowise-governance/) for the production-ready server, a sample policy, and a Flowise flow you can drag-and-drop.

## Direct Python Usage

The nodes can also be used standalone in any Python code:

```python
from flowise_agentmesh import GovernanceNode, TrustGateNode, AuditNode, RateLimiterNode

# Governance check
gov = GovernanceNode(policy_path="policy.yaml")
result = gov.run({"tool": "search_web", "content": "latest news"})
# result["allowed"] == True

# Trust gate
gate = TrustGateNode(min_trust_score=0.7, review_threshold=0.4)
result = gate.run({"agent_id": "agent-1", "trust_score": 0.85})
# result["tier"] == "trusted"

# Audit logging
audit = AuditNode(storage="file", file_path="audit.jsonl", export_format="jsonl")
result = audit.run({"action": "search", "query": "hello"})
# result["chain_valid"] == True

# Rate limiting
limiter = RateLimiterNode(max_requests=10, window_seconds=60)
result = limiter.run({"agent_id": "agent-1", "action": "search"})
# result["allowed"] == True
```

## Composing Nodes

Each node implements `run(input_data: dict) -> dict`. Chain them in your sidecar server:

```python
from flowise_agentmesh import GovernanceNode, TrustGateNode, AuditNode, RateLimiterNode

limiter = RateLimiterNode(max_requests=100, window_seconds=60)
gov     = GovernanceNode(policy_path="policy.yaml")
audit   = AuditNode(storage="memory")
gate    = TrustGateNode(min_trust_score=0.7)

def governance_pipeline(input_data: dict) -> dict:
    rate_result = limiter.run(input_data)
    if not rate_result["allowed"]:
        return rate_result

    gov_result = gov.run(input_data)
    if not gov_result["allowed"]:
        audit.run({"decision": "blocked", **gov_result})
        return gov_result

    audit.run(input_data)
    return gate.run(input_data)
```

`run()` return shapes:

```json
// GovernanceNode -- allowed
{ "allowed": true,  "reason": null,         "tool": "search_web", "output": { ... } }
// GovernanceNode -- blocked
{ "allowed": false, "reason": "Tool 'rm_*' is not allowed by policy", "tool": "rm_data", "output": null }

// TrustGateNode
{ "agent_id": "agent-1", "trust_score": 0.85, "tier": "trusted", "routed_to": "trusted", "output": { ... } }

// AuditNode
{ "audit_index": 0, "audit_hash": "a3f4...", "chain_valid": true, "output": { ... } }

// RateLimiterNode
{ "allowed": true, "remaining_tokens": 99.0, "retry_after": null, "output": { ... } }
```

## Components

### GovernanceNode

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `policy` | `Policy \| str \| dict` | `None` | Policy object, YAML string, or dict |
| `policy_path` | `str` | `None` | Path to YAML policy file |
| `strict_mode` | `bool` | `True` | Require at least one check input |
| `log_level` | `str` | `"INFO"` | Logging level |

### TrustGateNode

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `min_trust_score` | `float` | `0.7` | Minimum score for "trusted" tier |
| `review_threshold` | `float` | `0.4` | Minimum score for "review" tier |

### AuditNode

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `storage` | `str` | `"memory"` | Storage backend: `memory` or `file` |
| `file_path` | `str` | `None` | File path (required when `storage="file"`) |
| `export_format` | `str` | `"json"` | Export format: `json` or `jsonl` |

### RateLimiterNode

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `max_requests` | `int` | `10` | Maximum requests per window |
| `window_seconds` | `float` | `60.0` | Time window in seconds |

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## License

MIT
