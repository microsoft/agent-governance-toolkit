# flowise-agentmesh

**AgentMesh governance nodes for [Flowise](https://github.com/FlowiseAI/Flowise)** — policy enforcement, trust gating, audit logging, and rate limiting for visual AI flows.

> Deterministic, LLM-independent governance that plugs into any Flowise chatflow or agentflow.

## What It Does

This package provides four governance nodes designed to sit inline within Flowise flows:

| Node | Purpose |
|------|---------|
| **GovernanceNode** | Evaluate tool calls against YAML policy (allowlist/blocklist, content patterns, argument scanning) |
| **TrustGateNode** | Route agents to trust tiers (trusted / review / blocked) based on score thresholds |
| **AuditNode** | Log all actions to a hash chain audit trail with SHA-256 tamper evidence |
| **RateLimiterNode** | Token bucket rate limiting per agent and per action |

All nodes are **zero-dependency on LLMs**, fully deterministic, and composable.

## Installation

```bash
pip install flowise-agentmesh
```

Or install from source:

```bash
git clone https://github.com/imran-siddique/agentmesh-integrations.git
cd agentmesh-integrations/flowise-agentmesh
pip install -e ".[dev]"
```

## Quick Start

### 1. Define a Governance Policy (YAML)

```yaml
# policy.yaml
allowed_tools:
  - search_*
  - read_file
blocked_tools:
  - rm_*
  - delete_*
blocked_content_patterns:
  - "DROP\\s+TABLE"
  - "rm\\s+-rf"
blocked_argument_patterns:
  - "\\.\\./"
  - "/etc/passwd"
default_action: deny
```

### 2. Use in Python (Custom Flowise Node)

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

## Flowise Integration

### Where These Nodes Fit in a Flow

```
┌─────────────┐    ┌─────────────────┐    ┌──────────────┐    ┌──────────┐
│  User Input  │───▶│  RateLimiterNode │───▶│ GovernanceNode│───▶│ LLM/Agent│
└─────────────┘    └─────────────────┘    └──────────────┘    └──────────┘
                                                │                    │
                                                ▼                    ▼
                                          ┌───────────┐      ┌───────────┐
                                          │ Block Flow │      │ AuditNode │
                                          └───────────┘      └───────────┘
                                                              │
                                                              ▼
                                                        ┌──────────────┐
                                                        │ TrustGateNode │
                                                        └──────────────┘
                                                         ╱      │      ╲
                                                        ▼       ▼       ▼
                                                    Trusted  Review  Blocked
```

### Using as a Flowise Custom Node

Each node implements a `run(input_data: dict) -> dict` interface compatible with Flowise's custom node pattern:

**Input**: A dictionary from the previous node in the flow
**Output**: A dictionary with the governance decision plus `output` key for the next node

Example `run()` return for GovernanceNode:

```json
{
  "allowed": true,
  "reason": null,
  "tool": "search_web",
  "output": { "tool": "search_web", "content": "latest news" }
}
```

When blocked, `output` is `null` and `reason` explains why.

### Example: Governance Pipeline

```python
from flowise_agentmesh import GovernanceNode, TrustGateNode, AuditNode, RateLimiterNode

# Set up pipeline
limiter = RateLimiterNode(max_requests=100, window_seconds=60)
gov = GovernanceNode(policy_path="policy.yaml")
audit = AuditNode(storage="memory")
gate = TrustGateNode(min_trust_score=0.7)

def governance_pipeline(input_data: dict) -> dict:
    # Step 1: Rate limit
    rate_result = limiter.run(input_data)
    if not rate_result["allowed"]:
        return rate_result

    # Step 2: Policy check
    gov_result = gov.run(input_data)
    if not gov_result["allowed"]:
        audit.run({"decision": "blocked", **gov_result})
        return gov_result

    # Step 3: Audit log
    audit.run(input_data)

    # Step 4: Trust gate
    trust_result = gate.run(input_data)
    return trust_result
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
