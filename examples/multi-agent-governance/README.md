# Multi-Agent Collective Policy Example

Demonstrates how AGT enforces collective constraints across multiple agents:
rate limits, concurrent agent caps, and alert-only monitoring.

## Prerequisites

- Python 3.10+
- No API keys required

```bash
pip install agentmesh-platform
```

## How to Run

```bash
python examples/multi-agent-governance/multi_agent_policy_demo.py
```

## Expected Output

```
  Rate limit: 3 transfers/min allowed, 4th BLOCKED
  Concurrent cap: 2 agents writing OK, 3rd BLOCKED
  Alert-only: policy logs warning but does not block
  Window stats: real-time activity snapshot printed
```

## What This Demo Shows

1. **Rate Limiting**: Max 3 transfers per minute across all agents
2. **Concurrent Agent Cap**: At most 2 distinct agents writing to DB
3. **Alert-Only**: Non-blocking monitoring policies
4. **Config Loading**: Bulk load policies from dicts/YAML
5. **Window Stats**: Real-time activity snapshot

## Learn More

- [Tutorial 49: Multi-Agent Policies](../../docs/tutorials/49-multi-agent-policies.md)
- [API: multi_agent_policy.py](../../agent-governance-python/agent-mesh/src/agentmesh/governance/multi_agent_policy.py)
