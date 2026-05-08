# Multi-Agent Collective Policy Example

Demonstrates how AGT enforces collective constraints across multiple agents:
rate limits, concurrent agent caps, and alert-only monitoring.

## Quick Start

```bash
pip install agentmesh-platform
python multi_agent_policy_demo.py
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
