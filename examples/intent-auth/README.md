# Intent-Based Authorization Example

Demonstrates AGT's intent-based authorization: agents declare what they
plan to do, the system approves the plan, and drift is detected when
agents deviate.

## Quick Start

```bash
pip install agent-os-kernel
python intent_auth_demo.py
```

## What This Demo Shows

1. **Full Lifecycle**: Declare, approve, execute under, and verify an intent
2. **Drift Detection**: An agent tries an unplanned action; trust score drops
3. **Hard Block**: Strict policy that denies any unplanned actions
4. **Child Intents**: Orchestrator scopes sub-agent permissions via inheritance

## Learn More

- [Tutorial 48: Intent-Based Authorization](../../docs/tutorials/48-intent-based-authorization.md)
- [API: intent.py](../../agent-governance-python/agent-os/src/agent_os/intent.py)
