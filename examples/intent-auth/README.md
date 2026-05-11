# Intent-Based Authorization Example

Demonstrates AGT's intent-based authorization: agents declare what they
plan to do, the system approves the plan, and drift is detected when
agents deviate.

## Prerequisites

- Python 3.10+
- No API keys required

```bash
pip install agent-os-kernel
```

## How to Run

```bash
python examples/intent-auth/intent_auth_demo.py
```

## Expected Output

```
  Intent declared: "read customer data" -> APPROVED
  Execute under intent: read_file -> ALLOWED
  Drift detected: delete_file (unplanned) -> trust drops 1.0 -> 0.7
  Strict mode: unplanned action -> HARD BLOCK
  Child intent: sub-agent scoped to parent permissions
```

## What This Demo Shows

1. **Full Lifecycle**: Declare, approve, execute under, and verify an intent
2. **Drift Detection**: An agent tries an unplanned action; trust score drops
3. **Hard Block**: Strict policy that denies any unplanned actions
4. **Child Intents**: Orchestrator scopes sub-agent permissions via inheritance

## Learn More

- [Tutorial 48: Intent-Based Authorization](../../docs/tutorials/48-intent-based-authorization.md)
- [API: intent.py](../../agent-governance-python/agent-os/src/agent_os/intent.py)
