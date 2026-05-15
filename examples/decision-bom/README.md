# Decision BOM Example

Demonstrates how AGT reconstructs a complete Bill of Materials for any
governance decision, on demand, from existing observability signals.

## Prerequisites

- Python 3.10+
- No API keys required

```bash
pip install agentmesh-platform
```

## How to Run

```bash
python examples/decision-bom/decision_bom_demo.py
```

## Expected Output

```
  Partial BOM (audit-only): 60% completeness, 3 fields populated
  Full BOM (all signals):   100% completeness, 7 field categories
  Batch: 5 decisions reconstructed for agent "analyst" in time range
  JSON export: structured output ready for audit reporting
```

## What This Demo Shows

1. **Partial BOM**: Reconstruction with just audit logs (60% completeness)
2. **Full BOM**: All 4 signal sources for 100% completeness
3. **Field Categories**: Identity, trust, policy, action, context, outcome, lineage
4. **Batch Reconstruction**: All decisions by an agent in a time range
5. **JSON Export**: Structured output for audit reporting

## Learn More

- [Tutorial 50: Decision BOM](../../docs/tutorials/50-decision-bom.md)
- [API: decision_bom.py](../../agent-governance-python/agent-mesh/src/agentmesh/governance/decision_bom.py)
