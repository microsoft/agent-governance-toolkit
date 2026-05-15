# Governed AI Agent in OpenShell Sandbox

Demonstrates AGT policy enforcement, trust scoring, and audit inside an OpenShell sandbox.

## Prerequisites

- Python 3.10+
- No API keys required

```bash
pip install openshell-agentmesh
```

## How to Run

```bash
python examples/openshell-governed/demo.py
```

## Expected Output

```
  3 allowed actions + 3 denied actions
  Trust decays from 1.00 to 0.55 as violations accumulate
  Full audit trail with timestamps and decision reasons
```

## Related

- [OpenShell Integration Guide](../../docs/integrations/openshell.md)
- [Skill Package](../../agent-governance-python/agentmesh-integrations/openshell-skill/)
