# Cedarling Governed Agent

Demonstrates how to integrate [Cedarling](https://github.com/JanssenProject/jans/tree/main/jans-cedarling)
with AGT's `PolicyEvaluator` using the `cedarling-agentmesh` community integration package.

AGT core is not modified. The integration is registered as an external backend.

## Run

```bash
pip install agent-os-kernel cedarling_agentmesh
python example.py
```

Optional — enable in-process Cedarling evaluation:

```bash
pip install cedarling-python
python example.py
```

Or point at an existing Cedarling HTTP service:

```bash
CEDARLING_URL=http://cedarling.internal:8080 python example.py
```

## What it shows

- `CedarlingBackend` registered with `PolicyEvaluator.add_backend()`
- Auto-mode runtime selection (Python → HTTP → safe denial)
- Normalized `BackendDecision` output with timing and diagnostics
- Zero modifications to `agent-os-kernel`
