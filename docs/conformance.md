---
title: Conformance
last_reviewed: 2026-07-11
owner: agent-governance
---

# Conformance

AGT runtime policy conformance is defined by the Agent Control Specification,
the AGT manifest model, and the framework adapter contract.

## Runtime

| Contract | Evidence |
|----------|----------|
| Native manifest validation | `agent-governance-python/agt-policies/tests/test_manifest.py` |
| Runtime verdict and fail-closed behavior | `agent-governance-python/agt-policies/tests/test_runtime.py` |
| Native result and audit schema | `agent-governance-python/agt-policies/tests/test_result.py` |
| Session counters and snapshots | `agent-governance-python/agt-policies/tests/test_session.py` |

## Framework adapters

Adapter mediation is checked in
`agent-governance-python/agent-os/tests/test_adapter_mediation_contract.py`.
Native exception identity is checked in
`agent-governance-python/agent-os/tests/test_adapter_exception_identity.py`.

## MCP and trust

- `agent-governance-python/agent-os/tests/test_spec_mcp_gateway_conformance.py`
- `agent-governance-python/agent-mesh/tests/test_spec_identity_trust_conformance.py`
- `agent-governance-python/agent-mesh/tests/test_spec_mesh_trust_conformance.py`

## Run

```bash
pytest \
  agent-governance-python/agt-policies/tests/test_manifest.py \
  agent-governance-python/agt-policies/tests/test_runtime.py \
  agent-governance-python/agt-policies/tests/test_result.py \
  agent-governance-python/agent-os/tests/test_adapter_mediation_contract.py \
  -v
```
