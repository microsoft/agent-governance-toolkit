---
title: Progressive Governance
last_reviewed: 2026-07-12
owner: docs-team
---

# Progressive Governance

Start with one native ACS manifest, then add host controls only when the risk
requires them.

## Level 1

Create a manifest and evaluate it through `AgtRuntime`.

```python
from agt.policies import AdapterRuntimeSession, AgtRuntime

runtime = AgtRuntime("policies/manifest.yaml")
session = AdapterRuntimeSession(
    runtime,
    agent_id="agent-1",
    session_id="session-1",
)

evaluation = session.evaluate_pre_tool_call(
    tool_name="delete_file",
    args={"path": "report.txt"},
)
assert not evaluation.is_allowed()
```

The manifest owns policy definitions, tool catalogs, intervention-point
bindings, budgets, transforms, and approval.

## Level 2

Add version-controlled Rego or Cedar bundles and use ACS `extends` to compose
resolved manifests. Run `agt lint-policy` and `agt test` in CI.

```bash
agt lint-policy policies/manifest.yaml
agt test policies/manifest.yaml policies/fixtures.json
```

## Level 3

Use an Agent OS framework adapter. Pass the same runtime through `runtime=` so
model, tool, and output paths are mediated by the manifest.

## Level 4

Add AgentMesh identity, trust, and transport controls for multi-agent systems.
These controls remain separate from ACS policy evaluation.

## Level 5

Add sandbox isolation, SRE controls, approval services, and centralized audit.
Sandbox resources and egress belong in `SandboxConfig`, not in policy objects.

| Level | Add when you need |
|-------|-------------------|
| 1 | Deterministic policy checks |
| 2 | Reviewed bundles and replay |
| 3 | Framework lifecycle mediation |
| 4 | Multi-agent identity and trust |
| 5 | Isolation, resilience, and operations |

See [Your First Policy](policy-as-code/01-your-first-policy.md) and
[Agent Control Specification](55-agent-control-specification.md).
