# agt-policies (5.0.0a1)

AGT 5.0 policy layer. Wraps the AGT-vendored ACS engine at
`policy-engine/`, adds AGT-specific extensions (manifest resolution,
snapshot builder, evaluation result), and exposes the public Python
API that AGT host code calls.

Status: alpha.

## What is here

- `agt.manifest_resolution` — folder discovery + scope filtering +
  rule merge layer that runs in the host before the engine sees a
  manifest. Implements `spec/agt/AGT-RESOLUTION-1.0.md`.
  (`discover`, `scope`, `merge`, `build`.)
- `agt.policies.snapshot` — snapshot builder per
  `spec/agt/AGT-SNAPSHOT-1.0.md`.
- `agt.policies.bridge` — renders a v4 `GovernancePolicy` into an ACS
  manifest + OPA rego module.
- `agt.policies.result` — `EvaluationResult` (replaces v4
  `PolicyCheckResult`).
- `agt.policies.runtime` — Python wrapper over the ACS Python SDK that
  loads a resolved manifest, runs intervention points, applies the
  transform verdict, enforces approval, and emits AGT telemetry events.

## Security invariants

The host layer is fail-closed by design. Notably: governance files
that resolve outside the workspace root are rejected; directory-style
scopes (`dir/`) cover their subtree; a parent `deny` cannot be
neutralised by a child `allow` whose condition overlaps it; malformed
budget counters and approval-resolver timeouts deny rather than
silently allow.

## Install (development)

```sh
cd agent-governance-python/agt-policies
pip install -e ".[dev]"
pytest
```
