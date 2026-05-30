# agt-policies (5.0.0a1)

AGT 5.0 policy layer. Wraps the AGT-vendored ACS engine at
`policy-engine/`, adds AGT-specific extensions (manifest resolution,
snapshot builder, evaluation result), and exposes the public Python
API that AGT host code calls.

Status: alpha. M3 deliverable from
`/home/mhabuomar/.copilot/session-state/.../plan.md`.

## What is here so far

- `agt.manifest_resolution` — folder discovery + scope filtering +
  rule merge layer that runs in the host before the engine sees a
  manifest. Implements `spec/agt/AGT-RESOLUTION-1.0.md`.

## What is coming next

- `agt.policies.snapshot` — snapshot builder per
  `spec/agt/AGT-SNAPSHOT-1.0.md`.
- `agt.policies.result` — `EvaluationResult` (replaces v4
  `PolicyCheckResult`).
- `agt.policies.runtime` — Python wrapper over the ACS Python SDK that
  loads a resolved manifest, runs intervention points, applies the
  transform verdict, and emits AGT telemetry events.

## Install (development)

```sh
cd agent-governance-python/agt-policies
pip install -e ".[dev]"
pytest
```
