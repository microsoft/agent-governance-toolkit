# Agent Control Specification spec

`schema/manifest.schema.json` in artifact kits and `spec/schema/manifest.schema.json` in this repository are the authoritative contracts for Agent Control Specification (ACS) manifest syntax. [`SPECIFICATION.md`](SPECIFICATION.md) is the normative specification for runtime semantics, which are the evaluation order, the policy input shape, verdict handling, effect application, and fail closed behavior.

## Manifest top-level properties

- `agent_control_specification_version`
- `metadata`
- `extends`
- `policies`
- `intervention_points`
- `tools`
- `annotators`

## Intervention points

ACS defines these eight intervention points:

1. `agent_startup`
2. `input`
3. `pre_model_call`
4. `post_model_call`
5. `pre_tool_call`
6. `post_tool_call`
7. `output`
8. `agent_shutdown`

Each intervention-point entry selects a value with `policy_target`, may request `annotations`, and references a top-level `policies` entry with `policy.id`.
