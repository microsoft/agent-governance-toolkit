# Agent Control Specification spec

The [upstream ACS specification](https://github.com/responsibleai/agent-control-spec/blob/main/spec/SPECIFICATION.md)
and [schema](https://github.com/responsibleai/agent-control-spec/tree/main/spec/schema)
define the decision engine contract.
[Agent Hooks](https://github.com/responsibleai/agent-hooks) defines interception
points, verdict types and host obligations.

[`SPECIFICATION.md`](SPECIFICATION.md) and `schema/manifest.schema.json` in
this directory document AGT's compatibility profile and authoring validation.
They must be read with the [retarget guide](../docs/acs-retarget.md), which
identifies the pinned engine and the restrictions AGT adds. A local schema
check does not replace validation by that engine.

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
