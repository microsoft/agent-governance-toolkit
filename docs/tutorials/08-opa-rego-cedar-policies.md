---
title: Rego and Cedar in ACS
last_reviewed: 2026-10-23
owner: docs-team
---

# Rego and Cedar in ACS

ACS manifests declare Rego and Cedar policies under `policies`.

Rego policies reference a bundle and query. Cedar policies use the native
inline policy set or file fields defined by the manifest schema. Bind the
policy identifier at one or more intervention points.

## Default evaluation

The host default policy dispatcher evaluates both engines. A manifest that
declares only Cedar policies needs no host-supplied dispatcher, and one manifest
may combine Rego and Cedar policies. Rego evaluation uses the OPA executable
selected by the host, as before.

```yaml
agent_control_specification_version: 0.4.0-alpha.1
policies:
  input_guard:
    type: cedar
    policy_set: |
      @id("blocked_inputs")
      forbid(principal, action, resource) when {
        context.input.text == "ignore previous instructions"
      };
      permit(principal, action, resource);
intervention_points:
  input:
    policy_target_kind: user_input
    policy:
      id: input_guard
    policy_target: $.input
```

A contributing `permit` may carry an `@advice` annotation whose JSON object
matches `cedar_advice.schema.json`. The dispatcher translates that advice into
warnings, an approval request, or a transform. Advice that does not match the
schema fails closed. The runtime reports dispatcher errors as
`runtime_error:policy_invocation_failed` under the ACS dispatcher contract, and
the underlying Cedar error is `runtime_error:policy_output_invalid` when the
advice is malformed.

The `test` and `custom` policy types have no bundled evaluator. A manifest that
declares either type with the default dispatcher fails at construction. Supply a
host `PolicyDispatcher` for those types.

See the [manifest schema](https://github.com/microsoft/agent-governance-toolkit/blob/main/policy-engine/spec/schema/manifest.schema.json)
and [ACS specification](https://github.com/microsoft/agent-governance-toolkit/blob/main/policy-engine/spec/SPECIFICATION.md).
