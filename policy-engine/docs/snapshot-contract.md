# Snapshot and policy-input contract

This is the frozen contract SDK adapters target when calling the stateless core.

## Intervention-point snapshots

Every `Runtime::evaluate_intervention_point` call passes one complete JSON snapshot for exactly one intervention point. The final user-visible response is always `output`.

| Intervention point | Required snapshot fields |
|---|---|
| `agent_startup` | `agent` plus optional `metadata` |
| `input` | `input` |
| `pre_model_call` | `model_request` |
| `post_model_call` | `model_response` |
| `pre_tool_call` | `tool_call.name`, `tool_call.args`, optional `tool_call.id` |
| `post_tool_call` | `tool_call.name`, `tool_result`, optional `tool_call.id` |
| `output` | `output` |
| `agent_shutdown` | `agent` or full shutdown snapshot plus optional `reason` |

Common ambient fields such as `actor`, `tenant`, `conversation`, `messages`, `approvals`, `prior_decisions`, `transport`, and `metadata` stay inside the snapshot; the core does not read hidden session state.

## Tool call identity

The `tool_call.id` field carries the caller-supplied invocation identity on the `pre_tool_call` and `post_tool_call` snapshots, and the snapshot model treats it as optional. When a value is present every SDK includes the identical value on both the pre and post snapshots so a policy that keys escalation, audit, deduplication, or transforms on it observes one stable id across the surrounding mediation.

Every SDK host API treats `tool_call.id` uniformly. The Rust, Python, Node, and .NET host APIs all model the id as optional, validate it as a string whose length is greater than zero when one is supplied, preserve the supplied bytes including whitespace, and omit the `tool_call.id` field from the snapshot entirely when no value is supplied. No SDK layer fabricates a synthetic id into the snapshot, because the id participates in the canonical policy input and therefore in the sha256 action identity, so a fabricated value would corrupt action identity and break determinism across pre and post evaluation. A host-correlation id that an integration mints for its own bookkeeping stays outside the snapshot. The GHCP integration follows this rule by minting an internal admission-correlation id while still omitting `tool_call.id` from the snapshot whenever no host id exists.

Policy authors must therefore treat `tool_call.id` as optional in the data model. A policy that requires an id should deny explicitly when the field is absent rather than assume it always exists. The reusable `agent_control_specification.lib.tool_call` Rego helpers in `policy/lib/tool_call.rego` provide `valid_tool_call_id` and `require` for this deny-on-absence pattern.

## Policy input

The core builds this exact policy-input shape for policy dispatchers:

```json
{
  "intervention_point": "pre_tool_call",
  "policy_target": {
    "kind": "tool_args",
    "path": "$snap.tool_call.args",
    "value": {}
  },
  "snapshot": {},
  "annotations": {},
  "tool": null
}
```

`annotations` is retained as the internal field for annotation outputs: each per-point `annotations.<name>` entry is dispatched through the host and inserted at `policy_input.annotations.<name>`. There is no public top-level `annotations`, `request`, `resource`, or `tools` root in policy input. Current tool metadata is projected as `tool` only at the `pre_tool_call` and `post_tool_call` intervention points, where the runtime resolves the configured `tool_name_from` path and projects the matching `tools` catalog entry; at all other points it is `null`.

Golden examples are frozen under `tests/fixtures/policy-inputs/` and are checked by Rust integration tests.

## Manifest invariants

Canonical manifests live under `tests/fixtures/manifests/`. They use:

- top-level `intervention_points` with only `agent_startup`, `input`, `pre_model_call`, `post_model_call`, `pre_tool_call`, `post_tool_call`, `output`, and `agent_shutdown`
- top-level `policies`, referenced per point by `policy.id`
- top-level `annotators` with `type: classifier | llm | endpoint`
- per-point `annotations`
- array-only `extends`, resolved by file-based loaders relative to the including manifest for paths and over HTTPS for URL entries; string and FFI loaders retain `extends` as data but cannot build an enforcing runtime while it is non-empty
- `policy_target` paths rooted in `$snap`, `$`, or `$.field`

## Operational statelessness

Allowed: request-scoped structs, local variables, futures/tasks, and immutable runtime/manifest handles passed through a call stack for one evaluation or one host-managed request. The host may include all needed memory, approvals, prior decisions, and transport facts explicitly in the snapshot.

Forbidden: module-level, process-level, or singleton mutable session registries that affect verdicts; hidden maps keyed by user/session/request; global current-session state; background tasks that mutate core-owned session facts; and any durable variable/lifetime/event-bus behavior inside the core. External policy/annotation systems may keep their own operational caches, but adapter decisions must be reproducible from the manifest, the explicit snapshot, and dispatcher outputs.
