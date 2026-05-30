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
| `pre_tool_call` | `tool_call.id`, `tool_call.name`, `tool_call.args` |
| `post_tool_call` | `tool_call.id`, `tool_call.name`, `tool_result` |
| `output` | `output` |
| `agent_shutdown` | `agent` or full shutdown snapshot plus optional `reason` |

Common ambient fields such as `actor`, `tenant`, `conversation`, `messages`, `approvals`, `prior_decisions`, `transport`, and `metadata` stay inside the snapshot; the core does not read hidden session state.

## Tool call identity

The `tool_call.id` field carries the caller-supplied invocation identity on the `pre_tool_call` and `post_tool_call` snapshots, and the underlying snapshot model treats it as optional. When a value is present every SDK includes the identical value on both the pre and post snapshots so a policy that keys escalation, audit, deduplication, or transforms on it observes one stable id across the surrounding mediation. No SDK ever synthesizes a value, which means no SDK invents a random id, a deterministic hash id, a placeholder, or an empty string.

SDK host APIs differ deliberately in whether they demand the id. The Python, Node, and .NET host APIs require the caller to supply a non-empty `tool_call_id` and fail before policy evaluation when it is missing, reflecting a host-correlation contract where model and MCP style invocation ids are operationally important for tying tool calls to responses and audit events. The Rust host API models the id as optional through `ToolRunOptions { tool_call_id }` and omits the `tool_call.id` field from the snapshot when no value is supplied. That omission is deterministic and load-bearing for first-party integrations such as the rig adapter, which wraps arbitrary tools invoked outside any model or MCP context that would carry a JSON-RPC call id.

Policy authors must therefore treat `tool_call.id` as optional in the data model. A policy that requires an id should deny explicitly when the field is absent rather than assume it always exists.

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

`annotations` is retained as the internal field for annotation outputs: each per-point `annotations.<name>` entry is dispatched through the host and inserted at `policy_input.annotations.<name>`. There is no public top-level `annotations`, `request`, `resource`, or `tools` root in policy input. Current tool metadata is projected as `tool` only at the `pre_tool_call` and `post_tool_call` intervention points, where the runtime derives the invoked tool name from `$snap.tool_call.name` and projects the matching `tools` catalog entry; at all other points it is `null`.

Golden examples are frozen under `tests/fixtures/policy-inputs/` and are checked by Rust integration tests.

## Manifest invariants

Canonical manifests live under `tests/fixtures/manifests/`. They use:

- top-level `intervention_points` with only `agent_startup`, `input`, `pre_model_call`, `post_model_call`, `pre_tool_call`, `post_tool_call`, `output`, and `agent_shutdown`
- top-level `policies`, referenced per point by `policy.id`
- top-level `annotators` with `type: classifier | llm | endpoint`
- per-point `annotations`
- array-only `extends`, resolved by file-based path loaders relative to the including manifest; string and FFI loaders retain `extends` as data but cannot build an enforcing runtime while it is non-empty
- `policy_target` paths rooted in `$snap`, `$`, or `$.field`

## Operational statelessness

Allowed: request-scoped structs, local variables, futures/tasks, and immutable runtime/manifest handles passed through a call stack for one evaluation or one host-managed request. The host may include all needed memory, approvals, prior decisions, and transport facts explicitly in the snapshot.

Forbidden: module-level, process-level, or singleton mutable session registries that affect verdicts; hidden maps keyed by user/session/request; global current-session state; background tasks that mutate core-owned session facts; and any durable variable/lifetime/event-bus behavior inside the core. External policy/annotation systems may keep their own operational caches, but adapter decisions must be reproducible from the manifest, the explicit snapshot, and dispatcher outputs.
