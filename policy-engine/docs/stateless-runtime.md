# Stateless runtime guide

This guide describes how to embed the Rust core in a host or SDK without adding runtime-owned state.

## Evaluation flow

For each intervention-point evaluation, the host calls `Runtime::evaluate_intervention_point` with a complete snapshot. The core then:

1. Finds the intervention point config in the manifest.
2. Resolves `policy_target` against `$snap` (or the `$`/`$.field` snapshot aliases).
3. Projects current tool metadata at `pre_tool_call` and `post_tool_call` by resolving the configured `tool_name_from` snapshot path.
4. Builds preliminary policy input with empty `annotations`.
5. Calls each configured annotator through the host-supplied `AnnotatorDispatcher`.
6. Builds final policy input with annotation results inserted under the compatibility `annotations` field.
7. Prepares the configured Rego policy invocation and calls the host-supplied `PolicyDispatcher`.
8. Normalizes the policy result into a common verdict.
9. Validates any `transform` verdict and, in `enforce` mode, applies the replacement only when the decision is `transform`.

The runtime never performs network I/O, reads policy bundles, calls models, executes tools, stores approvals, expires facts, or drives an async event loop. Operationally, request-scoped structs passed through the host call stack are still stateless; module-level/process-level mutable session registries, global current-session state, and hidden maps keyed by user/session/request are not.

## Intervention snapshots

Use these portable snapshot fields when writing adapters and examples:

| Intervention point | Required snapshot fields |
|---|---|
| `agent_startup` | `$snap.agent`, `$snap.metadata`, or `$` |
| `input` | `$snap.input` |
| `pre_model_call` | `$snap.model_request` |
| `post_model_call` | `$snap.model_response` |
| `pre_tool_call` | `$snap.tool_call.name`, `$snap.tool_call.args` |
| `post_tool_call` | `$snap.tool_call.name`, `$snap.tool_result` |
| `output` | `$snap.output` |
| `agent_shutdown` | `$snap.agent`, `$snap.metadata`, or `$` |

Recommended ambient fields include `$snap.actor`, `$snap.tenant`, `$snap.conversation`, `$snap.messages`, `$snap.approvals`, `$snap.prior_decisions`, `$snap.transport`, and `$snap.metadata`.

The final user-visible response is always `$snap.output` at the `output` intervention point. See [snapshot-contract.md](snapshot-contract.md) for the frozen SDK adapter contract and the golden fixture locations.

## Path roots

Every manifest path has an explicit root and a small deterministic grammar: fields, nested fields, array indices, and bracket-string fields. Missing required paths fail closed; values are preserved exactly without type coercion.

| Manifest field | Allowed root |
|---|---|
| `policy_target` | `$snap`, `$`, `$.field` |
| `tool_name_from` | `$snap`, `$`, `$.field` |
| annotation `from` | preliminary `$pi`, `$policy_target`, `$tool`, `$snap`, `$`, `$.field` |
| `transform.path` | `$policy_target` only |

## Annotators

Top-level `annotators` are declarative metadata (`type: classifier | llm | endpoint`). Each intervention point opts in with `annotations.<name>.from`. The core resolves each `from` path against preliminary policy input/snapshot, then calls `AnnotatorDispatcher::dispatch`. The dispatcher owns the actual HTTP call, classifier invocation, LLM judge call, cache lookup, timeout policy, and retry policy.

Annotator outputs are inserted under `policy_input.annotations.<annotator_name>` for compatibility with existing policy input contracts. Annotator errors fail closed as `runtime_error:annotation_failed`; timeouts fail closed as `runtime_error:annotation_timeout`.

## IFC

Information flow control is supported as stateless policy logic. The runtime performs no IFC check, stores no labels, and propagates no taint. The host supplies source labels in `input.snapshot.ifc.source_labels`, tool clearance remains ordinary manifest metadata projected into `policy_input.tool`, and Rego policies enforce label flow at intervention point sinks. The reusable library `agent_control_specification.lib.ifc` supplies lattice, dominance, maximum sensitivity, allow, and deny helpers. For cross-turn propagation a policy returns the produced data's labels in `verdict.result_labels`; the core returns them verbatim and the host re-supplies them as `ifc.source_labels` on later evaluations. See [ifc-label-flow.md](ifc-label-flow.md).

## Policy dispatchers

`PolicyDispatcher` is a host boundary. The manifest declares reusable top-level `policies` (Rego only) and each intervention point references one with `policy.id` plus the Rego `query`. The core prepares the Rego invocation by passing the per-point `query` and bundle reference alongside the canonical final policy input; the dispatcher owns actual Rego or remote service execution. `test` and `custom` variants exist for test doubles or host-specific adapters; they are not production policy engines.

Policies should return reasons from their own namespace. `runtime_error:*` is reserved for the core.

## Telemetry

`Runtime::with_telemetry` accepts an optional `TelemetrySink`. The default constructor uses a no-op sink. Events use the stable kinds `decision`, `annotator_dispatch`, `policy_evaluation`, `evaluation_timing`, `intervention_point.transformed`, `annotator_failed`, and `policy_failed`. Events carry stable metadata such as intervention point, enforcement mode, policy id, annotator names, decision, reason code, error class, duration, transform status, and action identity when available. Policy target values, tool args/results, annotation values, model messages, transform replacement values, secrets, and PII are not emitted.

## Transform verdicts and transformed policy targets

`transform` is the only mutating verdict. When policy returns a valid `transform` verdict and the mode is `enforce`, `InterventionPointResult::transformed_policy_target` contains the changed policy target. The host is responsible for mapping it back into the model request, tool arguments, tool result, or final output it controls.

In `evaluate_only`, a `transform` verdict is validated but not applied, so `transformed_policy_target` remains `None`. `allow`, `warn`, `deny`, and `escalate` never mutate the policy target.

## Streaming and parallel tool calls

The core sees complete snapshots, not live streams. Hosts aggregate streamed model output before `post_model_call` and streamed final output before `output`.

### Streaming behavior and leakage controls

The safe default is buffer before disclose. A host must accumulate the full streamed value, build the snapshot from the complete aggregated content, evaluate the relevant intervention point, and only then release the content to the principal or to a downstream consumer. A host that forwards partial chunks to a user, a tool, or a model before the governing point has returned an `allow` or `warn` verdict has left the ACS security envelope for that data flow, because the core has not yet seen the content it is being asked to govern.

Buffering is bounded by the snapshot size resource limit described above. When aggregated streamed content would exceed the configured snapshot byte budget the host must fail closed by stopping aggregation and treating the activity as a `runtime_error:resource_limit_exceeded` deny rather than disclosing the partial value or silently truncating it. A host that needs to govern very large outputs raises the limit deliberately and accepts the memory cost rather than relaxing the buffer cap into a leak.

Because ACS validates only the complete aggregated value, chunk boundaries cannot be used to evade detection. A phrase split across two transport chunks, a multibyte UTF-8 sequence split across a network packet, or a grapheme cluster split across a token boundary all reassemble into the same complete string before the snapshot is built, so policy and annotators observe the reassembled content rather than the fragments. This is the structural reason ACS does not expose a windowed or per-chunk streaming validator. There is no window size or overlap parameter to misconfigure into missing a cross boundary pattern, because there is no mid-stream validation surface in the core.

Reasoning or thinking tokens are governed under the same rule. A host that streams intermediate reasoning to a destination outside the model loop must aggregate and evaluate that disclosure at the appropriate point, and a host that keeps reasoning internal still aggregates it into the snapshot fields the policy expects.

Adapters that wrap streaming providers must document whether they buffer output before yielding it or emit it only after validation, so an integrator can tell from the adapter contract whether a given stream can leak content before the governing verdict. An adapter that yields tokens to the principal as they arrive and validates only afterward provides observability rather than enforcement for that path, and its documentation must say so.

`Runtime` is immutable after construction and `evaluate_intervention_point` is reentrant. For parallel tool calls, invoke `pre_tool_call` and `post_tool_call` separately for each tool invocation, including an invocation ID in `$snap.tool_call.id` when correlation is useful. The invocation ID is host supplied and optional in the snapshot model.

## Removed concepts

The stateless runtime intentionally excludes the old stateful-control concepts: state and endpoint intervention points, a separate hooks block, the per-point `ifc:` block, non-Rego in-manifest policy engines, variables, lifetimes, event bus, resolvers, expression language, guard-policy merging, auto-resolution, durable runtime state, and manifest-level fail-open behavior. `tool_name_from` and `policy_target_kind` are current ACS manifest fields.
