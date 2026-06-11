# Production deployment

ACS is an in-process security runtime for mediated agent paths. It evaluates a host supplied snapshot, invokes host supplied annotator and policy dispatchers, normalizes the verdict, and returns an optional transformed policy target. The host still owns the agent loop, model calls, tool execution, approval path, networking, credentials, and release process.

Read the [Required Integration Invariants](security-model.md#required-integration-invariants) and [Production Readiness Checklist](security-model.md#production-readiness-checklist) before using this guide. This page expands those requirements into deployment steps rather than replacing them.

## Deployment mode

| Mode | Operational use | Host behavior |
| --- | --- | --- |
| `evaluate_only` | Shadow evaluation, policy tuning, and pre-production comparison. | Record verdicts and reasons while the host may continue with the original action. Do not claim enforcement coverage from this mode. |
| `enforce` | Production blocking and transformation. | Block `deny`, route `escalate` to a host approval path, and apply returned transformed policy targets only for `transform`. |

Start new policies in `evaluate_only` on mirrored or low risk traffic. Promote to `enforce` only after telemetry shows expected allow, warn, deny, and escalate rates for each governed intervention point.

## Fail closed posture

Runtime failures become deny verdicts with reserved runtime error reasons. The host must treat those verdicts as blocking in `enforce` mode. Do not add a fail open bypass around manifest validation, path resolution, annotator dispatch, policy dispatch, policy output normalization, transform validation, approval identity checks, or resource limits.

| Failure class | Reserved reason family |
| --- | --- |
| Manifest, intervention point, path, and tool projection failures | `runtime_error:manifest_invalid`, `runtime_error:intervention_point_unknown`, `runtime_error:path_missing`, `runtime_error:path_type_mismatch`, `runtime_error:tool_unknown` |
| Annotator failures | `runtime_error:annotation_failed`, `runtime_error:annotation_timeout` |
| Policy dispatcher and output failures | `runtime_error:policy_invocation_failed`, `runtime_error:policy_output_invalid` |
| Transform and approval failures | `runtime_error:transform_invalid`, `runtime_error:transform_target_forbidden`, legacy `runtime_error:effect_*` compatibility reasons, `runtime_error:approval_action_mismatch` |
| Resource limits | `runtime_error:resource_limit_exceeded` |

## Host integration invariants

The security model defines the normative invariants. Operationally, every workload owner should prove the following items before the workload receives production traffic.

| Area | Production check |
| --- | --- |
| Mediation coverage | Inventory every governed model request, model response, tool call, tool result, user input, final output, startup path, and shutdown path. Tests should fail when any governed path skips ACS. |
| Stream handling | Aggregate streamed model and final output before `post_model_call` and `output`. Release content only after the verdict is `allow` or `warn`, or after a `transform` verdict has produced the transformed target to release. |
| Policy target binding | Ensure the manifest `policy_target` selects the exact value the host will send, execute, store, or disclose. Treat the evaluated value as immutable until the host applies the verdict. |
| Transform application | Map `transformed_policy_target` back into the host object only when the verdict is `transform` in `enforce` mode. `allow`, `warn`, `deny`, and `escalate` never mutate the policy target. |
| Deny handling | Stop the governed action on `deny`. Preserve the decision, reason, intervention point, policy id, manifest version, bundle version, and runtime version when audit requires it. |
| Escalation | Route `escalate` to a host approval path. Fail closed when no path is configured, the path fails, or the result does not match the current action identity. |
| Parallel tools | Evaluate each concrete tool invocation with separate `pre_tool_call` and `post_tool_call` calls. Handle partial batch failure deliberately. |
| JSON fidelity | Preserve JSON types and character offsets across SDK and FFI boundaries. Convert redaction spans to ACS character offsets before policy returns them. |

## Dispatcher limits and timeouts

ACS does not own network I/O or async cancellation for dispatchers. The host must bound policy and annotator work around the synchronous core call.

| Limit | Default |
| --- | --- |
| Snapshot serialized size | `1_048_576` bytes |
| Policy input depth | `64` |
| Annotators per intervention point | `16` |
| Annotator output serialized size | `262_144` bytes |
| Manifest extends depth | `16` |
| Merged manifest serialized size | `1_048_576` bytes |
| Manifest HTTPS extends body size | `1_048_576` bytes |
| Manifest HTTPS extends timeout | `30_000` ms |
| Manifest HTTPS extends redirects | `5` |

Set policy dispatcher timeouts shorter than customer facing request deadlines. Set annotator timeouts per annotator class and fail closed when the dispatcher reports an error or timeout. Keep gateway payload caps aligned with snapshot and manifest limits so oversized requests fail before expensive policy work begins.

## Telemetry defaults

The runtime telemetry contract is content minimized by default. Events carry low cardinality metadata such as event kind, intervention point, decision, reason code, policy id, annotator names, mode, duration, counts, and stable metadata. The core does not emit raw policy targets, tool arguments, tool results, model messages, annotation values, secrets, or personal data.

Use the no-op sink for local tests and a host supplied sink for production export. If using the OpenTelemetry bridge, alert from `acs_intervention_deny_total`, `acs_intervention_warn_total`, `acs_intervention_escalate_total`, `acs_intervention_allow_total`, and `acs_intervention_duration_ms`. Enable perf telemetry only at the level needed for operations.

## Manifest and bundle integrity

Treat manifests, Rego bundles, OPA binaries, SDK packages, native libraries, and adapter code as security critical release artifacts. Protect them with review, provenance, pinning, vulnerability scanning, and deploy promotion controls. File based manifest loading may compose file and HTTPS `extends`; string and FFI loaders must receive an already merged manifest. Pin HTTPS `extends` with `integrity` or `sha256` when transport trust and repository controls are not sufficient for the deployment.

Record the manifest version, bundle version, policy query, runtime version, SDK version, and host adapter version alongside production decisions when those fields are needed for audit or rollback.

## Pre-production readiness checklist

| Check | Evidence |
| --- | --- |
| Invariant review complete | Link to the workload review against the security model invariants. |
| Coverage tests pass | Tests exercise every governed path and fail on an unmediated path. |
| Mode plan approved | Each intervention point has an `evaluate_only` bake window and an `enforce` promotion criterion. |
| Runtime errors handled | Host blocks every reserved runtime error reason in `enforce` mode. |
| Dispatcher budgets set | Policy and annotator timeouts, retries, circuit breakers, concurrency caps, and rate limits are configured. |
| Resource limits reviewed | Defaults are accepted or tuned with matching gateway caps. |
| Telemetry reviewed | Export excludes sensitive payloads and includes reason, decision, mode, intervention point, policy id, and dispatcher failure events. |
| Integrity controls enabled | Manifest, bundle, SDK, native library, OPA, and adapter versions are pinned and review protected. |
| Approval path tested | `escalate` allows, denies, suspends, and identity mismatch failure are tested. |
| Rollback rehearsed | Manifest, bundle, SDK, and native library rollback steps are tested with representative traffic. |
