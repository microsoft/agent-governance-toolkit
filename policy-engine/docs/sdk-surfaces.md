# SDK surfaces

AGT's Rust, Python, Node.js and .NET SDKs wrap the published
[`agent-control-spec`](https://github.com/responsibleai/agent-control-spec)
engine. They retain AGT's host API and framework adapters. The standalone
upstream SDKs expose a different API built around the
[Agent Hooks contract](https://github.com/responsibleai/agent-hooks).

The C ABI is implemented in `sdk/rust/src/ffi.rs` and ships as
`libagent_control_specification.so` on Linux. The Python PyO3 extension is a
different artifact and may require Python runtime symbols when loaded outside
Python. ACS owns strings returned by `acs_runtime_evaluate` and error
out-parameters; hosts release them with `acs_free_string`. Hosts own callback
return strings, released through `AcsFreeResultCallback`.
`acs_builder_build` consumes the builder on success or failure.

`acs_builder_from_path` resolves resources relative to the manifest file.
String constructors require resolved `extends`; relative bundle paths have
no manifest directory and depend on the process working directory. The C ABI
returns a liftable deny for approval. The managed SDK or calling host resolves
it before proceeding.

Every SDK exposes:

- a base intervention-point evaluation API over a native runtime client (`evaluate_intervention_point` / `evaluateInterventionPoint` / `EvaluateInterventionPointAsync`)
- host-supplied annotator and policy dispatchers as interfaces or protocols
- generic run wrappers that enforce `input` and `output`
- model wrappers that enforce `pre_model_call` and `post_model_call`
- tool wrappers that enforce `pre_tool_call` and `post_tool_call`
- an `enforce` seam that resolves a verdict into proceed, block, or suspend, consulting an optional approval resolver for `escalate`

On top of that base, the SDKs ship framework adapters where the framework and language support them. The supported framework matrix is documented in [adapter-matrix.md](adapter-matrix.md).

The SDKs own host async orchestration, stream aggregation, tool execution,
approval resolution, transform application and framework type mapping. The
upstream engine evaluates policy and returns a verdict with its policy input.
It does not apply a transform to the host's snapshot.

Manifest and native library load failures can occur before a runtime exists. SDK constructors surface those failures by refusing construction, which is a fail closed outcome for the host. Once construction succeeds, evaluation-time runtime errors are returned as deny verdicts.

For zero-config Rego policies, `$ACS_OPA_PATH` is authoritative when set and must point to the OPA binary or its containing directory. A bad explicit path fails closed instead of falling back to another `opa` on `PATH`.

SDK enforcement boundaries that synthesize a fail closed verdict use the same content safe telemetry schema when a host enables telemetry. Approval resolver failures report `host_error:approval_resolver_failed`. Streaming helpers that cannot assemble a complete snapshot report `host_error:streaming_unsupported`. Adapters that detect unsupported framework methods report `host_error:adapter_unsupported`. JSON wire bindings that receive malformed intervention request envelopes report `runtime_error:request_invalid`. These events may carry the action identity only when it already exists from the evaluated policy input.

Approval resolvers should return the action identity from the liftable `deny` result they approved. Tests should also mutate an approval-relevant field in a copied policy input and confirm stale approvals fail with `host_error:approval_identity_mismatch`. This pattern proves that approval is bound to the exact canonical policy input for the action.
