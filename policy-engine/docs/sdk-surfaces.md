# SDK surfaces

The Rust, Python, Node.js, and .NET SDKs are thin host-side wrappers over the stateless Agent Control Specification core. Each binds to the same native core (Rust in-process, Python via pyo3, Node via napi, .NET via P/Invoke) and adds host orchestration; the host enforces the verdicts the core returns.

Native hosts can bind directly through the C ABI declared in `core/include/agent_control_specification.h`. Artifact kits include the standalone `libagent_control_specification_core.so` for this surface. The Python PyO3 extension is not the public C ABI artifact and may require Python runtime symbols when loaded from a non-Python process. ACS owns strings returned by `acs_runtime_evaluate` and error out-parameters, and hosts release them with `acs_free_string`. Hosts own callback return strings, and ACS releases them through the paired host `AcsFreeResultCallback`. `acs_builder_build` consumes the builder on success or failure. `acs_builder_from_path` resolves relative manifest resources against the manifest file location. YAML string constructors do not carry a base directory, so relative Rego bundles and file-based `extends` are resolved against the host process current working directory. The C ABI exposes escalation as a verdict only. Approval resolver orchestration is available through SDK approval seams or host code around the returned C ABI result.

Every SDK exposes:

- a base intervention-point evaluation API over a native runtime client (`evaluate_intervention_point` / `evaluateInterventionPoint` / `EvaluateInterventionPointAsync`)
- host-supplied annotator and policy dispatchers as interfaces or protocols
- generic run wrappers that enforce `input` and `output`
- model wrappers that enforce `pre_model_call` and `post_model_call`
- tool wrappers that enforce `pre_tool_call` and `post_tool_call`
- an `enforce` seam that resolves a verdict into proceed, block, or suspend, consulting an optional approval resolver for `escalate`

On top of that base, the SDKs ship framework adapters where the framework and language support them. The supported framework matrix is documented in [adapter-matrix.md](adapter-matrix.md).

The SDKs own host async orchestration, stream aggregation, tool execution, approval resolution, and framework type mapping. The native core remains responsible for deterministic intervention-point evaluation, policy input construction, verdict normalization, and policy-target-only effects.

Manifest and native library load failures can occur before a runtime exists. SDK constructors surface those failures by refusing construction, which is a fail closed outcome for the host. Once construction succeeds, evaluation-time runtime errors are returned as deny verdicts.

For zero-config Rego policies, `$ACS_OPA_PATH` is authoritative when set and must point to the OPA binary or its containing directory. A bad explicit path fails closed instead of falling back to another `opa` on `PATH`.

SDK enforcement boundaries that synthesize a fail closed verdict use the same content safe telemetry schema when a host enables telemetry. Approval resolver failures report `runtime_error:approval_resolver_failed`. Streaming helpers that cannot assemble a complete snapshot report `runtime_error:streaming_unsupported`. Adapters that detect unsupported framework methods report `runtime_error:adapter_unsupported`. JSON wire bindings that receive malformed intervention request envelopes report `runtime_error:request_invalid`. These events may carry the action identity only when it already exists from the evaluated policy input.

Approval resolvers should return the action identity from the `escalate` result they approved. Tests should also mutate an approval-relevant field in a copied policy input and confirm stale approvals fail with `runtime_error:approval_action_mismatch`. This pattern proves that approval is bound to the exact canonical policy input for the action.
