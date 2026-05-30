# SDK surfaces

The Rust, Python, Node.js, and .NET SDKs are thin host-side wrappers over the stateless Agent Control Specification core. Each binds to the same native core (Rust in-process, Python via pyo3, Node via napi, .NET via P/Invoke) and adds host orchestration; the host enforces the verdicts the core returns.

Every SDK exposes:

- a base intervention-point evaluation API over a native runtime client (`evaluate_intervention_point` / `evaluateInterventionPoint` / `EvaluateInterventionPointAsync`)
- host-supplied annotator and policy dispatchers as interfaces or protocols
- generic run wrappers that enforce `input` and `output`
- model wrappers that enforce `pre_model_call` and `post_model_call`
- tool wrappers that enforce `pre_tool_call` and `post_tool_call`
- an `enforce` seam that resolves a verdict into proceed, block, or suspend, consulting an optional approval resolver for `escalate`

On top of that base, the SDKs ship framework adapters where the framework and language support them. The supported framework matrix is documented in [adapter-matrix.md](adapter-matrix.md).

The SDKs own host async orchestration, stream aggregation, tool execution, approval resolution, and framework type mapping. The native core remains responsible for deterministic intervention-point evaluation, policy input construction, verdict normalization, and policy-target-only effects.
