# Agent Control Specification .NET SDK

This is a thin, stateless .NET surface for Agent Control Specification. It keeps .NET async orchestration in managed code and leaves deterministic intervention point evaluation to a supplied `IAgentControlRuntime`.

`AgentControl.FromPath("manifest.yaml")` builds a control backed by the bundled Rust core through P/Invoke. The native library ships alongside the managed assembly and is loaded at runtime. With no dispatcher arguments the bundled OPA policy dispatcher and annotator dispatcher are wired from the manifest, so a host that uses Rego policies integrates in roughly three lines. Pass `annotatorDispatcher:` and `policyDispatcher:` (or use `FromNative(manifest, ...)`) to override either bundled default, and supply a custom `IAgentControlRuntime` for testing or alternative backends. The zero-config construction section in the root README describes when to supply custom dispatchers.

Manifest and native library load failures happen before an `AgentControl` runtime exists. `FromPath` and `FromNative` surface those failures by throwing during construction, which blocks the host from proceeding. Once construction succeeds, evaluation-time runtime errors are returned as deny verdicts.

For zero-config Rego policies, `ACS_OPA_PATH` is authoritative when set and must point to the OPA binary or its containing directory. The .NET SDK synchronizes `ACS_OPA_PATH` and `PATH` into the native environment before runtime construction so managed environment changes are honored by the P/Invoke core.

Available today:

- enums and records for intervention points, enforcement mode, decisions, verdicts, intervention point requests, and intervention point results
- `ArtifactValidator.Validate(...)` for structured manifest and Rego validation through the shared Rust core
- `IAnnotatorDispatcher`, `IPolicyDispatcher`, and `IAgentControlRuntime` contracts
- `AgentControl.EvaluateInterventionPointAsync()`
- lifecycle/single-point helpers: `EvaluateAgentStartupAsync()`, `EvaluateAgentShutdownAsync()`, `EvaluateInputAsync()`, `EvaluateOutputAsync()`, `EvaluatePreModelCallAsync()`, `EvaluatePostModelCallAsync()`, `EvaluatePreToolCallAsync()`, and `EvaluatePostToolCallAsync()`
- `AgentControl.RunAsync()` for `input` + `output`
- `AgentControl.RunModelAsync()` for `pre_model_call` + `post_model_call`
- `AgentControl.RunModelStreamAsync()` for buffered SSE chat-completion streams over byte arrays or async byte chunks
- `AgentControlStreaming.AssembleSseStream()` and `AgentControlStreaming.SynthesizeSseStream()` for shared streaming conformance fixtures
- `AgentControl.RunToolAsync()` for `pre_tool_call` + `post_tool_call`
- `AgentControl.ProtectToolAsync()` as an alias for `RunToolAsync()`
- `AgentControlMcpToolProvider<TArgs,TResult>` for MCP tool calls
- no-dependency, conceptual adapter shapes:
  - `IAgentControlChatClient<TRequest,TResponse>` and `AgentControlDelegatingChatClient<TRequest,TResponse>` with `UseAgentControl(...)`
  - `AgentControlToolInvocationFilter<TArgs,TOutput>` for duck-typed tool invocation middleware
  - `AgentControlSemanticKernelFunctionFilter<TArgs,TOutput>` plus a no-dependency function invocation context interface mirroring Semantic Kernel filter flow
  - `AgentControlAgentMiddleware<TInput,TOutput>` for duck-typed agent middleware
  - `AgentControlAutoGenMiddleware<TInput,TOutput>` plus a no-dependency invocation context interface mirroring AutoGen middleware flow
  - `AgentControlAgentFrameworkFunctionMiddleware<TArgs,TOutput>` and `AgentControlAgentFrameworkRunMiddleware<TInput,TOutput>` plus the `AgentControlFrameworkAdapters.AgentFramework*` factory methods, mirroring Microsoft Agent Framework's function-calling and agent-run middleware seams (the unified successor to Semantic Kernel and AutoGen)
  - `UnsupportedFrameworkAdapter<TAgent>` and `AgentControlFrameworkAdapters` for loud package-specific gaps
- package-specific adapters:
  - `AgentControlSpecification.AI` wraps real `Microsoft.Extensions.AI.IChatClient` instances with `UseAgentControl(...)` or `AsGuarded(...)`
  - `AgentControlSpecification.SemanticKernel` registers an `IAutoFunctionInvocationFilter` through `IKernelBuilder.UseAgentControl(...)` or `AsGuarded(...)`, and decorates individual `IChatCompletionService` instances with the `AgentControlChatCompletionService` constructor
  - `AgentControlSpecification.AutoGen` wraps real AutoGen `IAgent` instances with `UseAgentControl(...)` or `AsGuarded(...)`
  - `AgentControlSpecification.AgentFramework` wraps real `Microsoft.Agents.AI.AIAgent` instances with `UseAgentControl(...)` or `AsGuarded(...)`

```csharp
var validation = ArtifactValidator.Validate(
    manifestYaml,
    new Dictionary<string, string>
    {
        ["policy.rego"] = regoSource,
    });
```

`RunToolAsync()` and `ProtectToolAsync()` always evaluate both `pre_tool_call` and `post_tool_call`. Manifests used with these helpers must configure both intervention points. If no post-tool policy is needed, configure `post_tool_call` with an allow policy so the helper does not fail closed after the tool returns.

`RunModelAsync()` guards non-streaming model calls and fails closed before upstream invocation when the request carries `stream: true`. Use `RunModelStreamAsync()` for buffered SSE chat-completion streams.

## Chat client and telemetry surfaces

The base `AgentControlSpecification` package has no framework package dependencies. It exposes generic `IAgentControlChatClient<TRequest,TResponse>` and `AgentControlDelegatingChatClient<TRequest,TResponse>` shapes for dependency-light hosts. Install the companion `AgentControlSpecification.AI` package when the host needs wrappers over concrete `Microsoft.Extensions.AI.IChatClient` objects.

`PerfTelemetry` controls timing detail in native runtime evaluation. It is independent from host telemetry export.

## Telemetry

The .NET SDK ships a pure host-side telemetry layer. Pass an `ITelemetrySink` to `AgentControl`, `FromNative`, `FromPath`, `FromPathAsync`, or `FromManifestChain`, and every evaluation emits one redaction-safe `TelemetryEvent` to the sink. Pass `new MultiSink(...)` or the overloads that accept sink collections to fan out to multiple sinks. The default null telemetry sink preserves the prior behavior with no events and no overhead beyond a null check.

```csharp
var sink = new MultiSink(
    new JsonStdoutTelemetrySink(),
    new OtelMetricsTelemetrySink());
var control = AgentControl.FromPath("manifest.yaml", telemetrySink: sink);
```

`TelemetryEvent` mirrors the Rust `core/src/telemetry.rs` field set. It carries `event_type`, `intervention_point`, `decision`, `reason_code`, `error_class`, `policy_id`, `annotators`, `enforcement_mode`, `duration_ms`, `evidence_artefact`, `evidence_verification_pointer_keys`, `action_identity`, and `metadata`. Redaction is the load-bearing invariant. Events never carry raw prompts, tool arguments, tool results, transform values, annotator outputs, policy target payloads, or pointer URL values. A free-text reason is reduced to `policy_reason`, matching the Rust redaction helper.

`policy_id` and `annotators` are resolved from the fully merged manifest by the native core at construction, through the native `PolicyLabels` accessor, so they are populated for every constructor, including `FromManifestChain` and YAML manifests. No host-side manifest parsing is involved, so the SDK needs no YAML parser. A custom `IAgentControlRuntime` that does not implement `IPolicyLabelSource` leaves `policy_id` null, and in that case `annotators` falls back to the executed annotation keys on the result.

This host layer emits exactly one `decision` event per evaluation. It does not replicate the Rust core's second `intervention_point.transformed` event on a `transform` verdict. The transform is observable through `decision == "transform"`.

| Sink | Behavior |
| --- | --- |
| `InMemoryTelemetrySink` | Records events in an `Events` list for tests and inspection. |
| `JsonStdoutTelemetrySink` | Writes one JSON object per line to a `TextWriter`, defaulting to `Console.Out`. |
| `OtelMetricsTelemetrySink` | Emits BCL `System.Diagnostics.Metrics` instruments under meter `agent_control_specification`. |
| `MultiSink` | Fans one event out to several sinks. A failing child is logged and isolated. |

`OtelMetricsTelemetrySink` emits `acs_intervention_allow_total`, `acs_intervention_deny_total`, `acs_intervention_warn_total`, `acs_intervention_escalate_total`, `acs_intervention_transform_total`, and `acs_intervention_duration_ms`. OpenTelemetry .NET collects these BCL metrics natively, so the base SDK does not add an OpenTelemetry NuGet dependency.

Telemetry is never load-bearing. Event construction and sink emission are wrapped together so a failing sink cannot change the verdict or fail evaluation.

## Escalation and approval

In enforce mode a `deny` verdict throws `AgentControlBlockedException`. An `escalate` verdict consults an optional approval resolver, a host callback that decides whether the action proceeds. Supply a resolver on the instance with `new AgentControl(runtime, approvalResolver)` (or `AgentControl.FromNative(manifest, annotator, policy, approvalResolver)`) or override it per call with the `approvalResolver` argument on `RunAsync`, `RunModelAsync`, `RunToolAsync`, and `ProtectToolAsync`. The `ApprovalResolver` delegate returns `ApprovalResolution.Allow(result.ActionIdentity!)`, `ApprovalResolution.Deny()`, or `ApprovalResolution.Suspend(handle, result.ActionIdentity!)`.

The framework-adapter shapes accept the same resolver so approval flows through the adapter layer. `AgentControlDelegatingChatClient` (via `UseAgentControl`), `AgentControlSemanticKernelFunctionFilter`, and `AgentControlAutoGenMiddleware` take an `approvalResolver` at construction; `AgentControlToolInvocationFilter`, `AgentControlAgentMiddleware`, and `AgentControlMcpToolProvider` take a per-call `approvalResolver` on their invocation method, mirroring where each shape accepts its enforcement mode.

- allow proceeds with the original action target. `escalate` verdicts do not return or apply transformed targets
- deny, an unrecognized result, or a resolver that throws raises `AgentControlBlockedException` (the original exception is preserved as `InnerException`)
- suspend raises `AgentControlSuspendedException` carrying the opaque host handle
- with no resolver an `escalate` verdict fails closed to a block

The resolver is consulted only for `escalate` and only in enforce mode. A `deny` never consults it. A resolver that throws `OperationCanceledException` propagates that cancellation rather than failing closed. `AgentControlBlockedException` and `AgentControlSuspendedException` both extend `AgentControlInterruptionException`.

Gaps:

- the base package has no NuGet dependencies beyond the native runtime payload
- package-specific adapters live in companion packages so hosts only restore the framework packages they use

Run the tests when `dotnet` is available. The project is a console harness, so run it rather than using `dotnet test`:

```bash
dotnet run --project tests/AgentControlSpecification.Tests/AgentControlSpecification.Tests.csproj
```
