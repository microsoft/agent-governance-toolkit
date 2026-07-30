# Agent Control Specification Node SDK

Phase A exposes the synchronous Rust core through a thin napi-rs binding. Build the native addon before using the package locally:

```sh
npm install
npm run build
```

```js
const { AgentControl, InterventionPoint } = require("agent-control-specification");

// Zero-config. With no dispatcher arguments the bundled OPA policy dispatcher and
// annotator dispatcher are wired from the manifest, so a Rego-policy host needs no
// dispatcher code.
const agentControl = AgentControl.fromPath("manifest.yaml");

const result = await agentControl.evaluateInterventionPoint(
  InterventionPoint.Input,
  { input: { text: "hello" } },
);
```

Validate authored manifest and Rego strings without constructing a runtime:

```js
const { validateArtifacts } = require("agent-control-specification");

const validation = await validateArtifacts(manifestYaml, {
  "policy.rego": regoSource,
});
```

Supply host-specific dispatchers when annotators are local or policy outputs need post-processing. The dispatcher arguments are optional and default independently, so a host can override the annotator dispatcher while keeping the bundled OPA policy default:

```js
const agentControl = AgentControl.fromNative(manifestYamlOrJson, {
  async dispatch(annotatorName, annotatorConfig, preliminaryPolicyInput) {
    return { ok: true };
  },
});
```

`NativeRuntimeClient` accepts a manifest string or JSON value plus optional async-capable annotator and policy dispatchers, falling back to the bundled defaults when a dispatcher is omitted. The native layer calls the Rust core off the Node main thread and bridges dispatcher promises back into the synchronous core. `AgentControl.run`, `protectTool`, and `runTool` mirror the Python SDK orchestration. The zero-config construction section in the root README describes when to supply custom dispatchers.

## Bundled OPA binary

Rego policies require an `opa` executable. An explicit `ACS_OPA_PATH` or `opaPath` is authoritative and must point to the binary or its containing directory. If no explicit path is set, the Node zero-config and GitHub Copilot bootstrap paths look for a pinned vendored binary before falling back to host configuration. Resolution order is:

1. `ACS_OPA_PATH` or an explicit `opaPath`
2. the platform optional dependency such as `agent-control-specification-opa-linux-x64`
3. `opa` already available on `PATH`

Set `ACS_OPA_NO_BUNDLE=1` to skip bundled binary resolution when a host must use a specific system OPA. Artifact-only or local tarball installs must provide the matching OPA package tarball, install Open Policy Agent separately, or set `ACS_OPA_PATH`. A bad explicit path fails closed instead of falling back to another `opa` on `PATH`.

## Escalation and approval

In enforce mode a `deny` verdict throws `AgentControlBlockedError`. An `escalate` verdict consults an optional approval resolver, a host callback that decides whether the action proceeds. Supply a resolver on the instance with `new AgentControl(runtimeClient, approvalResolver)` (or `AgentControl.fromNative(manifest, annotator, policy, approvalResolver)`) or override it per call with the `approvalResolver` option on `run`, `runTool`, and `protectTool`. The resolver returns `ApprovalResolution.allow(result.actionIdentity)`, `ApprovalResolution.deny()`, or `ApprovalResolution.suspend(handle, result.actionIdentity)`.

- allow proceeds with the original action target. `escalate` verdicts do not return or apply transformed targets
- deny, an unrecognized result, or a resolver that rejects throws `AgentControlBlockedError` (the original error is preserved as `cause`)
- suspend throws `AgentControlSuspendedError` carrying the opaque host handle
- with no resolver an `escalate` verdict fails closed to a block

The resolver is consulted only for `escalate` and only in enforce mode. A `deny` never consults it. `AgentControlBlockedError` and `AgentControlSuspendedError` both extend `AgentControlInterruptionError`. The GitHub Copilot permission hook integration maps `escalate` to a permission deny, since that surface exposes only allow and deny.

Custom annotator dispatcher throws and rejected promises fail closed as `runtime_error:annotation_failed`. Distinct `runtime_error:annotation_timeout` reporting is available when a dispatcher surface explicitly returns that runtime error. Resource limit configuration is exposed by the Rust core surface, not by the Node constructor surface.

## Telemetry

The Node SDK ships a pure host-side telemetry layer. Pass a `telemetrySink` to `AgentControl`, `fromNative`, `fromPath`, `fromUrl`, or `fromManifestChain`, and each evaluation emits one redaction-safe `TelemetryEvent`. `telemetrySink` accepts one sink or an array of sinks. An array fans out through `MultiSink`. The default `telemetrySink` value preserves prior behavior with no events.

```js
const {
  AgentControl,
  JsonStdoutTelemetrySink,
  MultiSink,
  OtelMetricsTelemetrySink,
} = require("agent-control-specification");

const sink = new MultiSink([
  new JsonStdoutTelemetrySink(),
  new OtelMetricsTelemetrySink(),
]);
const control = AgentControl.fromPath(
  "manifest.json",
  undefined,
  undefined,
  undefined,
  undefined,
  sink,
);
```

### Event model

`TelemetryEvent` carries `eventType`, `interventionPoint`, `decision`, `reasonCode`, `errorClass`, `policyId`, `annotators`, `enforcementMode`, `durationMs`, `evidenceArtefact`, `evidenceVerificationPointerKeys`, `actionIdentity`, and `metadata`. The in-memory object and `toObject()` use these camelCase names; the wire serialization (`toJSON()`, which `JSON.stringify` and `JsonStdoutTelemetrySink` use, and the OpenTelemetry metric attributes) uses snake_case keys (`event_type`, `intervention_point`, ...) so a mixed-SDK fleet writes one consistent audit.jsonl shape and one consistent metric attribute set. Redaction is the invariant. Events carry decision metadata, the evidence `artefact`, and sorted evidence pointer keys only. Events never carry raw prompts, tool arguments, tool results, transform values, annotator outputs, or pointer URL values. Free-text policy reasons reduce to `policy_reason`, matching the Rust helper.

`policyId` and configured `annotators` are resolved from the fully merged manifest by the native core at construction, through the native `policyLabels` accessor, so they are populated for every constructor, including `fromUrl`, `fromManifestChain`, and YAML manifests. No host-side manifest parsing is involved, so the Node SDK needs no YAML parser dependency. A custom runtime client that does not expose `policyLabels` leaves `policyId` unset, and in that case `annotators` falls back to the executed annotation keys present on the runtime result.

The host layer emits exactly one `decision` event per evaluation. It does not replicate the Rust core's second `intervention_point.transformed` event for a `transform` verdict. The transform path is observable through `decision === "transform"`.

### Built-in sinks

| Sink | Behavior |
| --- | --- |
| `InMemoryTelemetrySink` | Records events in an `events` array for tests and inspection. |
| `JsonStdoutTelemetrySink` | Writes one JSON object per line. |
| `OtelMetricsTelemetrySink` | Emits optional OpenTelemetry metrics. |
| `MultiSink` | Fans one event out to several sinks. A failing child is logged and isolated. |

Emission is never load-bearing. Event construction and sink emission are caught together, logged, and swallowed so telemetry cannot change the verdict.

### OpenTelemetry metrics

`OtelMetricsTelemetrySink` matches the metric contract of the Rust OpenTelemetry crate. It emits `acs_intervention_allow_total`, `acs_intervention_deny_total`, `acs_intervention_warn_total`, `acs_intervention_escalate_total`, and `acs_intervention_transform_total`, plus `acs_intervention_duration_ms`, under the meter name `agent_control_specification` by default. `@opentelemetry/api` is optional and imported lazily. When the package is absent the sink becomes a safe no-op after one warning.

## Model adapters and streaming

Generic model helpers such as `runModel`, `protectModel`, `wrapModel`, and `createModelMiddleware` are exported from the package root and the `agent-control-specification/adapters` subpath. Use them for direct OpenAI-compatible clients when a dedicated OpenAI client adapter is not present. The Node SDK also exports `wrapAnthropicClient`, `runAnthropicMessage`, and `createAnthropicAdapter` for Anthropic Messages clients.

Non-streaming model helpers mediate `pre_model_call` before upstream execution and `post_model_call` before returning the response. Direct streaming requests passed to `wrapModel` or `wrapAnthropicClient` fail closed before upstream execution with `runtime_error:streaming_unsupported`. That reason is distinct from `runtime_error:adapter_unsupported`, which is used when an adapter detects an unmediated framework method or unsupported call shape such as LangChain `stream()` or MCP resource methods. Use `runModelStream` for buffered OpenAI-style chat-completion SSE mediation. It buffers the stream, evaluates `post_model_call` over the assembled response, then synthesizes redacted SSE bytes when effects transform the response.

## MCP tool providers

Use `wrapMcpToolProvider` when you already have a provider instance. Use `createMcpToolProviderAdapter(control).wrapProvider(provider)` when framework code expects an adapter object. The provider must expose `callTool(...)` or `call_tool(...)`. Object calls may use `name`, `tool`, or `toolName` for the tool name and `arguments`, `args`, or `input` for the tool arguments. Positional calls use `call_tool(name, args)`.

The adapter routes the call through `AgentControl.runTool`. Effects from `pre_tool_call` are passed to the provider as transformed arguments. Effects from `post_tool_call` are returned to the host as transformed results. MCP resources, prompts, streams, and lifecycle hooks still need package-specific adapters, and known unsupported methods on a wrapped provider fail closed with `runtime_error:adapter_unsupported` instead of being delegated.

```js
const {
  AgentControl,
  createMcpToolProviderAdapter,
  wrapMcpToolProvider,
} = require("agent-control-specification");

const control = AgentControl.fromPath("manifest.yaml");
const provider = {
  async callTool(request) {
    return { content: `read ${request.arguments.path}` };
  },
};

const wrapped = wrapMcpToolProvider(control, provider, {
  toolCallId: "mcp-read-file",
});

await wrapped.callTool({
  name: "read_file",
  arguments: { path: "README.md" },
});

const adapter = createMcpToolProviderAdapter(control);
const alsoWrapped = adapter.wrapProvider(provider, {
  toolCallId: "mcp-read-file-2",
});
```

## LangChain adapters

Use `guardLangChainRunnable()` or `createLangChainAdapter(control).guard(runnable)` for Runnable-like objects. The wrapper mediates `invoke(...)` and `ainvoke(...)` through `input`, `pre_model_call`, `post_model_call`, and `output`. Use `guardLangChainTool()` or `createLangChainAdapter(control).guardTool(tool)` for tool-like objects. The wrapper mediates the selected tool method through `pre_tool_call` and `post_tool_call`.

`batch(...)` and `stream(...)` are not guarded by these adapters. When those methods exist on the wrapped object they fail closed with `runtime_error:adapter_unsupported` instead of calling the upstream object.
