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
