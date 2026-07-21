# Agent Control Specification Python SDK

## What is the Agent Control Specification?

Agent Control Specification (ACS) is a stateless, deterministic, fail-closed policy decision runtime for agent security. At each of eight intervention points across the agent loop, `Input -> Model -> Tool Call -> Tool Result -> Output`, the host submits a complete snapshot and policy manifest, then receives a normalized verdict. Verdicts are `allow`, `warn`, `deny`, `escalate`, or `transform`, with runtime errors failing closed to `deny` and no transform. This SDK is the thin Python surface over the Rust core, and ACS is vendored into AGT's `policy-engine/` as the AGT 5.0 policy layer. See the [policy engine overview](../../README.md) for where it fits with Agent OS as the kernel and host.

This package is the thin Python surface for the stateless Agent Control Specification runtime.

It intentionally owns Python async orchestration and host/framework integration while the native core owns deterministic intervention point evaluation. `AgentControl.from_path("manifest.yaml")` builds a control backed by the bundled Rust core through the `_native` extension, which is built when the package is installed with maturin. With no dispatcher arguments the bundled OPA policy dispatcher and annotator dispatcher are wired automatically, so a host that uses Rego policies integrates in roughly three lines. Pass `annotator_dispatcher=` and `policy_dispatcher=` (or use `from_native(manifest, ...)`) to override either bundled default with host-specific logic. The zero-config construction section in the root README describes when to supply custom dispatchers.

Runnable pieces today:

- dataclasses/enums for `InterventionPointRequest`, `InterventionPointResult`, `Verdict`, intervention points, decisions, and enforcement mode
- protocols for host-supplied annotator and policy dispatchers
- `parse_manifest()`, `validate_manifest()`, and `validate_manifest_overlay()` backed by the Rust runtime parser
- `AgentControl.evaluate_intervention_point()` delegating to an abstract runtime client
- `AgentControl.run()` enforcing `input` and `output`
- `AgentControl.protect_tool()` / `run_tool()` enforcing `pre_tool_call` and `post_tool_call`
- stateless adapter helpers:
  - `guard_run()` for generic agent/run callables
  - `run_model_call()` / `guard_model_call()` for `pre_model_call` and `post_model_call`
  - `guard_tool()` / `guard_mcp_tool()` for ergonomic single-tool wrappers returning the guarded value
  - `guard_mcp_server()` for duck-typed MCP tool providers exposing `call_tool(...)` or `callTool(...)`
  - `guard_litellm_proxy()` / `LiteLLMProxyMiddleware` for ASGI JSON LiteLLM/OpenAI-compatible proxy calls
  - `AgentControlLiteLLMGuardrail` for codeless LiteLLM Proxy `guardrails:` YAML registration
  - `guard_foundry_agent()` (alias `guard_azure_ai_agents()`) for governing an Azure AI Foundry hosted agent run loop
  - duck-typed async shapes for LangChain (`guard_langchain_runnable()` and `guard_langchain_tool()`), OpenAI clients (`guard_openai_client()`), OpenAI Agents Runner (`guard_openai_agents_runner()`), Anthropic (`guard_anthropic_client()`), AutoGen (`guard_autogen_agent()`), and CrewAI (`guard_crewai_crew()`)

Adapters are intentionally stateless. Pass ambient per-call data with the reserved keyword `agent_control_snapshot={...}`; it is merged over any default snapshot supplied when creating the wrapper. Unsupported or potentially bypassing methods raise `AdapterUnsupportedError` rather than returning an unguarded path. `guard_mcp_server()` covers MCP tool calls only. MCP resources, prompts, streams, and lifecycle hooks still need package-specific adapters, and known unsupported methods on a wrapped provider are blocked instead of being delegated. `guard_litellm_proxy()` buffers JSON ASGI request/response bodies and streaming chat responses instead of bypassing controls. `AgentControlLiteLLMGuardrail` maps LiteLLM `pre_call` and `post_call` guardrail hooks to ACS input, model, tool, and output intervention points. Install the optional proxy dependency with `pip install "agent-control-specification[litellm-proxy]"`.

Use `parse_manifest(text)` when a host needs the runtime parser's YAML or JSON value before applying another contract such as JSON Schema. Use `validate_manifest(text)` for a complete manifest and `validate_manifest_overlay(text)` for resolution-independent checks on a partial manifest with `extends`. All three functions use the same bounded `serde_yaml` implementation as runtime construction.

```python
from agent_control_specification import validate_acs_artifacts

report = validate_acs_artifacts(
    manifest=request.manifest,
    rego={"payments.rego": request.rego},
)
return report.to_dict()
```

The validation API delegates canonical JSON Schema validation, complete or overlay-specific typed checks, and OPA parsing to the shared Rust core. It bounds manifest and Rego input plus returned diagnostics. Rego bundle compilation and runtime evaluation remain separate host or generator checks.

`guard_litellm_proxy()` targets the LiteLLM proxy server ASGI app and needs the proxy extra. Install real-package tests with `litellm[proxy]`, not bare `litellm`. Pass `litellm.proxy.proxy_server.app` explicitly or let `guard_litellm_proxy(control)` load it lazily. The LiteLLM proxy rejects client supplied `api_base` and credentials unless proxy configuration allows client-side credentials, for example `proxy_server.general_settings["allow_client_side_credentials"] = True` in local tests.

`guard_litellm_proxy()` mediates the ASGI request as a model call. It evaluates `pre_model_call` before replaying the request body to the upstream app and evaluates `post_model_call` over the captured upstream response before sending the response to the client. JSON responses and chat-completion SSE responses are buffered before release so `post_model_call` effects can redact or replace the response. Streaming is guarded only for chat-completion paths. Streaming on embeddings, completions, messages, and responses paths raises `AdapterUnsupportedError` before the upstream app runs.

Use `post_model_call` for proxy response redaction. The generic `output` point is not evaluated by `guard_litellm_proxy()`. Approval uses the resolver configured on the `AgentControl` instance because the ASGI middleware has no per-request resolver argument.

`guard_foundry_agent()` (alias `guard_azure_ai_agents()`) governs an Azure AI Foundry hosted agent. The Foundry seam is the manual run loop rather than a single client method, so the adapter returns a thin proxy over the real `AgentsClient` whose governed driver (`create_thread_and_run(...)` and `run_until_complete(thread_id, run_id)`) drives the `requires_action -> submit_tool_outputs` loop. Each required function tool call named in `tools` is routed through `control.run_tool` so `pre_tool_call` gates the arguments and `post_tool_call` gates the result before the output is submitted. In enforce mode a deny submits a policy rejection output and never executes the callable, an escalate is routed to the approval resolver and is never auto-allowed (a suspend outcome raises `AgentControlSuspended` for the host to resume), and a transform submits the rewritten arguments or result. Malformed or non-object tool arguments, unknown tools, and non function-tool required actions fail closed without executing. The SDK auto-function-call paths bypass governance, so `enable_auto_function_calls`, `create_thread_and_process_run`, `runs.create_and_process`, and the streaming run helpers are blocked through the governed handle. `azure-ai-agents` is an optional dependency loaded lazily. Install it with `pip install azure-ai-agents`.

```python
from agent_control_specification import AgentControl, guard_litellm_proxy

control = AgentControl.from_path("manifest.yaml")

async def fake_openai_app(scope, receive, send):
    await receive()
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({
        "type": "http.response.body",
        "body": b'{"choices":[{"message":{"content":"ticket TICKET-123"}}]}',
        "more_body": False,
    })

app = guard_litellm_proxy(control, fake_openai_app)
```

`guard_crewai_crew()` does not modify CrewAI environment. CrewAI 1.6 prompts for first-run trace viewing in normal interactive mode. Set `CREWAI_TESTING=true` before importing CrewAI for headless or CI runs. Set `OTEL_SDK_DISABLED=true` or `CREWAI_DISABLE_TELEMETRY=true` as a separate telemetry export opt out when needed.

Python framework helpers are duck typed and guard the selected async or sync method when that method is the adapter's supported entry point. Alternate methods that would bypass the guarded path fail closed with `AdapterUnsupportedError` before the upstream object runs. For example, `guard_openai_agents_runner()` mediates `run(...)` and blocks `run_sync(...)` and `run_streamed(...)`. `guard_autogen_agent()` and `guard_crewai_crew()` can guard the selected run method, while unselected sync or alternate entry points on the proxy remain blocked.

Semantic Kernel helpers are exported as `guard_semantic_kernel_function()` for a single function-like object and `guard_semantic_kernel_filter()` for filter-style invocation contexts. Function wrappers mediate `pre_tool_call` and `post_tool_call`, passing transformed arguments to the function and transformed results back to the host.

Single-tool wrappers accept an optional snapshot-compatible tool call id: pass `tool_call_id=` to `AgentControl.run_tool()` / `protect_tool()`, or `agent_control_tool_call_id=` to adapter helpers such as `guard_tool()` / `guard_mcp_tool()`. When no id is supplied the snapshot omits `tool_call.id`.

## Telemetry

The Python SDK ships a pure-Python host-side telemetry layer. Pass a `telemetry_sink` to `AgentControl`, `from_native`, `from_path`, or `from_manifest_chain`, and every evaluation emits one redaction-safe `TelemetryEvent` to the sink. `telemetry_sink` accepts a single sink or a list of sinks (a list is fanned out through a `MultiSink`). The default `telemetry_sink=None` preserves the prior behavior with no events and no overhead beyond a `None` check. The native `PerfTelemetry` level is independent and still controls internal timing-detail capture only.

```python
from agent_control_specification import (
    AgentControl,
    JsonStdoutTelemetrySink,
    OtelMetricsTelemetrySink,
    MultiSink,
)

sink = MultiSink([JsonStdoutTelemetrySink(), OtelMetricsTelemetrySink()])
control = AgentControl.from_path("manifest.yaml", telemetry_sink=sink)
```

### Event model

`TelemetryEvent` mirrors the Rust `core/src/telemetry.rs` field set. It carries `event_type`, `intervention_point`, `decision`, `reason_code`, `error_class`, `policy_id`, `annotators`, `enforcement_mode`, `duration_ms`, `evidence_artefact`, `evidence_verification_pointer_keys`, `action_identity`, and `metadata`. Redaction is the load-bearing invariant. An event carries decision and reason metadata, the evidence `artefact`, and the sorted evidence pointer keys only. It never carries raw prompts, tool arguments, tool results, transform values, annotator outputs, or pointer URL values. A free-text policy reason is reduced to the constant `policy_reason`, matching the Rust `safe_telemetry_reason_code` helper, so an operator-authored reason string cannot leak through telemetry.

`policy_id` and configured `annotators` are resolved from the fully merged manifest by the native core at construction, through the native `policy_labels` accessor, so they are populated for every constructor, including `from_url`, `from_manifest_chain`, and `extends`-inherited ids. A fail-closed event still carries the configured annotator names. A custom `RuntimeClient` that does not expose `policy_labels` leaves `policy_id` as `None`, and in that case `annotators` falls back to the result's executed-annotation keys, which reflect only annotators that ran.

This host layer emits exactly one `decision` event per evaluation. It does not replicate the Rust core's second `intervention_point.transformed` event on a `transform` verdict; the transform is observable through `decision == "transform"`. The OTel `acs_intervention_transform_total` counter and `acs_intervention_duration_ms` histogram count one increment per evaluation, consistent across all SDKs (the Rust OTel sink records only the base `decision` event, so a transform counts once everywhere). The Rust event stream additionally carries the `intervention_point.transformed` event for stream consumers; the host SDKs do not.

### Built-in sinks

| Sink | Behavior |
| --- | --- |
| `InMemoryTelemetrySink` | Records events in an `events` list for tests and inspection. |
| `JsonStdoutTelemetrySink` | Writes one JSON object per line. The audit.jsonl use case is built in. |
| `OtelMetricsTelemetrySink` | Optional OpenTelemetry metrics export. |
| `MultiSink` | Fans one event out to several sinks. A failing child is logged and isolated. |

Emission is never load-bearing. A sink that raises is caught, logged, and swallowed so it can never change the verdict or fail the evaluation.

### OpenTelemetry metrics

`OtelMetricsTelemetrySink` matches the metric contract of the Rust `agent_control_specification_otel` crate. It emits the per-decision counters `acs_intervention_allow_total`, `acs_intervention_deny_total`, `acs_intervention_warn_total`, `acs_intervention_escalate_total`, and `acs_intervention_transform_total`, plus the duration histogram `acs_intervention_duration_ms`, under the meter name `agent_control_specification` by default. `opentelemetry` is an optional dependency. It is imported lazily, and when it is absent the sink degrades to a safe no-op after a single warning, so a host can wire it unconditionally without making OpenTelemetry a hard dependency. The Rust core and the `agent_control_specification_otel` crate remain the direct sink surfaces for hosts that prefer the in-core path.

Python custom annotator dispatcher exceptions fail closed as `runtime_error:annotation_failed`. Distinct `runtime_error:annotation_timeout` reporting is available when a dispatcher surface explicitly returns that runtime error. Resource limit configuration is exposed by the Rust core surface, not by the Python constructor surface.

## LangChain adapters

Use `guard_langchain_runnable()` for async Runnable objects. It wraps `ainvoke(...)` and routes the call through `input` and `output`. Sync and batch entry points such as `invoke`, `batch`, and `stream` are blocked by the adapter instead of bypassing ACS.

Use `guard_langchain_tool()` for async BaseTool-style objects. The tool must expose a string `name` and an async `ainvoke(...)` method. The adapter routes arguments through `pre_tool_call`, invokes the tool with transformed arguments, then routes the tool result through `post_tool_call`.

```python
from agent_control_specification import (
    AgentControl,
    guard_langchain_runnable,
    guard_langchain_tool,
)

control = AgentControl.from_path("manifest.yaml")

guarded_chain = guard_langchain_runnable(control, chain)
answer = await guarded_chain.ainvoke(
    {"question": "Summarize public policy"},
    agent_control_snapshot={"tenant": "demo"},
)

guarded_tool = guard_langchain_tool(
    control,
    retriever_tool,
    tool_call_id="rag-retrieve-1",
)
documents = await guarded_tool.ainvoke({"query": "public docs"})
```

## Escalation and approval

In enforce mode a `deny` verdict raises `AgentControlBlocked`. An `escalate` verdict consults an optional approval resolver, a host callback that decides whether the action proceeds. Supply a resolver on the instance with `AgentControl(..., approval_resolver=...)` (or `from_native(..., approval_resolver=...)`) or override it per call with the `approval_resolver=` argument on `run()`, `run_tool()`, and `protect_tool()`. The resolver returns `ApprovalResolution.allow(result.action_identity)`, `ApprovalResolution.deny()`, or `ApprovalResolution.suspend(handle=..., action_identity=result.action_identity)`.

- allow proceeds with the original action target. `escalate` verdicts do not return or apply transformed targets
- deny, an unrecognized result, or a resolver that raises blocks with `AgentControlBlocked`
- suspend raises `AgentControlSuspended` carrying the opaque host handle
- with no resolver an `escalate` verdict fails closed to a block

The resolver is consulted only for `escalate` and only in enforce mode. A `deny` never consults it. Framework adapters use the instance resolver. Resumption after a suspension is owned by the host. For a post action point such as `post_tool_call` the action already ran, so a resuming host delivers the produced result instead of running it again. `mcp_approval_resolver(elicit)` adapts an MCP elicitation callback into a resolver.

In artifact kits, install the Python wheel into a temporary virtual environment and run a host smoke test that loads a manifest with `NativeRuntimeClient.from_path`. In repository checkouts, run the Python SDK test suite through the project build instructions.
