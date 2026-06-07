# Agent Control Specification Python SDK

## What is the Agent Control Specification?

Agent Control Specification (ACS) is a stateless, deterministic, fail-closed policy decision runtime for agent security. At each of eight intervention points across the agent loop, `Input -> Model -> Tool Call -> Tool Result -> Output`, the host submits a complete snapshot and policy manifest, then receives a normalized verdict. Verdicts are `allow`, `warn`, `deny`, `escalate`, or `transform`, with runtime errors failing closed to `deny` and no transform. This SDK is the thin Python surface over the Rust core, and ACS is vendored into AGT's `policy-engine/` as the AGT 5.0 policy layer. See the [policy engine overview](../../README.md) for where it fits with Agent OS as the kernel and host.

This package is the thin Python surface for the stateless Agent Control Specification runtime.

It intentionally owns Python async orchestration and host/framework integration while the native core owns deterministic intervention point evaluation. `AgentControl.from_path("manifest.yaml")` builds a control backed by the bundled Rust core through the `_native` extension, which is built when the package is installed with maturin. With no dispatcher arguments the bundled OPA policy dispatcher and annotator dispatcher are wired automatically, so a host that uses Rego policies integrates in roughly three lines. Pass `annotator_dispatcher=` and `policy_dispatcher=` (or use `from_native(manifest, ...)`) to override either bundled default with host-specific logic. The zero-config construction section in the root README describes when to supply custom dispatchers.

Runnable pieces today:

- dataclasses/enums for `InterventionPointRequest`, `InterventionPointResult`, `Verdict`, intervention points, decisions, and enforcement mode
- protocols for host-supplied annotator and policy dispatchers
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
  - duck-typed async shapes for LangChain (`guard_langchain_runnable()` and `guard_langchain_tool()`), OpenAI clients (`guard_openai_client()`), OpenAI Agents Runner (`guard_openai_agents_runner()`), Anthropic (`guard_anthropic_client()`), AutoGen (`guard_autogen_agent()`), and CrewAI (`guard_crewai_crew()`)

Adapters are intentionally stateless. Pass ambient per-call data with the reserved keyword `agent_control_snapshot={...}`; it is merged over any default snapshot supplied when creating the wrapper. Unsupported or potentially bypassing methods raise `AdapterUnsupportedError` rather than returning an unguarded path. `guard_mcp_server()` covers MCP tool calls only. MCP resources, prompts, streams, and lifecycle hooks still need package-specific adapters, and known unsupported methods on a wrapped provider are blocked instead of being delegated. `guard_litellm_proxy()` buffers JSON ASGI request/response bodies and streaming chat responses instead of bypassing controls. `AgentControlLiteLLMGuardrail` maps LiteLLM `pre_call` and `post_call` guardrail hooks to ACS input, model, tool, and output intervention points. Install the optional proxy dependency with `pip install "agent-control-specification[litellm-proxy]"`.

`guard_litellm_proxy()` targets the LiteLLM proxy server ASGI app and needs the proxy extra. Install real-package tests with `litellm[proxy]`, not bare `litellm`. Pass `litellm.proxy.proxy_server.app` explicitly or let `guard_litellm_proxy(control)` load it lazily. The LiteLLM proxy rejects client supplied `api_base` and credentials unless proxy configuration allows client-side credentials, for example `proxy_server.general_settings["allow_client_side_credentials"] = True` in local tests.

`guard_litellm_proxy()` mediates the ASGI request as a model call. It evaluates `pre_model_call` before replaying the request body to the upstream app and evaluates `post_model_call` over the captured upstream response before sending the response to the client. JSON responses and chat-completion SSE responses are buffered before release so `post_model_call` effects can redact or replace the response. Streaming is guarded only for chat-completion paths. Streaming on embeddings, completions, messages, and responses paths raises `AdapterUnsupportedError` before the upstream app runs.

Use `post_model_call` for proxy response redaction. The generic `output` point is not evaluated by `guard_litellm_proxy()`. Approval uses the resolver configured on the `AgentControl` instance because the ASGI middleware has no per-request resolver argument.

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

The Python SDK accepts the native `PerfTelemetry` level on `from_path`, `from_native`, and `from_manifest_chain`. It does not expose the Rust `TelemetrySink` or an OpenTelemetry exporter hook. Python hosts that need application telemetry should record sanitized decision, effect, duration, and action identity fields from `InterventionPointResult` at the host boundary. The Rust core and `agent_control_specification_otel` crate remain the direct telemetry sink surfaces.

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
