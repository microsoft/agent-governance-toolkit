# Agent Control Specification Python SDK

This package is the thin Python surface for the stateless Agent Control Specification runtime.

It intentionally owns Python async orchestration and host/framework integration while the native core owns deterministic intervention point evaluation. `AgentControl.from_path("manifest.yaml")` builds a control backed by the bundled Rust core through the `_native` extension, which is built when the package is installed with maturin. With no dispatcher arguments the bundled OPA policy dispatcher and annotator dispatcher are wired automatically, so a host that uses Rego policies integrates in roughly three lines. Pass `annotator_dispatcher=` and `policy_dispatcher=` (or use `from_native(manifest, ...)`) to override either bundled default with host-specific logic. See [Zero-config construction](../../README.md#zero-config-construction).

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
  - `guard_litellm_proxy()` / `LiteLLMProxyMiddleware` for non-streaming ASGI JSON LiteLLM/OpenAI-compatible proxy calls
  - duck-typed async shapes for LangChain (`guard_langchain_runnable()` and `guard_langchain_tool()`), OpenAI clients (`guard_openai_client()`), OpenAI Agents Runner (`guard_openai_agents_runner()`), Anthropic (`guard_anthropic_client()`), AutoGen (`guard_autogen_agent()`), and CrewAI (`guard_crewai_crew()`)

Adapters are intentionally stateless. Pass ambient per-call data with the reserved keyword `agent_control_snapshot={...}`; it is merged over any default snapshot supplied when creating the wrapper. Unsupported or potentially bypassing methods raise `AdapterUnsupportedError` rather than returning an unguarded path. `guard_mcp_server()` covers MCP tool calls only; MCP resources/prompts/streams and lifecycle hooks still need package-specific adapters. `guard_litellm_proxy()` buffers JSON ASGI request/response bodies and rejects streaming instead of bypassing controls.

`guard_litellm_proxy()` targets the LiteLLM proxy server ASGI app and needs the proxy extra. Install real-package tests with `litellm[proxy]`, not bare `litellm`. Pass `litellm.proxy.proxy_server.app` explicitly or let `guard_litellm_proxy(control)` load it lazily. The LiteLLM proxy rejects client supplied `api_base` and credentials unless proxy configuration allows client-side credentials, for example `proxy_server.general_settings["allow_client_side_credentials"] = True` in local tests.

`guard_crewai_crew()` does not modify CrewAI environment. CrewAI 1.6 prompts for first-run trace viewing in normal interactive mode. Set `CREWAI_TESTING=true` before importing CrewAI for headless or CI runs. Set `OTEL_SDK_DISABLED=true` or `CREWAI_DISABLE_TELEMETRY=true` as a separate telemetry export opt out when needed.

Single-tool wrappers require a snapshot-compatible tool call id: pass `tool_call_id=` to `AgentControl.run_tool()` / `protect_tool()`, or `agent_control_tool_call_id=` to adapter helpers such as `guard_tool()` / `guard_mcp_tool()`.

## Escalation and approval

In enforce mode a `deny` verdict raises `AgentControlBlocked`. An `escalate` verdict consults an optional approval resolver, a host callback that decides whether the action proceeds. Supply a resolver on the instance with `AgentControl(..., approval_resolver=...)` (or `from_native(..., approval_resolver=...)`) or override it per call with the `approval_resolver=` argument on `run()`, `run_tool()`, and `protect_tool()`. The resolver returns `ApprovalResolution.allow()`, `ApprovalResolution.deny()`, or `ApprovalResolution.suspend(handle=...)`.

- allow proceeds without applying escalate effects, since only `allow` and `warn` apply effects
- deny, an unrecognized result, or a resolver that raises blocks with `AgentControlBlocked`
- suspend raises `AgentControlSuspended` carrying the opaque host handle
- with no resolver an `escalate` verdict fails closed to a block

The resolver is consulted only for `escalate` and only in enforce mode. A `deny` never consults it. Framework adapters use the instance resolver. Resumption after a suspension is owned by the host. For a post action point such as `post_tool_call` the action already ran, so a resuming host delivers the produced result instead of running it again. `mcp_approval_resolver(elicit)` adapts an MCP elicitation callback into a resolver.

Run local tests from the repository root:

```sh
mkdir -p .copilot-tmp && TMPDIR=$PWD/.copilot-tmp PYTHONPATH=sdk/python python3 -m unittest discover sdk/python/tests
```
