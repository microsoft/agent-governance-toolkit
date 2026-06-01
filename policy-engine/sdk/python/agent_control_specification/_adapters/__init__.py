from __future__ import annotations

from ._errors import AdapterUnsupportedError
from ._generic import (
    AgentT,
    FullCoverageAgentAdapter,
    ModelCallResult,
    ModelInterventionPointMiddleware,
    ModelRequestT,
    ModelResponseT,
    UnsupportedFrameworkAdapter,
    guard_agent_method,
    guard_model_call,
    guard_run,
    guard_tool,
    run_model_call,
    _guard_invocation_method,
    _policy_target_and_executor,
)
from ._shared import (
    Execute,
    SNAPSHOT_KWARG,
    TOOL_CALL_ID_KWARG,
    _body_bytes,
    _capture_asgi_send,
    _decode_json_body,
    _encode_json_body,
    _first_callable,
    _has_path,
    _headers_with_content_length,
    _maybe_await,
    _merge_snapshot,
    _ObjectProxy,
    _pop_common_adapter_kwargs,
    _read_asgi_body,
    _require_callable,
    _response_json_from_asgi_messages,
    _scope_with_content_length,
    _send_json_asgi_response,
    _single_body_receive,
    _string_or_none,
    _transformed_or,
)
from .agents import guard_autogen_agent, guard_crewai_crew
from .langchain import guard_langchain_runnable, guard_langchain_tool
from .litellm import AgentControlLiteLLMGuardrail, LiteLLMProxyMiddleware, guard_litellm_proxy, _is_guarded_litellm_scope
from .mcp import (
    guard_mcp_server,
    guard_mcp_tool,
    mcp_approval_resolver,
    _guard_mcp_tool_provider_method,
    _mcp_tool_policy_target_and_executor,
)
from .semantic_kernel import guard_semantic_kernel_filter, guard_semantic_kernel_function
from .openai import (
    guard_openai_agents_runner,
    guard_openai_client,
    _guard_call_request_method,
    _guard_openai_agents_runner_run_method,
    _invoke_with_call_request,
    _pack_call_request,
    _runner_policy_target_and_executor,
)
from .anthropic import guard_anthropic_client

__all__ = [
    "AdapterUnsupportedError",
    "AgentControlLiteLLMGuardrail",
    "AgentT",
    "Execute",
    "FullCoverageAgentAdapter",
    "LiteLLMProxyMiddleware",
    "ModelCallResult",
    "ModelInterventionPointMiddleware",
    "ModelRequestT",
    "ModelResponseT",
    "SNAPSHOT_KWARG",
    "TOOL_CALL_ID_KWARG",
    "UnsupportedFrameworkAdapter",
    "guard_agent_method",
    "guard_anthropic_client",
    "guard_autogen_agent",
    "guard_crewai_crew",
    "guard_langchain_runnable",
    "guard_langchain_tool",
    "guard_litellm_proxy",
    "guard_mcp_server",
    "guard_mcp_tool",
    "guard_model_call",
    "guard_openai_agents_runner",
    "guard_openai_client",
    "guard_run",
    "guard_semantic_kernel_filter",
    "guard_semantic_kernel_function",
    "guard_tool",
    "mcp_approval_resolver",
    "run_model_call",
]
