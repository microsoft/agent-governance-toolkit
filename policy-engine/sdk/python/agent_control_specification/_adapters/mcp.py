from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from typing import Any, TypeVar

from .._orchestration import AgentControl
from .._types import (
    ApprovalOutcome,
    ApprovalResolution,
    ApprovalResolver,
    EnforcementMode,
    InterventionPoint,
    InterventionPointResult,
    JsonValue,
)
from ._errors import AdapterUnsupportedError
from ._generic import guard_tool
from ._shared import (
    Execute,
    TOOL_CALL_ID_KWARG,
    _merge_snapshot,
    _maybe_await,
    _ObjectProxy,
    _pop_common_adapter_kwargs,
    _resolve_control_and_target,
    _string_or_none,
)

AgentT = TypeVar("AgentT")

_UNSUPPORTED_MCP_METHODS = {
    "read_resource",
    "readResource",
    "get_prompt",
    "getPrompt",
    "stream",
    "initialize",
}


def guard_mcp_tool(
    control_or_tool_name: AgentControl | str,
    tool_name_or_handler: str | Execute | None = None,
    handler: Execute | None = None,
    *,
    control: AgentControl | None = None,
    tool_call_id: str | None = None,
    snapshot: Mapping[str, JsonValue] | None = None,
    mode: EnforcementMode | str = EnforcementMode.ENFORCE,
    approval_resolver: ApprovalResolver | None = None,
) -> Callable[..., Awaitable[JsonValue]]:
    """Guard one MCP-style tool handler with pre/post tool-call intervention points."""

    if isinstance(control_or_tool_name, AgentControl):
        if control is not None:
            raise TypeError("guard_mcp_tool() got AgentControl both positionally and by keyword")
        if not isinstance(tool_name_or_handler, str) or handler is None:
            raise AdapterUnsupportedError(
                "guard_mcp_tool() requires tool_name and handler after the AgentControl instance."
            )
        resolved_control = control_or_tool_name
        resolved_tool_name = tool_name_or_handler
        resolved_handler = handler
    else:
        if control is None:
            raise AdapterUnsupportedError(
                "guard_mcp_tool() requires control=AgentControl(...) when the tool name is first."
            )
        if not callable(tool_name_or_handler) or handler is not None:
            raise AdapterUnsupportedError(
                "guard_mcp_tool(tool_name, handler, control=...) requires one handler."
            )
        resolved_control = control
        resolved_tool_name = control_or_tool_name
        resolved_handler = tool_name_or_handler
    return guard_tool(
        resolved_control,
        resolved_tool_name,
        resolved_handler,
        tool_call_id=tool_call_id,
        snapshot=snapshot,
        mode=mode,
        approval_resolver=approval_resolver,
    )


def guard_mcp_server(
    control_or_server: AgentControl | AgentT,
    server: AgentT | None = None,
    *,
    control: AgentControl | None = None,
    snapshot: Mapping[str, JsonValue] | None = None,
    mode: EnforcementMode | str = EnforcementMode.ENFORCE,
    approval_resolver: ApprovalResolver | None = None,
) -> AgentT:
    """Guard a duck-typed MCP tool provider/server ``call_tool`` method."""

    resolved_control, resolved_server = _resolve_control_and_target(
        control_or_server,
        server,
        control=control,
        target_name="MCP server/tool provider",
        adapter_name="guard_mcp_server",
    )

    overrides: dict[str, Any] = {}
    for method_name in ("call_tool", "callTool"):
        method = getattr(resolved_server, method_name, None)
        if callable(method):
            overrides[method_name] = _guard_mcp_tool_provider_method(
                resolved_control,
                method,
                snapshot=snapshot,
                mode=mode,
                approval_resolver=approval_resolver,
            )

    if not overrides:
        raise AdapterUnsupportedError(
            "MCP server/tool-provider adapter requires call_tool(...) or callTool(...); "
            "full MCP resource/prompt/server interception is still unsupported."
        )

    blocked = {
        name: f"MCP method {name} is not guarded by this adapter."
        for name in _UNSUPPORTED_MCP_METHODS
        if name not in overrides and callable(getattr(resolved_server, name, None))
    }

    return _ObjectProxy(resolved_server, overrides=overrides, blocked=blocked)  # type: ignore[return-value]


def mcp_approval_resolver(
    elicit: Callable[..., Any],
    *,
    accept_actions: tuple[str, ...] = ("accept",),
) -> ApprovalResolver:
    """Build an :data:`ApprovalResolver` from an MCP elicitation callable.

    ``elicit`` is a duck-typed callable matching MCP elicitation: it is invoked
    with a human-readable ``message`` and returns (or awaits) a response whose
    ``action`` field is one of ``accept``, ``decline`` or ``cancel`` (either an
    attribute or a mapping key). Only an ``accept`` action approves the escalate;
    every other action, and any malformed response, fails closed as a deny.
    """

    async def resolve(
        intervention_point: InterventionPoint,
        result: InterventionPointResult,
    ) -> ApprovalResolution:
        reason = result.verdict.reason or "policy requires approval"
        message = f"Approval required for {intervention_point.value}: {reason}"
        response = await _maybe_await(elicit(message))
        action = _elicit_action(response)
        if action in accept_actions:
            return ApprovalResolution.allow(result.action_identity or "")
        return ApprovalResolution(ApprovalOutcome.DENY)

    return resolve


def _elicit_action(response: Any) -> str | None:
    action = getattr(response, "action", None)
    if action is None and isinstance(response, Mapping):
        action = response.get("action")
    return action if isinstance(action, str) else None


def _guard_mcp_tool_provider_method(
    control: AgentControl,
    method: Execute,
    *,
    snapshot: Mapping[str, JsonValue] | None,
    mode: EnforcementMode | str,
    approval_resolver: ApprovalResolver | None = None,
) -> Callable[..., Awaitable[JsonValue]]:
    default_snapshot = dict(snapshot or {})

    async def guarded(*args: Any, **kwargs: Any) -> JsonValue:
        per_call_snapshot = _pop_common_adapter_kwargs(kwargs)
        explicit_call_id = kwargs.pop(TOOL_CALL_ID_KWARG, None)
        tool_name, tool_args, tool_call_id, execute_effective = _mcp_tool_policy_target_and_executor(
            method,
            args,
            kwargs,
            explicit_call_id=explicit_call_id,
        )
        merged_snapshot = _merge_snapshot(default_snapshot, per_call_snapshot)
        result = await control.run_tool(
            tool_name,
            tool_args,
            execute_effective,
            tool_call_id=tool_call_id,
            snapshot=merged_snapshot,
            mode=mode,
            approval_resolver=approval_resolver,
        )
        return result.value

    return guarded


def _mcp_tool_policy_target_and_executor(
    method: Execute,
    args: tuple[Any, ...],
    kwargs: Mapping[str, Any],
    *,
    explicit_call_id: str | None,
) -> tuple[str, JsonValue, str | None, Callable[[JsonValue], Awaitable[JsonValue]]]:
    if args and isinstance(args[0], Mapping):
        request = dict(args[0])
        rest = args[1:]
        tool_name = request.get("name") or request.get("tool") or request.get("toolName")
        if not isinstance(tool_name, str) or not tool_name:
            raise AdapterUnsupportedError("MCP tool request must include string name/tool/toolName.")
        tool_args = request.get("arguments", request.get("args", request.get("input", {})))
        tool_call_id = explicit_call_id
        if tool_call_id is None:
            tool_call_id = _mcp_request_call_id(request)

        async def execute_effective(effective_args: JsonValue) -> JsonValue:
            effective_request = dict(request)
            if "arguments" in effective_request:
                effective_request["arguments"] = effective_args
            elif "args" in effective_request:
                effective_request["args"] = effective_args
            elif "input" in effective_request:
                effective_request["input"] = effective_args
            else:
                effective_request["arguments"] = effective_args
            return await _maybe_await(method(effective_request, *rest, **dict(kwargs)))

        return tool_name, tool_args, tool_call_id, execute_effective

    if args and isinstance(args[0], str):
        tool_name = args[0]
        tool_args = args[1] if len(args) > 1 else {}
        rest = args[2:] if len(args) > 2 else ()

        async def execute_effective(effective_args: JsonValue) -> JsonValue:
            return await _maybe_await(method(tool_name, effective_args, *rest, **dict(kwargs)))

        return tool_name, tool_args, explicit_call_id, execute_effective

    raise AdapterUnsupportedError(
        "MCP tool calls must be object-shaped with name/arguments or positional name, args."
    )


def _mcp_request_call_id(request: Mapping[str, Any]) -> str | None:
    for key in ("id", "call_id", "tool_call_id"):
        if key in request:
            return _string_or_none(request[key])
    return None
