from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from typing import Any, TypeVar

from .._orchestration import AgentControl
from .._types import EnforcementMode, JsonValue
from ._generic import guard_agent_method
from ._errors import AdapterUnsupportedError
from ._shared import (
    TOOL_CALL_ID_KWARG,
    _maybe_await,
    _merge_snapshot,
    _ObjectProxy,
    _pop_common_adapter_kwargs,
    _resolve_control_and_target,
    _string_or_none,
)

AgentT = TypeVar("AgentT")


def guard_langchain_runnable(
    control_or_runnable: AgentControl | AgentT,
    runnable: AgentT | None = None,
    *,
    control: AgentControl | None = None,
    snapshot: Mapping[str, JsonValue] | None = None,
    mode: EnforcementMode | str = EnforcementMode.ENFORCE,
) -> AgentT:
    """Guard a LangChain-style async Runnable via ``ainvoke``."""

    resolved_control, resolved_runnable = _resolve_control_and_target(
        control_or_runnable,
        runnable,
        control=control,
        target_name="LangChain Runnable",
        adapter_name="guard_langchain_runnable",
    )
    return guard_agent_method(
        resolved_control,
        resolved_runnable,
        "ainvoke",
        input_kwarg="input",
        snapshot=snapshot,
        mode=mode,
        blocked_methods=("invoke", "batch", "stream"),
    )


def guard_langchain_tool(
    control_or_tool: AgentControl | AgentT,
    tool: AgentT | None = None,
    *,
    control: AgentControl | None = None,
    tool_call_id: str | None = None,
    snapshot: Mapping[str, JsonValue] | None = None,
    mode: EnforcementMode | str = EnforcementMode.ENFORCE,
) -> AgentT:
    """Guard a LangChain BaseTool-style object via ``pre/post_tool_call``."""

    resolved_control, resolved_tool = _resolve_control_and_target(
        control_or_tool,
        tool,
        control=control,
        target_name="LangChain tool",
        adapter_name="guard_langchain_tool",
    )
    tool_name = _string_or_none(getattr(resolved_tool, "name", None))
    if tool_name is None:
        raise AdapterUnsupportedError("LangChain tool must expose a string name.")

    method = getattr(resolved_tool, "ainvoke", None)
    if not callable(method):
        raise AdapterUnsupportedError("LangChain tool adapter requires ainvoke(...).")

    return _ObjectProxy(
        resolved_tool,
        overrides={
            "ainvoke": _guard_langchain_tool_ainvoke(
                resolved_control,
                tool_name,
                method,
                tool_call_id=tool_call_id,
                snapshot=snapshot,
                mode=mode,
            )
        },
        blocked={
            name: f"{name} is not guarded by this adapter; use ainvoke()."
            for name in ("invoke", "batch", "stream")
            if hasattr(resolved_tool, name)
        },
    )  # type: ignore[return-value]


def _guard_langchain_tool_ainvoke(
    control: AgentControl,
    tool_name: str,
    method: Callable[..., JsonValue | Awaitable[JsonValue]],
    *,
    tool_call_id: str | None,
    snapshot: Mapping[str, JsonValue] | None,
    mode: EnforcementMode | str,
) -> Callable[..., Awaitable[JsonValue]]:
    default_snapshot = dict(snapshot or {})

    async def guarded(args_value: JsonValue, *args: Any, **kwargs: Any) -> JsonValue:
        per_call_snapshot = _pop_common_adapter_kwargs(kwargs)
        explicit_call_id = kwargs.pop(TOOL_CALL_ID_KWARG, None)
        merged_snapshot = _merge_snapshot(default_snapshot, per_call_snapshot)

        async def execute_effective(effective_args: JsonValue) -> JsonValue:
            return await _maybe_await(method(effective_args, *args, **kwargs))

        result = await control.run_tool(
            tool_name,
            args_value,
            execute_effective,
            tool_call_id=explicit_call_id or tool_call_id,
            snapshot=merged_snapshot,
            mode=mode,
        )
        return result.value

    return guarded
