from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Mapping
from typing import Any, Literal, TypeVar

from .._host import SnapshotSource, run_sync
from .._orchestration import AgentControl
from .._types import (
    AgentControlBlocked,
    AgentControlInterruption,
    AgentControlRuntimeError,
    EnforcementMode,
    InterventionPoint,
    JsonValue,
)
from ._errors import AdapterUnsupportedError
from ._generic import _guard_invocation_method
from ._shared import (
    TOOL_CALL_ID_KWARG,
    _default_snapshot,
    _maybe_await,
    _merge_snapshot,
    _ObjectProxy,
    _pop_common_adapter_kwargs,
    _require_callable,
    _resolve_control_and_target,
    _string_or_none,
)

AgentT = TypeVar("AgentT")
OutputT = TypeVar("OutputT")
_ITERATOR_METHODS = (
    "stream", "astream", "transform", "atransform", "astream_events", "astream_log",
    "batch_as_completed", "abatch_as_completed",
)
_DERIVED_RUNNABLE_METHODS = (
    "with_config", "bind", "with_retry", "with_fallbacks", "with_types",
    "with_listeners", "with_alisteners", "map", "pick", "assign", "pipe",
    "configurable_fields", "configurable_alternatives", "as_tool",
)


def guard_langchain_runnable(
    control_or_runnable: AgentControl | AgentT,
    runnable: AgentT | None = None,
    *,
    control: AgentControl | None = None,
    snapshot: Mapping[str, JsonValue] | None = None,
    mode: EnforcementMode | str = EnforcementMode.ENFORCE,
) -> AgentT:
    """Guard ``invoke``, ``ainvoke``, ``batch`` and ``abatch`` on a Runnable."""

    resolved_control, resolved_runnable = _resolve_control_and_target(
        control_or_runnable,
        runnable,
        control=control,
        target_name="LangChain Runnable",
        adapter_name="guard_langchain_runnable",
    )
    overrides: dict[str, Any] = {
        "ainvoke": _guard_invocation_method(
            resolved_control,
            _require_callable(resolved_runnable, "ainvoke", "LangChain Runnable"),
            input_kwarg="input",
            snapshot=snapshot,
            mode=mode,
        )
    }
    sync_method: Callable[..., Awaitable[Any]] | None = None
    method = getattr(resolved_runnable, "invoke", None)
    if callable(method):
        sync_method = _guard_invocation_method(
            resolved_control, method, input_kwarg="input", snapshot=snapshot, mode=mode,
        )
        overrides["invoke"] = _sync_from_async(sync_method)
    _add_batches(resolved_runnable, overrides, sync_method)
    return _ObjectProxy(
        resolved_runnable,
        overrides=overrides,
        blocked=_blocked_langchain_methods(resolved_runnable, overrides),
    )  # type: ignore[return-value]


def guard_langchain_tool(
    control_or_tool: AgentControl | AgentT,
    tool: AgentT | None = None,
    *,
    control: AgentControl | None = None,
    tool_call_id: str | None = None,
    snapshot: Mapping[str, JsonValue] | SnapshotSource | None = None,
    mode: EnforcementMode | str = EnforcementMode.ENFORCE,
    on_deny: Literal["raise", "tool_error"] = "raise",
) -> AgentT:
    """Guard a BaseTool via ``pre/post_tool_call``; optionally return a terminal deny."""

    if on_deny not in ("raise", "tool_error"):
        raise ValueError("on_deny must be 'raise' or 'tool_error'")
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
    injected_args_keys = frozenset(getattr(resolved_tool, "_injected_args_keys", ()) or ())

    overrides: dict[str, Any] = {
        "ainvoke": _guard_langchain_tool_method(
            resolved_control,
            tool_name,
            _require_callable(resolved_tool, "ainvoke", "LangChain tool"),
            tool_call_id=tool_call_id,
            snapshot=snapshot,
            mode=mode,
            on_deny=on_deny,
            injected_args_keys=injected_args_keys,
        )
    }
    sync_method: Callable[..., Awaitable[Any]] | None = None
    method = getattr(resolved_tool, "invoke", None)
    if callable(method):
        sync_method = _guard_langchain_tool_method(
            resolved_control, tool_name, method, tool_call_id=tool_call_id,
            snapshot=snapshot, mode=mode, on_deny=on_deny, injected_args_keys=injected_args_keys,
        )
        overrides["invoke"] = _sync_from_async(sync_method)
    _add_batches(resolved_tool, overrides, sync_method)
    return _ObjectProxy(
        resolved_tool,
        overrides=overrides,
        blocked=_blocked_langchain_methods(resolved_tool, overrides, tool=True),
    )  # type: ignore[return-value]


def _guard_langchain_tool_method(
    control: AgentControl,
    tool_name: str,
    method: Callable[..., Any],
    *,
    tool_call_id: str | None,
    snapshot: Mapping[str, JsonValue] | SnapshotSource | None,
    mode: EnforcementMode | str,
    on_deny: Literal["raise", "tool_error"],
    injected_args_keys: frozenset[str],
) -> Callable[..., Awaitable[Any]]:
    default_snapshot = _default_snapshot(snapshot)

    async def guarded(args_value: JsonValue, *args: Any, **kwargs: Any) -> Any:
        per_call_snapshot = _pop_common_adapter_kwargs(kwargs)
        explicit_call_id = kwargs.pop(TOOL_CALL_ID_KWARG, None)
        merged_snapshot = _merge_snapshot(default_snapshot, per_call_snapshot)
        tool_call = args_value if isinstance(args_value, Mapping) and args_value.get("type") == "tool_call" else None
        call_id = tool_call.get("id") if tool_call is not None else None
        if tool_call is not None:
            if not isinstance(call_id, str) or not call_id:
                raise AdapterUnsupportedError("A LangChain ToolCall must have a non-empty id.")
            if explicit_call_id is not None and explicit_call_id != call_id:
                raise ValueError("agent_control_tool_call_id must match the LangChain ToolCall id")
            policy_args = tool_call.get("args")
            if not isinstance(policy_args, Mapping):
                raise AdapterUnsupportedError("A LangChain ToolCall must have mapping args.")
            injected_args = {key: value for key, value in policy_args.items() if key in injected_args_keys}
            policy_args = {key: value for key, value in policy_args.items() if key not in injected_args_keys}
        else:
            policy_args = args_value
            injected_args = {}
        effective_call_id = call_id or explicit_call_id or tool_call_id
        original_message: Any = None
        serialized_message: JsonValue | None = None

        async def execute_effective(effective_args: JsonValue) -> JsonValue:
            nonlocal original_message, serialized_message
            if tool_call is not None:
                if not isinstance(effective_args, Mapping):
                    raise AdapterUnsupportedError("A transformed LangChain ToolCall must have mapping args.")
                if injected_args_keys.intersection(effective_args):
                    raise AdapterUnsupportedError("Policy cannot transform injected LangChain tool arguments.")
                effective_input = {**tool_call, "args": {**effective_args, **injected_args}}
            else:
                effective_input = effective_args
            output = await _maybe_await(method(effective_input, *args, **kwargs))
            if tool_call is not None:
                from langchain_core.messages import ToolMessage
                from pydantic_core import PydanticSerializationError

                if isinstance(output, ToolMessage):
                    original_message = output
                    try:
                        serialized_message = output.model_dump(mode="json")
                    except PydanticSerializationError as exc:
                        raise AdapterUnsupportedError(
                            "LangChain ToolMessage artifact and fields must be JSON-serializable for post-tool policy evaluation."
                        ) from exc
                    return serialized_message
            return output

        try:
            result = await control.run_tool(
                tool_name,
                policy_args,
                execute_effective,
                tool_call_id=effective_call_id,
                snapshot=merged_snapshot,
                mode=mode,
            )
        except AgentControlBlocked as exc:
            if on_deny != "tool_error" or type(exc) is not AgentControlBlocked:
                raise
            if exc.intervention_point not in (InterventionPoint.PRE_TOOL_CALL, InterventionPoint.POST_TOOL_CALL):
                raise
            if (exc.result.verdict.reason or "").startswith(("runtime_error:", "host_error:")):
                raise
            return _tool_deny_message(exc, tool_name, effective_call_id)

        if original_message is not None:
            if result.value == serialized_message:
                return original_message
            from langchain_core.messages import ToolMessage

            if isinstance(result.value, Mapping) and "tool_call_id" in result.value:
                transformed = ToolMessage.model_validate(result.value)
                if transformed.tool_call_id != call_id:
                    raise AdapterUnsupportedError("A transformed LangChain ToolMessage cannot change the tool call id.")
                return transformed
            if isinstance(result.value, Mapping):
                content = json.dumps(result.value, ensure_ascii=False)
            elif isinstance(result.value, str | list):
                content = result.value
            else:
                raise AdapterUnsupportedError("A transformed LangChain ToolMessage must have valid content.")
            return ToolMessage(
                content=content, name=tool_name, tool_call_id=call_id, status=original_message.status,
            )
        return result.value

    return guarded


def _tool_deny_message(exc: AgentControlBlocked, tool_name: str, tool_call_id: str | None) -> Any:
    reason = exc.result.verdict.reason or "policy_denied"
    message = exc.result.verdict.message or "This tool is not permitted for this agent."
    content = f"Tool use denied by policy ({reason}): {message} Do not retry this tool call."
    denial = {"error": "policy_denied", "reason": reason, "message": message, "terminal": True}
    if tool_call_id is None:
        return denial
    from langchain_core.messages import ToolMessage

    return ToolMessage(
        content=content, name=tool_name, tool_call_id=tool_call_id, status="error",
        additional_kwargs={"agent_control": denial},
    )


def _sync_from_async(method: Callable[..., Awaitable[OutputT]]) -> Callable[..., OutputT]:
    def guarded(*args: Any, **kwargs: Any) -> OutputT:
        return run_sync(method(*args, **kwargs))

    return guarded


def _add_batches(
    target: Any, overrides: dict[str, Any], sync_method: Callable[..., Awaitable[Any]] | None,
) -> None:
    if callable(getattr(target, "batch", None)) and sync_method is not None:
        overrides["batch"] = _guarded_batch(sync_method)
    if callable(getattr(target, "abatch", None)) and "ainvoke" in overrides:
        overrides["abatch"] = _guarded_abatch(overrides["ainvoke"])


def _batch_configs(config: Any, length: int) -> list[Any]:
    if isinstance(config, list):
        if len(config) != length:
            raise ValueError(f"batch config length {len(config)} does not match inputs length {length}")
        return config
    return [config] * length


async def _execute_batch(
    invoke: Callable[..., Awaitable[OutputT]],
    inputs: list[JsonValue],
    config: Any,
    return_exceptions: bool,
    kwargs: dict[str, Any],
) -> list[OutputT | Exception]:
    outputs: list[OutputT | Exception] = []
    for value, item_config in zip(inputs, _batch_configs(config, len(inputs))):
        try:
            outputs.append(
                await invoke(value, item_config, **kwargs)
                if item_config is not None else await invoke(value, **kwargs)
            )
        except (AgentControlInterruption, AgentControlRuntimeError):
            raise
        except Exception as exc:
            if not return_exceptions:
                raise
            outputs.append(exc)
    return outputs


def _guarded_batch(invoke: Callable[..., Awaitable[OutputT]]) -> Callable[..., list[OutputT | Exception]]:
    def guarded(
        inputs: list[JsonValue], config: Any = None, *, return_exceptions: bool = False, **kwargs: Any,
    ) -> list[OutputT | Exception]:
        return run_sync(_execute_batch(invoke, inputs, config, return_exceptions, kwargs))

    return guarded


def _guarded_abatch(invoke: Callable[..., Awaitable[OutputT]]) -> Callable[..., Awaitable[list[OutputT | Exception]]]:
    async def guarded(
        inputs: list[JsonValue], config: Any = None, *, return_exceptions: bool = False, **kwargs: Any,
    ) -> list[OutputT | Exception]:
        return await _execute_batch(invoke, inputs, config, return_exceptions, kwargs)

    return guarded


def _blocked_langchain_methods(target: Any, overrides: Mapping[str, Any], *, tool: bool = False) -> dict[str, str]:
    names = (
        "invoke", "batch", "abatch", *_ITERATOR_METHODS, *_DERIVED_RUNNABLE_METHODS,
        *(("run", "arun") if tool else ()),
    )
    return {
        name: f"{name} is not guarded by this adapter; use invoke()/ainvoke() or batch()/abatch()."
        for name in names if name not in overrides and hasattr(target, name)
    }
