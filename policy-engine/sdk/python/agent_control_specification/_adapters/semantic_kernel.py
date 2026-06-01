from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from typing import Any, TypeVar

from .._orchestration import AgentControl
from .._types import EnforcementMode, JsonValue
from ._errors import AdapterUnsupportedError
from ._shared import (
    Execute,
    TOOL_CALL_ID_KWARG,
    _maybe_await,
    _merge_snapshot,
    _ObjectProxy,
    _pop_common_adapter_kwargs,
    _resolve_control_and_target,
    _string_or_none,
)

AgentT = TypeVar("AgentT")


def guard_semantic_kernel_function(
    control_or_function: AgentControl | AgentT,
    function: AgentT | None = None,
    *,
    control: AgentControl | None = None,
    tool_call_id: str | None = None,
    snapshot: Mapping[str, JsonValue] | None = None,
    mode: EnforcementMode | str = EnforcementMode.ENFORCE,
) -> AgentT:
    """Guard a duck-typed Semantic Kernel KernelFunction."""

    resolved_control, resolved_function = _resolve_control_and_target(
        control_or_function,
        function,
        control=control,
        target_name="Semantic Kernel function",
        adapter_name="guard_semantic_kernel_function",
    )
    tool_name = _semantic_kernel_function_name(resolved_function)
    overrides: dict[str, Any] = {}
    for method_name in ("invoke", "invoke_async", "__call__"):
        method = getattr(resolved_function, method_name, None)
        if callable(method):
            overrides[method_name] = _guard_semantic_kernel_function_method(
                resolved_control,
                tool_name,
                method,
                tool_call_id=tool_call_id,
                snapshot=snapshot,
                mode=mode,
            )

    if not overrides:
        raise AdapterUnsupportedError(
            "Semantic Kernel function adapter requires invoke(...), invoke_async(...), or __call__(...)."
        )

    proxy_cls = _CallableObjectProxy if "__call__" in overrides else _ObjectProxy
    return proxy_cls(resolved_function, overrides=overrides)  # type: ignore[return-value]


def guard_semantic_kernel_filter(
    control: AgentControl,
    *,
    snapshot: Mapping[str, JsonValue] | None = None,
    mode: EnforcementMode | str = EnforcementMode.ENFORCE,
) -> Callable[[Any, Execute], Awaitable[None]]:
    """Return a Semantic Kernel-style async function-invocation filter."""

    if not isinstance(control, AgentControl):
        raise AdapterUnsupportedError(
            "guard_semantic_kernel_filter() requires an AgentControl instance."
        )

    default_snapshot = dict(snapshot or {})

    async def filter(context: Any, next: Execute) -> None:
        if not callable(next):
            raise AdapterUnsupportedError("Semantic Kernel filter next must be callable.")

        tool_name = _semantic_kernel_function_name(getattr(context, "function", None))
        arguments = getattr(context, "arguments", None)
        tool_args = _arguments_snapshot(arguments)
        call_id = _semantic_kernel_tool_call_id(context)
        merged_snapshot = _merge_snapshot(default_snapshot, _context_snapshot(context))

        async def execute_effective(effective_args: JsonValue) -> JsonValue:
            _set_context_arguments(context, effective_args)
            await _maybe_await(next(context))
            return getattr(context, "result", None)

        result = await control.run_tool(
            tool_name,
            tool_args,
            execute_effective,
            tool_call_id=call_id,
            snapshot=merged_snapshot,
            mode=mode,
        )
        context.result = result.value

    return filter


class _CallableObjectProxy(_ObjectProxy):
    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self.__getattr__("__call__")(*args, **kwargs)


def _guard_semantic_kernel_function_method(
    control: AgentControl,
    tool_name: str,
    method: Execute,
    *,
    tool_call_id: str | None,
    snapshot: Mapping[str, JsonValue] | None,
    mode: EnforcementMode | str,
) -> Callable[..., Awaitable[JsonValue]]:
    default_snapshot = dict(snapshot or {})

    async def guarded(*args: Any, **kwargs: Any) -> JsonValue:
        per_call_snapshot = _pop_common_adapter_kwargs(kwargs)
        explicit_call_id = kwargs.pop(TOOL_CALL_ID_KWARG, None)
        arguments = _semantic_kernel_arguments(args, kwargs)
        tool_args = _arguments_snapshot(arguments)
        merged_snapshot = _merge_snapshot(default_snapshot, per_call_snapshot)

        async def execute_effective(effective_args: JsonValue) -> JsonValue:
            _apply_effective_arguments(arguments, effective_args)
            return await _maybe_await(method(*args, **dict(kwargs)))

        result = await control.run_tool(
            tool_name,
            tool_args,
            execute_effective,
            tool_call_id=_effective_tool_call_id(explicit_call_id, tool_call_id),
            snapshot=merged_snapshot,
            mode=mode,
        )
        return result.value

    return guarded


def _semantic_kernel_function_name(function: Any) -> str:
    name = _string_or_none(getattr(function, "name", None))
    if name is not None:
        return name
    metadata = getattr(function, "metadata", None)
    name = _string_or_none(getattr(metadata, "name", None))
    if name is not None:
        return name
    raise AdapterUnsupportedError("Semantic Kernel function must expose name or metadata.name.")


def _semantic_kernel_arguments(args: tuple[Any, ...], kwargs: Mapping[str, Any]) -> Any:
    if "arguments" in kwargs:
        return kwargs["arguments"]
    if len(args) > 1:
        return args[1]
    if args:
        return args[0]
    raise AdapterUnsupportedError("Semantic Kernel function invocation must include arguments.")


def _arguments_snapshot(arguments: Any) -> JsonValue:
    if arguments is None:
        return {}
    if isinstance(arguments, Mapping):
        return dict(arguments)
    items = getattr(arguments, "items", None)
    if callable(items):
        try:
            return dict(items())
        except Exception as exc:  # noqa: BLE001
            raise AdapterUnsupportedError("Semantic Kernel arguments must be mapping-like.") from exc
    raise AdapterUnsupportedError("Semantic Kernel arguments must be mapping-like.")


def _apply_effective_arguments(arguments: Any, effective_args: JsonValue) -> None:
    if arguments is effective_args:
        return
    if not isinstance(effective_args, Mapping):
        raise AdapterUnsupportedError(
            "Cannot apply transformed Semantic Kernel arguments because they are not a mapping."
        )

    try:
        if hasattr(arguments, "clear") and hasattr(arguments, "update"):
            arguments.clear()
            arguments.update(dict(effective_args))
            return

        keys = list(arguments.keys())
        for key in keys:
            del arguments[key]
        for key, value in dict(effective_args).items():
            arguments[key] = value
    except Exception as exc:  # noqa: BLE001
        raise AdapterUnsupportedError(
            "Cannot apply transformed Semantic Kernel arguments to the invocation."
        ) from exc


def _set_context_arguments(context: Any, effective_args: JsonValue) -> None:
    try:
        context.arguments = effective_args
    except Exception as exc:  # noqa: BLE001
        raise AdapterUnsupportedError(
            "Cannot apply transformed Semantic Kernel arguments to the filter context."
        ) from exc


def _semantic_kernel_tool_call_id(context: Any) -> str | None:
    return (
        _string_or_none(getattr(context, "tool_call_id", None))
        or _string_or_none(getattr(context, "toolCallId", None))
        or _string_or_none(getattr(context, "id", None))
    )


def _context_snapshot(context: Any) -> Mapping[str, JsonValue] | None:
    value = getattr(context, "snapshot", None)
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise TypeError("Semantic Kernel filter context snapshot must be a mapping.")
    return value


def _effective_tool_call_id(explicit_call_id: Any, default_call_id: str | None) -> Any:
    if explicit_call_id is not None:
        return explicit_call_id
    return default_call_id
