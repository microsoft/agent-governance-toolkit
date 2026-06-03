from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any, Generic, Protocol, TypeVar

from .._orchestration import AgentControl
from .._types import (
    ApprovalResolver,
    EnforcementMode,
    JsonValue,
    InterventionPoint,
    InterventionPointResult,
)
from ._errors import AdapterUnsupportedError
from ._shared import (
    Execute,
    _merge_snapshot,
    _maybe_await,
    _ObjectProxy,
    _pop_common_adapter_kwargs,
    _require_callable,
    _transformed_or,
)

AgentT = TypeVar("AgentT")
ModelRequestT = TypeVar("ModelRequestT")
ModelResponseT = TypeVar("ModelResponseT")


@dataclass(frozen=True)
class ModelCallResult:
    value: JsonValue
    pre_model_call_result: InterventionPointResult
    post_model_call_result: InterventionPointResult


class FullCoverageAgentAdapter(Protocol[AgentT]):
    """Framework-specific Pattern A adapter surface."""

    def guard(self, agent: AgentT, control: AgentControl) -> AgentT: ...


class ModelInterventionPointMiddleware(Protocol[ModelRequestT, ModelResponseT]):
    """Protocol for frameworks exposing explicit pre/post model middleware."""

    async def pre_model_call(self, model_request: ModelRequestT) -> InterventionPointResult: ...

    async def post_model_call(self, model_response: ModelResponseT) -> InterventionPointResult: ...


class UnsupportedFrameworkAdapter(Generic[AgentT]):
    """Explicit non-implementation for future framework adapters."""

    def __init__(self, framework_name: str):
        self.framework_name = framework_name

    def guard(self, agent: AgentT, control: AgentControl) -> AgentT:
        raise AdapterUnsupportedError(
            f"Full-coverage {self.framework_name} adapter is not implemented yet; "
            "use AgentControl.run(), guard_run(), guard_model_call(), or guard_tool() "
            "with explicit per-call snapshots."
        )


async def run_model_call(
    control: AgentControl,
    model_request: JsonValue,
    execute: Callable[[JsonValue], JsonValue | Awaitable[JsonValue]],
    *,
    snapshot: Mapping[str, JsonValue] | None = None,
    mode: EnforcementMode | str = EnforcementMode.ENFORCE,
    approval_resolver: "ApprovalResolver | None" = None,
) -> ModelCallResult:
    """Evaluate pre_model_call/post_model_call around a single model request."""

    enforcement_mode = EnforcementMode(mode)
    ambient = dict(snapshot or {})

    pre_result = await control.evaluate_intervention_point(
        InterventionPoint.PRE_MODEL_CALL,
        {**ambient, "model_request": model_request},
        enforcement_mode,
    )
    await control.enforce(
        InterventionPoint.PRE_MODEL_CALL, pre_result, enforcement_mode, approval_resolver=approval_resolver
    )
    effective_request = _transformed_or(pre_result, model_request, enforcement_mode)

    model_response = await _maybe_await(execute(effective_request))

    post_result = await control.evaluate_intervention_point(
        InterventionPoint.POST_MODEL_CALL,
        {
            **ambient,
            "model_request": effective_request,
            "model_response": model_response,
        },
        enforcement_mode,
    )
    await control.enforce(
        InterventionPoint.POST_MODEL_CALL, post_result, enforcement_mode, approval_resolver=approval_resolver
    )
    return ModelCallResult(
        value=_transformed_or(post_result, model_response, enforcement_mode),
        pre_model_call_result=pre_result,
        post_model_call_result=post_result,
    )


def guard_run(
    control: AgentControl,
    execute: Execute,
    *,
    snapshot: Mapping[str, JsonValue] | None = None,
    mode: EnforcementMode | str = EnforcementMode.ENFORCE,
    approval_resolver: ApprovalResolver | None = None,
) -> Callable[..., Awaitable[JsonValue]]:
    """Return an async callable guarded by input/output intervention points."""

    default_snapshot = dict(snapshot or {})

    async def guarded(input_value: JsonValue, *args: Any, **kwargs: Any) -> JsonValue:
        per_call_snapshot = _pop_common_adapter_kwargs(kwargs)
        merged_snapshot = _merge_snapshot(default_snapshot, per_call_snapshot)

        async def execute_effective(effective_input: JsonValue) -> JsonValue:
            return await _maybe_await(execute(effective_input, *args, **kwargs))

        result = await control.run(
            input_value,
            execute_effective,
            snapshot=merged_snapshot,
            mode=mode,
            approval_resolver=approval_resolver,
        )
        return result.value

    return guarded


def guard_model_call(
    control: AgentControl,
    execute: Execute,
    *,
    snapshot: Mapping[str, JsonValue] | None = None,
    mode: EnforcementMode | str = EnforcementMode.ENFORCE,
    approval_resolver: ApprovalResolver | None = None,
) -> Callable[..., Awaitable[JsonValue]]:
    """Return an async callable guarded by pre/post model-call intervention points."""

    default_snapshot = dict(snapshot or {})

    async def guarded(model_request: JsonValue, *args: Any, **kwargs: Any) -> JsonValue:
        per_call_snapshot = _pop_common_adapter_kwargs(kwargs)
        merged_snapshot = _merge_snapshot(default_snapshot, per_call_snapshot)

        async def execute_effective(effective_request: JsonValue) -> JsonValue:
            return await _maybe_await(execute(effective_request, *args, **kwargs))

        result = await run_model_call(
            control,
            model_request,
            execute_effective,
            snapshot=merged_snapshot,
            mode=mode,
            approval_resolver=approval_resolver,
        )
        return result.value

    return guarded


def guard_tool(
    control: AgentControl,
    tool_name: str,
    execute: Execute,
    *,
    tool_call_id: str | None = None,
    snapshot: Mapping[str, JsonValue] | None = None,
    mode: EnforcementMode | str = EnforcementMode.ENFORCE,
    approval_resolver: ApprovalResolver | None = None,
) -> Callable[..., Awaitable[JsonValue]]:
    """Return an async tool callable guarded by pre/post tool-call intervention points."""

    default_snapshot = dict(snapshot or {})

    async def guarded(args_value: JsonValue, *args: Any, **kwargs: Any) -> JsonValue:
        per_call_snapshot = _pop_common_adapter_kwargs(kwargs)
        call_id = kwargs.pop(TOOL_CALL_ID_KWARG, tool_call_id)
        merged_snapshot = _merge_snapshot(default_snapshot, per_call_snapshot)

        async def execute_effective(effective_args: JsonValue) -> JsonValue:
            return await _maybe_await(execute(effective_args, *args, **kwargs))

        result = await control.run_tool(
            tool_name,
            args_value,
            execute_effective,
            tool_call_id=call_id,
            snapshot=merged_snapshot,
            mode=mode,
            approval_resolver=approval_resolver,
        )
        return result.value

    return guarded


def guard_agent_method(
    control: AgentControl,
    agent: AgentT,
    method_name: str,
    *,
    input_kwarg: str | None = None,
    snapshot: Mapping[str, JsonValue] | None = None,
    mode: EnforcementMode | str = EnforcementMode.ENFORCE,
    blocked_methods: tuple[str, ...] = (),
) -> AgentT:
    """Wrap one duck-typed agent method with input/output enforcement."""

    method = _require_callable(agent, method_name, "agent")
    guarded_method = _guard_invocation_method(
        control,
        method,
        input_kwarg=input_kwarg,
        snapshot=snapshot,
        mode=mode,
    )
    blocked = {
        name: f"{name} is not guarded by this adapter; use {method_name} or AgentControl.run()."
        for name in blocked_methods
        if name != method_name and hasattr(agent, name)
    }
    return _ObjectProxy(agent, overrides={method_name: guarded_method}, blocked=blocked)  # type: ignore[return-value]


def _guard_invocation_method(
    control: AgentControl,
    method: Execute,
    *,
    input_kwarg: str | None,
    snapshot: Mapping[str, JsonValue] | None,
    mode: EnforcementMode | str,
) -> Callable[..., Awaitable[JsonValue]]:
    default_snapshot = dict(snapshot or {})

    async def guarded(*args: Any, **kwargs: Any) -> JsonValue:
        per_call_snapshot = _pop_common_adapter_kwargs(kwargs)
        policy_target, execute_effective = _policy_target_and_executor(method, args, kwargs, input_kwarg)
        merged_snapshot = _merge_snapshot(default_snapshot, per_call_snapshot)
        result = await control.run(
            policy_target,
            execute_effective,
            snapshot=merged_snapshot,
            mode=mode,
        )
        return result.value

    return guarded


def _policy_target_and_executor(
    method: Execute,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    input_kwarg: str | None,
) -> tuple[JsonValue, Callable[[JsonValue], Awaitable[JsonValue]]]:
    if args:
        policy_target = args[0]
        rest = args[1:]

        async def execute_effective(effective_policy_target: JsonValue) -> JsonValue:
            return await _maybe_await(method(effective_policy_target, *rest, **kwargs))

        return policy_target, execute_effective

    names = tuple(name for name in (input_kwarg, "input", "inputs", "prompt", "messages") if name)
    for name in names:
        if name in kwargs:
            policy_target = kwargs[name]

            async def execute_effective(
                effective_policy_target: JsonValue,
                *,
                selected_name: str = name,
            ) -> JsonValue:
                effective_kwargs = dict(kwargs)
                effective_kwargs[selected_name] = effective_policy_target
                return await _maybe_await(method(**effective_kwargs))

            return policy_target, execute_effective

    if kwargs:
        policy_target = dict(kwargs)

        async def execute_effective(effective_policy_target: JsonValue) -> JsonValue:
            if not isinstance(effective_policy_target, Mapping):
                raise AdapterUnsupportedError(
                    "Cannot apply transformed kwargs policy_target because it is not a mapping."
                )
            return await _maybe_await(method(**dict(effective_policy_target)))

        return policy_target, execute_effective

    raise AdapterUnsupportedError(
        "Cannot infer an input policy_target for this method; pass a positional input, "
        "an input/inputs keyword, or call AgentControl.run() explicitly."
    )


from ._shared import TOOL_CALL_ID_KWARG  # noqa: E402
