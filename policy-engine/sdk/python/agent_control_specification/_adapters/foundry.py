from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Mapping
from typing import Any, TypeVar

from .._orchestration import AgentControl
from .._types import (
    AgentControlBlocked,
    ApprovalResolver,
    EnforcementMode,
    JsonValue,
)
from ._errors import AdapterUnsupportedError
from ._shared import (
    _jsonable,
    _maybe_await,
    _merge_snapshot,
    _ObjectProxy,
    _resolve_control_and_target,
)

AgentT = TypeVar("AgentT")

# Run statuses that keep the manual run loop turning. The runtime drives until a
# terminal status (``completed``, ``failed``, ``cancelled``, ``expired``) is
# reached. Values mirror azure.ai.agents.models.RunStatus.
_REQUIRES_ACTION = "requires_action"
_ACTIVE_STATUSES = frozenset(
    {"queued", "in_progress", _REQUIRES_ACTION, "cancelling"}
)

# Default seconds to wait between non-action polls of runs.get. A host can pass
# poll_interval=0 to disable the delay (the fake-client tests do this).
_DEFAULT_POLL_INTERVAL = 0.5

# The Foundry methods that execute Python tools inside the SDK before any policy
# can intervene. The governed wrapper blocks them so the auto-function-call
# bypass is unreachable through the governed handle.
_BYPASS_MESSAGE = (
    "This method auto-executes agent tools before ACS can gate them. Drive the "
    "governed run loop with create_thread_and_run(...) or "
    "run_until_complete(...) so pre_tool_call and post_tool_call are enforced."
)
_BLOCKED_CLIENT_METHODS = ("enable_auto_function_calls",)
_BLOCKED_RUNS_METHODS = ("create_and_process", "create_and_poll", "stream")


def guard_foundry_agent(
    control_or_client: AgentControl | AgentT,
    client: AgentT | None = None,
    *,
    tools: Mapping[str, Callable[..., Any]],
    control: AgentControl | None = None,
    snapshot: Mapping[str, JsonValue] | None = None,
    mode: EnforcementMode | str = EnforcementMode.ENFORCE,
    approval_resolver: ApprovalResolver | None = None,
) -> AgentT:
    """Govern a live Azure AI Foundry hosted agent run loop with ACS.

    Foundry's governance seam is the manual run loop, not a single client
    method. The host posts a message, creates a run, then polls until the run
    reports ``requires_action`` and hands back the tool calls the model wants to
    make. This adapter intercepts at that seam. Each required function tool call
    is routed through ``control.run_tool`` so ``pre_tool_call`` gates the
    arguments and ``post_tool_call`` gates the result before the output is
    submitted back to the model.

    The return value is a thin proxy over the real ``AgentsClient`` that adds a
    governed run driver (``create_thread_and_run`` and ``run_until_complete``)
    and blocks the SDK's auto-function-call path. ``enable_auto_function_calls``
    and ``runs.create_and_process`` execute Python tools inside the SDK before a
    policy can run, so they are blocked rather than delegated. ``threads``,
    ``messages``, and the remaining ``runs`` operations pass through unchanged.

    ``tools`` maps a Foundry function tool name to the host callable that
    implements it. The model picks the tool and supplies JSON arguments. The
    callable is invoked with those arguments as keywords only after
    ``pre_tool_call`` allows or transforms them. A deny submits a policy
    rejection output instead of executing, so the underlying callable never
    runs. An escalate is routed to ``approval_resolver`` and is never
    auto-allowed.
    """

    resolved_control, resolved_client = _resolve_control_and_target(
        control_or_client,
        client,
        control=control,
        target_name="Azure AI Foundry AgentsClient",
        adapter_name="guard_foundry_agent",
    )
    resolved_tools = _validate_tools(tools)
    if not _is_foundry_run_surface(resolved_client):
        raise AdapterUnsupportedError(_unsupported_surface_message())

    driver = _FoundryRunDriver(
        resolved_control,
        resolved_client,
        resolved_tools,
        default_snapshot=dict(snapshot or {}),
        mode=mode,
        approval_resolver=approval_resolver,
    )
    runs_proxy = _ObjectProxy(
        resolved_client.runs,
        blocked={
            name: _BYPASS_MESSAGE
            for name in _BLOCKED_RUNS_METHODS
            if callable(getattr(resolved_client.runs, name, None))
        },
    )
    return _ObjectProxy(
        resolved_client,
        overrides={
            "create_thread_and_run": driver.create_thread_and_run,
            "run_until_complete": driver.run_until_complete,
            "runs": runs_proxy,
        },
        blocked={
            name: _BYPASS_MESSAGE
            for name in _BLOCKED_CLIENT_METHODS
            if callable(getattr(resolved_client, name, None))
        },
    )  # type: ignore[return-value]


# guard_azure_ai_agents is the package-name-aligned alias for guard_foundry_agent.
guard_azure_ai_agents = guard_foundry_agent


class _FoundryRunDriver:
    """Owns the manual requires_action -> submit_tool_outputs loop.

    The driver calls the real client directly so the blocked bypass methods on
    the returned proxy never interfere with its own polling and submission.
    """

    def __init__(
        self,
        control: AgentControl,
        client: Any,
        tools: dict[str, Callable[..., Any]],
        *,
        default_snapshot: Mapping[str, JsonValue],
        mode: EnforcementMode | str,
        approval_resolver: ApprovalResolver | None,
    ) -> None:
        self._control = control
        self._client = client
        self._tools = tools
        self._default_snapshot = dict(default_snapshot)
        self._mode = mode
        self._approval_resolver = approval_resolver

    async def create_thread_and_run(
        self,
        agent_id: str,
        *,
        content: JsonValue | None = None,
        role: str = "user",
        thread_id: str | None = None,
        poll_interval: float = _DEFAULT_POLL_INTERVAL,
        snapshot: Mapping[str, JsonValue] | None = None,
        approval_resolver: ApprovalResolver | None = None,
        **run_kwargs: Any,
    ) -> Any:
        """Create a thread and run, then drive the governed loop to completion.

        When ``thread_id`` is omitted a fresh thread is created. When ``content``
        is provided one user message is posted before the run starts. Extra
        keyword arguments flow to ``runs.create`` unchanged so a host can set
        ``model``, ``instructions``, ``temperature``, and similar run options.
        """

        client = self._client
        if thread_id is None:
            thread = await _maybe_await(client.threads.create())
            thread_id = _identity(thread)
        if content is not None:
            await _maybe_await(
                client.messages.create(thread_id=thread_id, role=role, content=content)
            )
        run = await _maybe_await(client.runs.create(thread_id, agent_id=agent_id, **run_kwargs))
        return await self._drive(
            thread_id,
            _identity(run),
            first_run=run,
            poll_interval=poll_interval,
            snapshot=snapshot,
            approval_resolver=approval_resolver,
        )

    async def run_until_complete(
        self,
        thread_id: str,
        run_id: str,
        *,
        poll_interval: float = _DEFAULT_POLL_INTERVAL,
        snapshot: Mapping[str, JsonValue] | None = None,
        approval_resolver: ApprovalResolver | None = None,
    ) -> Any:
        """Drive an already-created run to a terminal status under governance."""

        return await self._drive(
            thread_id,
            run_id,
            first_run=None,
            poll_interval=poll_interval,
            snapshot=snapshot,
            approval_resolver=approval_resolver,
        )

    async def _drive(
        self,
        thread_id: str,
        run_id: str,
        *,
        first_run: Any,
        poll_interval: float,
        snapshot: Mapping[str, JsonValue] | None,
        approval_resolver: ApprovalResolver | None,
    ) -> Any:
        client = self._client
        resolver = approval_resolver if approval_resolver is not None else self._approval_resolver
        merged_snapshot = _merge_snapshot(self._default_snapshot, snapshot)
        run = first_run
        if run is None:
            run = await _maybe_await(client.runs.get(thread_id=thread_id, run_id=run_id))
        while _run_status(run) in _ACTIVE_STATUSES:
            if _run_status(run) == _REQUIRES_ACTION:
                outputs = await self._govern_required_calls(
                    run, thread_id, run_id, merged_snapshot, resolver
                )
                run = await _maybe_await(
                    client.runs.submit_tool_outputs(
                        thread_id=thread_id, run_id=run_id, tool_outputs=outputs
                    )
                )
                continue
            if poll_interval:
                await asyncio.sleep(poll_interval)
            run = await _maybe_await(client.runs.get(thread_id=thread_id, run_id=run_id))
        return run

    async def _govern_required_calls(
        self,
        run: Any,
        thread_id: str,
        run_id: str,
        merged_snapshot: Mapping[str, JsonValue],
        resolver: ApprovalResolver | None,
    ) -> list[Any]:
        context: dict[str, JsonValue] = {"thread_id": thread_id, "run_id": run_id}
        agent_id = _get(run, "agent_id")
        if agent_id is None:
            agent_id = _get(run, "assistant_id")
        if isinstance(agent_id, str):
            context["agent_id"] = agent_id
        # Host snapshot keys win over the run context derived here.
        call_snapshot = {**context, **dict(merged_snapshot)}
        outputs: list[Any] = []
        for tool_call in _required_tool_calls(run):
            outputs.append(await self._govern_one_call(tool_call, call_snapshot, resolver))
        return outputs

    async def _govern_one_call(
        self,
        tool_call: Any,
        snapshot: Mapping[str, JsonValue],
        resolver: ApprovalResolver | None,
    ) -> Any:
        call_id, name, args, parse_error = _parse_tool_call(tool_call)
        if parse_error is not None:
            return _build_tool_output(call_id, _rejection_text(_REQUIRES_ACTION, parse_error))
        function = self._tools.get(name) if name is not None else None
        if function is None:
            reason = f"tool {name!r} is not registered with guard_foundry_agent"
            return _build_tool_output(call_id, _rejection_text(_REQUIRES_ACTION, reason))

        async def execute_effective(effective_args: JsonValue) -> JsonValue:
            if isinstance(effective_args, Mapping):
                return await _maybe_await(function(**dict(effective_args)))
            return await _maybe_await(function(effective_args))

        try:
            tool_result = await self._control.run_tool(
                name,
                args,
                execute_effective,
                tool_call_id=call_id,
                snapshot=snapshot,
                mode=self._mode,
                approval_resolver=resolver,
            )
        except AgentControlBlocked as blocked:
            reason = blocked.result.verdict.reason or "policy blocked the tool call"
            return _build_tool_output(
                call_id, _rejection_text(blocked.intervention_point.value, reason)
            )
        return _build_tool_output(call_id, _as_output_text(tool_result.value))


def _validate_tools(tools: Mapping[str, Callable[..., Any]]) -> dict[str, Callable[..., Any]]:
    if not isinstance(tools, Mapping) or not tools:
        raise AdapterUnsupportedError(
            "guard_foundry_agent requires a non-empty mapping of tool name to callable."
        )
    resolved: dict[str, Callable[..., Any]] = {}
    for name, function in tools.items():
        if not isinstance(name, str) or not callable(function):
            raise AdapterUnsupportedError(
                "guard_foundry_agent tools must map string tool names to callables."
            )
        resolved[name] = function
    return resolved


def _is_foundry_run_surface(client: Any) -> bool:
    return all(
        _has_callable_path(client, path)
        for path in (
            ("threads", "create"),
            ("messages", "create"),
            ("runs", "create"),
            ("runs", "get"),
            ("runs", "submit_tool_outputs"),
        )
    )


def _has_callable_path(target: Any, path: tuple[str, ...]) -> bool:
    current = target
    for name in path:
        current = getattr(current, name, None)
        if current is None:
            return False
    return callable(current)


def _unsupported_surface_message() -> str:
    base = (
        "guard_foundry_agent requires an Azure AI Foundry AgentsClient exposing "
        "threads.create, messages.create, and runs.create/get/submit_tool_outputs."
    )
    if not _foundry_sdk_available():
        return base + " Install the optional SDK with pip install azure-ai-agents."
    return base


def _foundry_sdk_available() -> bool:
    import importlib.util

    return importlib.util.find_spec("azure.ai.agents") is not None


def _tool_output_factory() -> Callable[..., Any] | None:
    """Return the real ToolOutput model when the optional SDK is importable.

    The faithful model and a plain dict both serialize through
    runs.submit_tool_outputs, so the dict fallback keeps the adapter usable
    without azure-ai-agents installed.
    """

    try:
        from azure.ai.agents.models import ToolOutput
    except ImportError:
        return None
    return ToolOutput


def _build_tool_output(call_id: str | None, output_text: str) -> Any:
    factory = _tool_output_factory()
    if factory is not None:
        try:
            return factory(tool_call_id=call_id, output=output_text)
        except Exception:  # noqa: BLE001 - fall back to the dict shape the SDK also accepts
            pass
    return {"tool_call_id": call_id, "output": output_text}


def _rejection_text(intervention_point: str, reason: str) -> str:
    return json.dumps(
        {
            "agent_control": "blocked",
            "intervention_point": intervention_point,
            "reason": reason,
        },
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _as_output_text(value: JsonValue) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(_jsonable(value), separators=(",", ":"), ensure_ascii=False)


def _run_status(run: Any) -> str:
    status = _get(run, "status")
    if status is None:
        return ""
    value = getattr(status, "value", None)
    if isinstance(value, str):
        return value
    return str(status)


def _required_tool_calls(run: Any) -> list[Any]:
    action = _get(run, "required_action")
    submit = _get(action, "submit_tool_outputs") if action is not None else None
    tool_calls = _get(submit, "tool_calls") if submit is not None else None
    if isinstance(tool_calls, (list, tuple)):
        return list(tool_calls)
    return []


def _parse_tool_call(tool_call: Any) -> tuple[str | None, str | None, JsonValue, str | None]:
    call_id = _get(tool_call, "id")
    call_id = call_id if isinstance(call_id, str) else None
    function = _get(tool_call, "function")
    if function is None:
        return call_id, None, {}, "required tool call is not a function tool call"
    name = _get(function, "name")
    if not isinstance(name, str) or not name:
        return call_id, None, {}, "function tool call is missing a string name"
    raw_arguments = _get(function, "arguments")
    args, parse_error = _parse_arguments(raw_arguments)
    return call_id, name, args, parse_error


def _parse_arguments(raw_arguments: Any) -> tuple[JsonValue, str | None]:
    if raw_arguments is None or raw_arguments == "":
        return {}, None
    if isinstance(raw_arguments, Mapping):
        return dict(raw_arguments), None
    if isinstance(raw_arguments, str):
        try:
            return json.loads(raw_arguments), None
        except json.JSONDecodeError:
            return {}, "function tool call arguments are not valid JSON"
    return {}, "function tool call arguments must be a JSON object string"


def _identity(obj: Any) -> str:
    value = _get(obj, "id")
    if not isinstance(value, str) or not value:
        raise AdapterUnsupportedError(
            "Azure AI Foundry thread/run objects must expose a string id."
        )
    return value


def _get(obj: Any, name: str) -> Any:
    if obj is None:
        return None
    value = getattr(obj, name, None)
    if value is None and isinstance(obj, Mapping):
        return obj.get(name)
    return value
