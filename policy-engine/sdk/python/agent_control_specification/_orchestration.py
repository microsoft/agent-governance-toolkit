from __future__ import annotations

import copy
import inspect
import logging
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from contextlib import asynccontextmanager

from ._client import AnnotatorDispatcher, NativeRuntimeClient, PolicyDispatcher, RuntimeClient
from ._telemetry import TelemetryEvent, TelemetrySink, _coerce_sink
from ._types import (
    AgentControlBlocked,
    AgentControlInterruption,
    AgentControlSuspended,
    ApprovalOutcome,
    ApprovalResolution,
    ApprovalResolver,
    Decision,
    EnforcementMode,
    JsonValue,
    RunResult,
    InterventionPoint,
    InterventionPointRequest,
    InterventionPointResult,
    ToolRunResult,
    Verdict,
    action_identity,
)

Execute = Callable[[JsonValue], JsonValue | Awaitable[JsonValue]]

_TELEMETRY_LOGGER = logging.getLogger("agent_control_specification.telemetry")


class AgentControl:
    """Host-owned async orchestration around a stateless runtime client."""

    def __init__(
        self,
        runtime_client: RuntimeClient,
        *,
        approval_resolver: ApprovalResolver | None = None,
        telemetry_sink: TelemetrySink | Sequence[TelemetrySink] | None = None,
    ):
        self._runtime_client = runtime_client
        self._approval_resolver = approval_resolver
        # A list/tuple of sinks is fanned out via MultiSink; a non-sink raises
        # TypeError here rather than silently dropping every event later.
        self._telemetry_sink = _coerce_sink(telemetry_sink)
        # Maps of intervention-point value to its manifest policy id and sorted
        # configured annotator names, resolved from the runtime client's merged
        # manifest (see NativeRuntimeClient.policy_labels). Populated for every
        # native-backed constructor, including from_url and from_manifest_chain.
        # Empty for a custom RuntimeClient that does not expose policy_labels, in
        # which case policy_id is None and annotators fall back to the executed
        # annotation keys on the result.
        self._policy_id_index, self._annotator_index = _labels_from_client(runtime_client)

    @classmethod
    def from_native(
        cls,
        manifest: Mapping[str, JsonValue] | str | bytes,
        annotator_dispatcher: AnnotatorDispatcher | None = None,
        policy_dispatcher: PolicyDispatcher | None = None,
        *,
        approval_resolver: ApprovalResolver | None = None,
        perf_telemetry: int = 0,
        telemetry_sink: TelemetrySink | Sequence[TelemetrySink] | None = None,
    ) -> "AgentControl":
        return cls(
            NativeRuntimeClient(
                manifest,
                annotator_dispatcher,
                policy_dispatcher,
                perf_telemetry,
            ),
            approval_resolver=approval_resolver,
            telemetry_sink=telemetry_sink,
        )

    @classmethod
    def from_path(
        cls,
        path: str,
        annotator_dispatcher: AnnotatorDispatcher | None = None,
        policy_dispatcher: PolicyDispatcher | None = None,
        *,
        approval_resolver: ApprovalResolver | None = None,
        perf_telemetry: int = 0,
        telemetry_sink: TelemetrySink | Sequence[TelemetrySink] | None = None,
    ) -> "AgentControl":
        return cls(
            NativeRuntimeClient.from_path(path, annotator_dispatcher, policy_dispatcher, perf_telemetry),
            approval_resolver=approval_resolver,
            telemetry_sink=telemetry_sink,
        )

    @classmethod
    def from_url(
        cls,
        url: str,
        sha256: str | None = None,
        annotator_dispatcher: AnnotatorDispatcher | None = None,
        policy_dispatcher: PolicyDispatcher | None = None,
        *,
        approval_resolver: ApprovalResolver | None = None,
        perf_telemetry: int = 0,
        max_url_bytes: int | None = None,
        url_timeout_ms: int | None = None,
        max_url_redirects: int | None = None,
        telemetry_sink: TelemetrySink | Sequence[TelemetrySink] | None = None,
    ) -> "AgentControl":
        return cls(
            NativeRuntimeClient.from_url(
                url,
                sha256,
                annotator_dispatcher,
                policy_dispatcher,
                perf_telemetry,
                max_url_bytes=max_url_bytes,
                url_timeout_ms=url_timeout_ms,
                max_url_redirects=max_url_redirects,
            ),
            approval_resolver=approval_resolver,
            telemetry_sink=telemetry_sink,
        )

    @classmethod
    def from_manifest_chain(
        cls,
        manifests: list[str],
        annotator_dispatcher: AnnotatorDispatcher | None = None,
        policy_dispatcher: PolicyDispatcher | None = None,
        *,
        approval_resolver: ApprovalResolver | None = None,
        perf_telemetry: int = 0,
        telemetry_sink: TelemetrySink | Sequence[TelemetrySink] | None = None,
    ) -> "AgentControl":
        return cls(
            NativeRuntimeClient.from_manifest_chain(manifests, annotator_dispatcher, policy_dispatcher, perf_telemetry),
            approval_resolver=approval_resolver,
            telemetry_sink=telemetry_sink,
        )

    async def evaluate_intervention_point(
        self,
        intervention_point: InterventionPoint | str,
        snapshot: Mapping[str, JsonValue],
        mode: EnforcementMode | str = EnforcementMode.ENFORCE,
    ) -> InterventionPointResult:
        try:
            normalized_intervention_point: InterventionPoint | str = InterventionPoint(intervention_point)
        except ValueError:
            normalized_intervention_point = str(intervention_point)
        sink = self._telemetry_sink
        started_at = time.perf_counter() if sink is not None else 0.0
        try:
            normalized_mode = EnforcementMode(mode)
            normalized_snapshot = dict(snapshot)
        except (TypeError, ValueError):
            result = _request_invalid_result()
            self._emit_telemetry(normalized_intervention_point, None, result, started_at)
            return result
        request = InterventionPointRequest(
            intervention_point=normalized_intervention_point,
            snapshot=normalized_snapshot,
            mode=normalized_mode,
        )
        result = await self._runtime_client.evaluate_intervention_point(request)
        self._emit_telemetry(normalized_intervention_point, normalized_mode, result, started_at)
        return result

    def _emit_telemetry(
        self,
        intervention_point: InterventionPoint | str,
        mode: EnforcementMode | None,
        result: InterventionPointResult,
        started_at: float,
    ) -> None:
        """Build and emit one redaction-safe telemetry event for an evaluation.

        Telemetry is never load-bearing. A sink that raises is caught, logged,
        and swallowed so it can never change the verdict or fail the evaluation.
        When no sink is configured this returns immediately, so the default
        (``telemetry_sink=None``) path costs only this attribute check.
        """

        sink = self._telemetry_sink
        if sink is None:
            return
        duration_ms = (time.perf_counter() - started_at) * 1000.0
        point_key = (
            intervention_point.value
            if isinstance(intervention_point, InterventionPoint)
            else str(intervention_point)
        )
        try:
            event = TelemetryEvent.from_result(
                intervention_point,
                mode,
                result,
                duration_ms,
                policy_id=self._policy_id_index.get(point_key),
                annotators=self._annotator_index.get(point_key),
            )
            sink.emit(event)
        except Exception:  # noqa: BLE001 - telemetry must never break enforcement
            _TELEMETRY_LOGGER.warning(
                "Telemetry sink %r raised while building or emitting a %s event; verdict is unaffected.",
                type(sink).__name__,
                point_key,
                exc_info=True,
            )

    async def run(
        self,
        input_value: JsonValue,
        execute: Execute,
        *,
        snapshot: Mapping[str, JsonValue] | None = None,
        mode: EnforcementMode | str = EnforcementMode.ENFORCE,
        approval_resolver: ApprovalResolver | None = None,
    ) -> RunResult:
        enforcement_mode = EnforcementMode(mode)
        ambient = dict(snapshot or {})

        input_result = await self.evaluate_intervention_point(
            InterventionPoint.INPUT,
            {**ambient, "input": input_value},
            enforcement_mode,
        )
        await self.enforce(
            InterventionPoint.INPUT, input_result, enforcement_mode, approval_resolver=approval_resolver
        )
        effective_input = _transformed_or(input_result, input_value, enforcement_mode)

        output = await _maybe_await(execute(effective_input))

        final_result = await self.evaluate_intervention_point(
            InterventionPoint.OUTPUT,
            {**ambient, "input": effective_input, "output": output},
            enforcement_mode,
        )
        await self.enforce(
            InterventionPoint.OUTPUT, final_result, enforcement_mode, approval_resolver=approval_resolver
        )
        return RunResult(
            value=_transformed_or(final_result, output, enforcement_mode),
            input_result=input_result,
            output_result=final_result,
        )

    def protect_tool(
        self,
        tool_name: str,
        execute: Execute,
        *,
        mode: EnforcementMode | str = EnforcementMode.ENFORCE,
        snapshot: Mapping[str, JsonValue] | None = None,
        approval_resolver: ApprovalResolver | None = None,
    ) -> Callable[..., Awaitable[ToolRunResult]]:
        default_snapshot = dict(snapshot or {})

        async def guarded_tool(
            args: JsonValue,
            *,
            tool_call_id: str | None = None,
            snapshot: Mapping[str, JsonValue] | None = None,
        ) -> ToolRunResult:
            merged_snapshot = {**default_snapshot, **dict(snapshot or {})}
            return await self.run_tool(
                tool_name,
                args,
                execute,
                tool_call_id=tool_call_id,
                snapshot=merged_snapshot,
                mode=mode,
                approval_resolver=approval_resolver,
            )

        return guarded_tool

    async def run_tool(
        self,
        tool_name: str,
        args: JsonValue,
        execute: Execute,
        *,
        tool_call_id: str | None = None,
        snapshot: Mapping[str, JsonValue] | None = None,
        mode: EnforcementMode | str = EnforcementMode.ENFORCE,
        approval_resolver: ApprovalResolver | None = None,
    ) -> ToolRunResult:
        enforcement_mode = EnforcementMode(mode)
        ambient = dict(snapshot or {})
        normalized_tool_call_id = _normalize_tool_call_id(tool_call_id)
        tool_call = _tool_call(tool_name, args, normalized_tool_call_id)

        pre_result = await self.evaluate_intervention_point(
            InterventionPoint.PRE_TOOL_CALL,
            {**ambient, "tool_call": tool_call},
            enforcement_mode,
        )
        await self.enforce(
            InterventionPoint.PRE_TOOL_CALL, pre_result, enforcement_mode, approval_resolver=approval_resolver
        )
        effective_args = _transformed_or(pre_result, args, enforcement_mode)

        tool_result = await _maybe_await(execute(effective_args))
        post_result = await self.evaluate_intervention_point(
            InterventionPoint.POST_TOOL_CALL,
            {
                **ambient,
                "tool_call": _tool_call(tool_name, effective_args, normalized_tool_call_id),
                "tool_result": tool_result,
            },
            enforcement_mode,
        )
        await self.enforce(
            InterventionPoint.POST_TOOL_CALL, post_result, enforcement_mode, approval_resolver=approval_resolver
        )
        return ToolRunResult(
            value=_transformed_or(post_result, tool_result, enforcement_mode),
            pre_tool_call_result=pre_result,
            post_tool_call_result=post_result,
        )

    async def enforce(
        self,
        intervention_point: InterventionPoint,
        result: InterventionPointResult,
        mode: EnforcementMode,
        *,
        approval_resolver: ApprovalResolver | None = None,
    ) -> None:
        """Apply enforcement for one intervention-point result.

        In ``enforce`` mode a ``deny`` raises :class:`AgentControlBlocked`, and an
        ``escalate`` is routed to the effective approval resolver (the per-call
        resolver if given, otherwise the instance resolver). With no resolver an
        ``escalate`` fails closed as a block. ``allow`` and ``warn`` proceed. In
        ``evaluate_only`` mode nothing is enforced and the resolver is never called.
        """

        if mode != EnforcementMode.ENFORCE:
            return
        decision = result.verdict.decision
        if decision == Decision.DENY:
            raise AgentControlBlocked(intervention_point, result)
        if decision != Decision.ESCALATE:
            return

        resolver = approval_resolver if approval_resolver is not None else self._approval_resolver
        if resolver is None:
            raise AgentControlBlocked(intervention_point, result)

        original_identity = result.action_identity
        try:
            resolution = await _maybe_await(resolver(intervention_point, result))
        except AgentControlInterruption:
            raise
        except Exception as exc:  # noqa: BLE001 - a failing resolver must fail closed
            raise AgentControlBlocked(intervention_point, _approval_resolver_failed_result(result)) from exc
        if isinstance(resolution, ApprovalOutcome):
            resolution = ApprovalResolution(resolution, action_identity=original_identity)
        if not isinstance(resolution, ApprovalResolution):
            raise AgentControlBlocked(intervention_point, _approval_resolver_failed_result(result))
        if resolution.outcome == ApprovalOutcome.ALLOW:
            _require_approved_identity(intervention_point, result, original_identity, resolution.action_identity)
            return
        if resolution.outcome == ApprovalOutcome.SUSPEND:
            _require_approved_identity(intervention_point, result, original_identity, resolution.action_identity)
            raise AgentControlSuspended(intervention_point, result, resolution.handle)
        raise AgentControlBlocked(intervention_point, result)

    async def agent_startup(
        self,
        agent: JsonValue,
        *,
        snapshot: Mapping[str, JsonValue] | None = None,
        mode: EnforcementMode | str = EnforcementMode.ENFORCE,
        approval_resolver: ApprovalResolver | None = None,
    ) -> InterventionPointResult:
        """Evaluate and enforce the ``agent_startup`` lifecycle point.

        ``agent`` is the agent-metadata policy target (e.g. ``{"name": ...}``).
        A ``deny`` raises :class:`AgentControlBlocked`; the result is returned so
        callers can inspect the verdict or any transformed metadata.
        """

        enforcement_mode = EnforcementMode(mode)
        ambient = dict(snapshot or {})
        result = await self.evaluate_intervention_point(
            InterventionPoint.AGENT_STARTUP, {**ambient, "agent": agent}, enforcement_mode
        )
        await self.enforce(
            InterventionPoint.AGENT_STARTUP, result, enforcement_mode, approval_resolver=approval_resolver
        )
        return result

    async def agent_shutdown(
        self,
        summary: JsonValue,
        *,
        snapshot: Mapping[str, JsonValue] | None = None,
        mode: EnforcementMode | str = EnforcementMode.ENFORCE,
        approval_resolver: ApprovalResolver | None = None,
    ) -> InterventionPointResult:
        """Evaluate and enforce the ``agent_shutdown`` lifecycle point.

        ``summary`` is the shutdown-summary policy target. A ``deny`` raises
        :class:`AgentControlBlocked`; the result is returned for inspection.
        """

        enforcement_mode = EnforcementMode(mode)
        ambient = dict(snapshot or {})
        result = await self.evaluate_intervention_point(
            InterventionPoint.AGENT_SHUTDOWN, {**ambient, "summary": summary}, enforcement_mode
        )
        await self.enforce(
            InterventionPoint.AGENT_SHUTDOWN, result, enforcement_mode, approval_resolver=approval_resolver
        )
        return result

    @asynccontextmanager
    async def guard_session(
        self,
        agent: JsonValue,
        *,
        snapshot: Mapping[str, JsonValue] | None = None,
        mode: EnforcementMode | str = EnforcementMode.ENFORCE,
        approval_resolver: ApprovalResolver | None = None,
    ) -> AsyncIterator["GuardedSession"]:
        """Framework-agnostic session seam covering the lifecycle points.

        Enforces ``agent_startup`` on entry and ``agent_shutdown`` on a clean
        exit, giving any host one-line lifecycle coverage regardless of which
        framework (if any) it uses::

            async with control.guard_session({"name": "support-bot"}) as session:
                ...                       # run the agent
                session.summary = {...}   # optional shutdown-audit target

        A ``deny`` at either point raises :class:`AgentControlBlocked`. Shutdown
        enforcement is skipped when the body raises, so an in-session error is
        never masked by the shutdown verdict.
        """

        enforcement_mode = EnforcementMode(mode)
        ambient = dict(snapshot or {})
        await self.agent_startup(
            agent, snapshot=ambient, mode=enforcement_mode, approval_resolver=approval_resolver
        )
        session = GuardedSession()
        body_raised = False
        try:
            yield session
        except BaseException:
            body_raised = True
            raise
        finally:
            if not body_raised:
                await self.agent_shutdown(
                    session.summary,
                    snapshot=ambient,
                    mode=enforcement_mode,
                    approval_resolver=approval_resolver,
                )


class GuardedSession:
    """Mutable handle yielded by :meth:`AgentControl.guard_session`.

    Set :attr:`summary` to the shutdown-audit policy target before the session
    block exits; it defaults to an empty mapping.
    """

    __slots__ = ("summary",)

    def __init__(self) -> None:
        self.summary: JsonValue = {}


def _require_approved_identity(
    intervention_point: InterventionPoint,
    result: InterventionPointResult,
    original_identity: str | None,
    approved_identity: str | None,
) -> None:
    current_identity = action_identity(result.policy_input) if result.policy_input is not None else None
    if (
        original_identity is not None
        and current_identity is not None
        and approved_identity is not None
        and original_identity == current_identity == approved_identity
    ):
        return
    raise AgentControlBlocked(intervention_point, _approval_action_mismatch_result())


def _approval_action_mismatch_result() -> InterventionPointResult:
    return InterventionPointResult(
        Verdict(Decision.DENY, reason="runtime_error:approval_action_mismatch"),
    )


def _approval_resolver_failed_result(result: InterventionPointResult) -> InterventionPointResult:
    return InterventionPointResult(
        Verdict(
            Decision.DENY,
            reason="runtime_error:approval_resolver_failed",
            message="Approval resolver failed closed.",
        ),
        policy_input=result.policy_input,
        input_identity=result.input_identity,
        enforced_identity=result.enforced_identity,
    )


def _request_invalid_result() -> InterventionPointResult:
    return InterventionPointResult(
        Verdict(
            Decision.DENY,
            reason="runtime_error:request_invalid",
            message="Request blocked by Agent Control Specification.",
        ),
    )


async def _maybe_await(value: JsonValue | Awaitable[JsonValue]) -> JsonValue:
    if inspect.isawaitable(value):
        return await value
    return value


def _transformed_or(
    result: InterventionPointResult, fallback: JsonValue, mode: EnforcementMode
) -> JsonValue:
    """Return the engine's transformed policy target when the verdict was
    ``Decision.TRANSFORM`` in enforce mode, otherwise the fallback.

    Per AGT D1 only ``Decision.TRANSFORM`` is allowed to mutate the policy
    target. The previous implementation gated on ``applies_effects`` which
    also returned True for ``allow``, ``warn``, and ``escalate``; under AGT
    those decisions never produce a transformed_policy_target, so the gate
    is moved to the canonical ``applies_transform`` predicate. An explicit
    ``transformed_policy_target_applied`` flag preserves upstream support for
    a transform whose replacement value is JSON null.
    """

    if mode != EnforcementMode.ENFORCE:
        return fallback
    if not result.verdict.decision.applies_transform:
        return fallback
    if result.transformed_policy_target_applied or result.transformed_policy_target is not None:
        transformed = result.transformed_policy_target
        return _splice_nested_policy_target(result, fallback, transformed)
    return fallback


def _splice_nested_policy_target(
    result: InterventionPointResult,
    fallback: JsonValue,
    transformed: JsonValue,
) -> JsonValue:
    path = _policy_target_path(result)
    relative = _relative_snapshot_path(path)
    if relative is None:
        return transformed
    if not relative:
        return transformed
    cloned = copy.deepcopy(fallback)
    return cloned if _set_relative_json_path(cloned, relative, transformed) else transformed


def _policy_target_path(result: InterventionPointResult) -> str | None:
    policy_input = result.policy_input
    if not isinstance(policy_input, Mapping):
        return None
    policy_target = policy_input.get("policy_target")
    if not isinstance(policy_target, Mapping):
        return None
    path = policy_target.get("path")
    return path if isinstance(path, str) else None


def _relative_snapshot_path(path: str | None) -> str | None:
    if path is None:
        return None
    if path.startswith("$."):
        rest = path[2:]
    elif path.startswith("$snap."):
        rest = path[6:]
    else:
        return None
    first_segment_end = len(rest)
    for delimiter in (".", "["):
        index = rest.find(delimiter)
        if index != -1:
            first_segment_end = min(first_segment_end, index)
    if first_segment_end == len(rest):
        return ""
    return rest[first_segment_end:]


def _set_relative_json_path(root: JsonValue, path: str, value: JsonValue) -> bool:
    segments = _relative_path_segments(path)
    if not segments:
        return False
    current = root
    for segment in segments[:-1]:
        match segment:
            case str():
                if not isinstance(current, Mapping) or segment not in current:
                    return False
                current = current[segment]
            case int():
                if not isinstance(current, list) or segment < 0 or segment >= len(current):
                    return False
                current = current[segment]
            case _:
                return False

    last = segments[-1]
    if isinstance(last, str) and isinstance(current, dict) and last in current:
        current[last] = value
        return True
    if isinstance(last, int) and isinstance(current, list) and 0 <= last < len(current):
        current[last] = value
        return True
    return False


def _relative_path_segments(path: str) -> list[str | int]:
    segments: list[str | int] = []
    index = 0
    while index < len(path):
        if path[index] == ".":
            index += 1
            start = index
            while index < len(path) and path[index] not in ".[":
                index += 1
            if start == index:
                return []
            segments.append(path[start:index])
        elif path[index] == "[":
            end = path.find("]", index)
            if end == -1:
                return []
            try:
                segments.append(int(path[index + 1:end]))
            except ValueError:
                return []
            index = end + 1
        else:
            return []
    return segments


def _normalize_tool_call_id(tool_call_id: str | None) -> str | None:
    if tool_call_id is None:
        return None
    if not isinstance(tool_call_id, str):
        raise TypeError("tool_call_id must be a string.")
    if tool_call_id == "":
        raise ValueError("tool_call_id must be a non-empty string when provided.")
    return tool_call_id


def _tool_call(tool_name: str, args: JsonValue, tool_call_id: str | None) -> dict[str, JsonValue]:
    tool_call: dict[str, JsonValue] = {"name": tool_name, "args": args}
    if tool_call_id is not None:
        tool_call["id"] = tool_call_id
    return tool_call


def _labels_from_client(
    runtime_client: RuntimeClient,
) -> tuple[dict[str, str], dict[str, tuple[str, ...]]]:
    """Build the policy-id and annotator indexes from a runtime client.

    Reads the client's ``policy_labels`` map, which the native client sources
    from the merged manifest, so the labels are populated on every native-backed
    constructor including ``from_url`` and ``from_manifest_chain`` and for
    ``extends``-inherited bindings. A client that does not expose
    ``policy_labels`` (a custom or pure-Python test client) yields empty indexes,
    so ``policy_id`` is ``None`` and annotators fall back to the executed
    annotation keys on the result. Never raises, since telemetry labels are best
    effort and must not block construction.
    """

    policy_ids: dict[str, str] = {}
    annotators: dict[str, tuple[str, ...]] = {}
    try:
        getter = getattr(runtime_client, "policy_labels", None)
        if not callable(getter):
            return policy_ids, annotators
        labels = getter()
    except Exception:  # noqa: BLE001 - label lookup must never break construction
        return policy_ids, annotators
    if not isinstance(labels, Mapping):
        return policy_ids, annotators
    for point, entry in labels.items():
        if not isinstance(entry, Mapping):
            continue
        point_key = point.value if isinstance(point, InterventionPoint) else str(point)
        policy_id = entry.get("policy_id")
        if isinstance(policy_id, str):
            policy_ids[point_key] = policy_id
        names = entry.get("annotators")
        if isinstance(names, Sequence) and not isinstance(names, (str, bytes)):
            sorted_names = tuple(sorted(str(name) for name in names))
            if sorted_names:
                annotators[point_key] = sorted_names
    return policy_ids, annotators
