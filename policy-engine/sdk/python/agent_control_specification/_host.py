# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Host-side helpers for calling Agent Control from synchronous code.

The runtime is stateless: it evaluates a snapshot the caller supplies and
tracks nothing between calls. Two things every host has to do for itself
therefore land here rather than in fifteen separate call sites:

* build the snapshot, including the identifiers and the running counters a
  budget policy reads;
* reach an ``async`` API from a synchronous framework callback.

The second one is cheaper than it looks. :meth:`RuntimeClient.evaluate_
intervention_point` is ``async`` but the native binding underneath it is
synchronous, so a synchronous caller only needs the loop that the async
surface asks for.

Nothing here interprets policy. Every method returns the runtime's own
:class:`InterventionPointResult`, so callers read ``result.verdict.decision``
and not a parallel set of verdict types.
"""

from __future__ import annotations

import asyncio
import math
import threading
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any, Awaitable, Protocol, runtime_checkable

from ._types import (
    AgentControlBlocked,
    AgentControlSuspended,
    Decision,
    EnforcementMode,
    InterventionPoint,

    InterventionPointResult,
    JsonValue,
)

_COUNTER_NAMES = ("tool_call_count", "token_count", "elapsed_seconds", "cost_usd")

def run_sync(coro: Awaitable[Any], *, timeout: float | None = None) -> Any:
    """Run an awaitable to completion from synchronous code.

    Synchronous framework callbacks routinely run inside an async host, so a
    loop is often already spinning on this thread. Driving that loop from
    inside itself would deadlock, so the coroutine goes to a worker thread with
    its own loop. With no loop running, it runs inline.
    """
    if timeout is None:
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coro)  # type: ignore[arg-type]

    outcome: dict[str, Any] = {}

    def _runner() -> None:
        try:
            outcome["value"] = asyncio.run(coro)  # type: ignore[arg-type]
        except BaseException as exc:  # noqa: BLE001 - re-raised on the caller
            outcome["error"] = exc

    thread = threading.Thread(target=_runner, name="acs-host-session", daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        # CPython cannot interrupt a resolver blocked in synchronous code. The
        # thread is a daemon, so it dies with the process; the caller must not
        # wait on it.
        raise TimeoutError("timed out waiting for the approval resolver")
    if "error" in outcome:
        raise outcome["error"]
    return outcome.get("value")

DEFAULT_APPROVAL_TIMEOUT_SECONDS = 300.0
"""Bound on the approval wait when neither the caller nor the manifest sets one.

An unbounded wait is a fail-open: CPython cannot interrupt a resolver blocked
in synchronous code, so a hung approval would hold the calling agent forever
instead of denying.

A manifest that declares ``approval.timeout_seconds`` (SPECIFICATION §24)
replaces this default through :attr:`AgentControl.approval_config`. An
explicit ``approval_timeout_seconds`` argument wins over both.
"""


def _manifest_approval_timeout(control: Any) -> float | None:
    """Return the control manifest's ``approval.timeout_seconds``, if declared.

    The native runtime validates the field as a positive integer, so
    anything else can only come from a custom control and is ignored.
    """
    approval = getattr(control, "approval_config", None)
    if not isinstance(approval, Mapping):
        return None
    timeout = approval.get("timeout_seconds")
    if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0:
        return None
    return float(timeout)


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

def _check_counter(name: str, value: Any) -> None:
    if name in ("tool_call_count", "token_count"):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"{name} must be a non-negative integer, got {value!r}")
        return
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
    ):
        raise ValueError(f"{name} must be a non-negative, finite number, got {value!r}")

@dataclass
class SnapshotBuilder:
    """Per-session snapshot source owned by the host.

    Holds the identifiers that stay fixed for a session and the counters that
    move as the agent runs. Counter mutators are additive, so
    ``record_tokens(100)`` adds a hundred rather than setting it.

    A budget policy reads these counters out of the snapshot. Whether to keep
    them at all is the host's decision: a host with no budget rules can ignore
    the mutators entirely.
    """

    agent_id: str
    session_id: str = "session-1"
    tenant_id: str | None = None
    agent_name: str | None = None
    agent_version: str = "1.0.0"
    session_started_at: str | None = None
    tool_call_count: int = 0
    token_count: int = 0
    elapsed_seconds: float = 0.0
    cost_usd: float = 0.0
    trace_id: str | None = None
    span_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.agent_id, str) or not self.agent_id:
            raise ValueError("agent_id must be a non-empty string")
        if not isinstance(self.session_id, str) or not self.session_id:
            raise ValueError("session_id must be a non-empty string")
        for name in _COUNTER_NAMES:
            _check_counter(name, getattr(self, name))
        if self.session_started_at is None:
            self.session_started_at = _utcnow_iso()

    def record_tool_call(self, count: int = 1) -> None:
        """Add ``count`` completed tool calls to the running total."""
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError(f"count must be a non-negative integer, got {count!r}")
        self.tool_call_count += count

    def record_tokens(self, tokens: int) -> None:
        """Add ``tokens`` to the running token total."""
        if isinstance(tokens, bool) or not isinstance(tokens, int) or tokens < 0:
            raise ValueError(f"tokens must be a non-negative integer, got {tokens!r}")
        self.token_count += tokens

    def record_cost(self, usd: float) -> None:
        """Add ``usd`` to the running cost total."""
        _check_counter("cost_usd", usd)
        self.cost_usd += float(usd)

    def record_elapsed(self, seconds: float) -> None:
        """Add ``seconds`` to the running elapsed total."""
        _check_counter("elapsed_seconds", seconds)
        self.elapsed_seconds += float(seconds)

    def release_tool_call(self, count: int = 1) -> None:
        """Give back ``count`` reservations for tool calls that did not go ahead."""
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise ValueError(f"count must be a non-negative integer, got {count!r}")
        if count > self.tool_call_count:
            raise ValueError(f"cannot release {count} tool calls; only {self.tool_call_count} recorded")
        self.tool_call_count -= count

    def reset_counters(self) -> None:
        """Zero the four counters."""
        self.tool_call_count = 0
        self.token_count = 0
        self.elapsed_seconds = 0.0
        self.cost_usd = 0.0

    def envelope(self, intervention_point: str) -> dict[str, Any]:
        """Return the identity and counter block for one evaluation."""
        for name in _COUNTER_NAMES:
            _check_counter(name, getattr(self, name))
        timestamp = _utcnow_iso()
        envelope: dict[str, Any] = {
            "agent": {
                "id": self.agent_id,
                "version": self.agent_version,
                "name": self.agent_name or self.agent_id,
            },
            "session": {
                "id": self.session_id,
                "started_at": self.session_started_at or timestamp,
            },
            "intervention_point": intervention_point,
            "timestamp": timestamp,
            "budgets": {
                "tool_call_count": self.tool_call_count,
                "token_count": self.token_count,
                "elapsed_seconds": self.elapsed_seconds,
                "cost_usd": self.cost_usd,
            },
        }
        if self.tenant_id:
            envelope["tenant"] = {"id": self.tenant_id, "name": self.tenant_id}
        trace = {}
        if self.trace_id:
            trace["trace_id"] = self.trace_id
        if self.span_id:
            trace["span_id"] = self.span_id
        if trace:
            envelope["trace"] = trace
        return envelope

    def snapshot(
        self, intervention_point: str, **body: JsonValue
    ) -> dict[str, Any]:
        """Return a full snapshot: the envelope plus whatever the hook carries."""
        return self.build_snapshot(intervention_point, body)

    def build_snapshot(
        self, intervention_point: str, body: Mapping[str, JsonValue]
    ) -> dict[str, Any]:
        """Like :meth:`snapshot`, with the hook body as a mapping so any key is allowed."""
        snapshot: dict[str, Any] = dict(body)
        # The envelope carries host-asserted identity, session and budget
        # counters that policies trust. Write it last so no hook body can
        # replace it and forge an identity or reset a budget.
        snapshot["envelope"] = self.envelope(intervention_point)
        return snapshot

@runtime_checkable
class SnapshotSource(Protocol):
    """Builds the snapshot for each evaluation and owns the budget counters.

    :class:`SnapshotBuilder` is the host-side implementation. The tool
    adapters and :meth:`AgentControl.run_tool` accept one in place of a frozen
    mapping so that ``tool_call_count`` advances between calls: they reserve a
    slot with ``record_tool_call`` before a call is evaluated and give it back
    with ``release_tool_call`` when the call does not go ahead. Hosts call
    neither for calls the SDK governs.
    """

    def build_snapshot(
        self, intervention_point: str, body: Mapping[str, JsonValue]
    ) -> dict[str, Any]: ...

    def record_tool_call(self, count: int = 1) -> None: ...

    def release_tool_call(self, count: int = 1) -> None: ...


class _AmbientSnapshotSource:
    """A view over a source that folds fixed ambient data into every snapshot."""

    def __init__(self, source: SnapshotSource, ambient: Mapping[str, JsonValue]) -> None:
        self._source = source
        self._ambient = dict(ambient)

    def build_snapshot(
        self, intervention_point: str, body: Mapping[str, JsonValue]
    ) -> dict[str, Any]:
        return self._source.build_snapshot(intervention_point, {**self._ambient, **body})

    def record_tool_call(self, count: int = 1) -> None:
        self._source.record_tool_call(count)

    def release_tool_call(self, count: int = 1) -> None:
        self._source.release_tool_call(count)


def merge_snapshot(
    default: Mapping[str, JsonValue] | SnapshotSource | None,
    per_call: Mapping[str, JsonValue] | None,
) -> dict[str, JsonValue] | SnapshotSource:
    """Layer per-call ambient data over a default mapping or snapshot source."""
    if isinstance(default, SnapshotSource):
        return default if not per_call else _AmbientSnapshotSource(default, per_call)
    return {**dict(default or {}), **dict(per_call or {})}


def _with_decision(
    result: InterventionPointResult, decision: Decision, reason: str | None
) -> InterventionPointResult:
    """Return the result with its decision rewritten, leaving the rest intact."""
    return replace(
        result, verdict=replace(result.verdict, decision=decision, reason=reason)
    )


class HostSession:
    """Synchronous session over :class:`AgentControl` for one agent run.

    Binds a control to a :class:`SnapshotBuilder` so a host evaluates a hook
    in one call instead of assembling a snapshot by hand each time::

        control = AgentControl.from_path("policies/manifest.yaml")
        session = HostSession(control, agent_id="support-bot")
        result = session.pre_tool_call(tool_name="lookup", args={"q": "x"})
        if result.verdict.decision is Decision.DENY:
            raise PermissionError(result.verdict.reason)

    Counters advance only when the host says so, through ``record_*`` on
    :attr:`builder`, because only the host knows whether a call completed.
    The exception is a tool call governed through the SDK: when
    :attr:`builder` is handed to a tool adapter or to ``run_tool``, the SDK
    counts that call itself, so do not also call ``record_tool_call`` for it.
    """

    def __init__(
        self,
        control: Any,
        *,
        agent_id: str = "agent",
        session_id: str = "session-1",
        builder: SnapshotBuilder | None = None,
        mode: EnforcementMode | str = EnforcementMode.ENFORCE,
        approval_timeout_seconds: float | None = None,
        approval_on_timeout: str = "deny",
    ) -> None:
        self._control = control
        self._mode = EnforcementMode(mode)
        if approval_timeout_seconds is None:
            approval_timeout_seconds = _manifest_approval_timeout(control)
        if approval_timeout_seconds is None:
            approval_timeout_seconds = DEFAULT_APPROVAL_TIMEOUT_SECONDS
        # The core accepts any u64, but a float past this bound makes
        # ``Thread.join`` raise OverflowError instead of waiting.
        self._approval_timeout_seconds = min(
            float(approval_timeout_seconds), threading.TIMEOUT_MAX
        )
        self._approval_on_timeout = approval_on_timeout
        self.builder = builder or SnapshotBuilder(
            agent_id=agent_id, session_id=session_id
        )

    @property
    def control(self) -> Any:
        """The underlying control this session evaluates against."""
        return self._control

    def evaluate(
        self, intervention_point: InterventionPoint | str, **body: JsonValue
    ) -> InterventionPointResult:
        """Evaluate one intervention point with the session's current counters."""
        name = (
            intervention_point.value
            if isinstance(intervention_point, InterventionPoint)
            else str(intervention_point)
        )
        snapshot = self.builder.snapshot(name, **body)
        result = run_sync(
            self._control.evaluate_intervention_point(
                intervention_point, snapshot, self._mode
            )
        )
        if (
            self._mode is EnforcementMode.ENFORCE
            and result.verdict.decision is Decision.DENY
            and result.verdict.approval is not None
        ):
            return self._resolve_escalation(intervention_point, result)
        return result

    def _resolve_escalation(
        self, intervention_point: InterventionPoint | str, result: InterventionPointResult
    ) -> InterventionPointResult:
        """Run the control's approval path and fold the outcome into the verdict.

        An approved escalation becomes an allow, a refused one a deny, and a
        suspended one stays escalated so the host can resume it later. A
        resolver that raises fails closed.
        """
        try:
            run_sync(
                self._control.enforce(intervention_point, result, self._mode),
                timeout=self._approval_timeout_seconds,
            )
        except TimeoutError:
            if self._approval_on_timeout == "allow":
                return _with_decision(result, Decision.ALLOW, "approval_timeout")
            return _with_decision(
                result, Decision.DENY, "host_error:approval_unresolved"
            )
        except AgentControlSuspended:
            return result
        except AgentControlBlocked as blocked:
            # The blocking result already carries a classified reason, either
            # the policy's own or a reserved host_error the enforcement layer
            # synthesized. Overwriting it with a name of our own destroyed
            # that and invented a reason outside the closed set.
            blocked_verdict = blocked.result.verdict
            message = blocked_verdict.message
            if message is None:
                message = result.verdict.message
            return _with_decision(
                replace(result, verdict=replace(result.verdict, message=message)),
                Decision.DENY,
                blocked_verdict.reason,
            )
        except Exception:  # noqa: BLE001 - a broken resolver must not permit
            return _with_decision(
                result, Decision.DENY, "host_error:approval_resolver_failed"
            )
        return _with_decision(result, Decision.ALLOW, result.verdict.reason)

    def agent_startup(self, agent: JsonValue | None = None) -> InterventionPointResult:
        return self.evaluate(InterventionPoint.AGENT_STARTUP, agent=agent or {})

    def input(self, body: JsonValue) -> InterventionPointResult:
        return self.evaluate(InterventionPoint.INPUT, input={"body": body})

    def pre_model_call(self, request: JsonValue) -> InterventionPointResult:
        # The whole request rides under ``model_request``, the key the snapshot
        # contract and the framework adapters use, so one manifest binds
        # ``$snap.model_request`` through either seam. Provider shapes
        # differ (Anthropic ``system``, Gemini ``contents``), so nothing is
        # folded or dropped on the way.
        return self.evaluate(InterventionPoint.PRE_MODEL_CALL, model_request=request)

    def post_model_call(self, response: JsonValue) -> InterventionPointResult:
        return self.evaluate(InterventionPoint.POST_MODEL_CALL, model_response=response)

    def pre_tool_call(
        self,
        *,
        tool_name: str,
        args: JsonValue,
        call_id: str | None = None,
    ) -> InterventionPointResult:
        return self.evaluate(
            InterventionPoint.PRE_TOOL_CALL,
            tool_call={"name": tool_name, "args": args, "id": call_id or "call-1"},
        )

    def post_tool_call(
        self,
        *,
        tool_name: str,
        args: JsonValue,
        result: JsonValue,
        call_id: str | None = None,
    ) -> InterventionPointResult:
        return self.evaluate(
            InterventionPoint.POST_TOOL_CALL,
            tool_call={"name": tool_name, "args": args, "id": call_id or "call-1"},
            # Same envelope the adapters emit, so ``$.tool_result.value`` resolves
            # whichever seam the host went through.
            tool_result={"value": result, "error": None, "duration_ms": None},
        )

    def output(self, content: JsonValue) -> InterventionPointResult:
        return self.evaluate(InterventionPoint.OUTPUT, output=content)

    def agent_shutdown(self, summary: JsonValue | None = None) -> InterventionPointResult:
        return self.evaluate(InterventionPoint.AGENT_SHUTDOWN, summary=summary or {})

__all__ = ["HostSession", "SnapshotBuilder", "run_sync"]
