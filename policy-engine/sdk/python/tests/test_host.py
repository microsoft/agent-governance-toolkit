# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the synchronous host helpers."""

from __future__ import annotations

import asyncio

import pytest

from agent_control_specification import (
    DEFAULT_APPROVAL_TIMEOUT_SECONDS,
    AgentControlBlocked,
    AgentControlSuspended,
    Decision,
    InterventionPoint,
    HostSession,
    InterventionPointResult,
    SnapshotBuilder,
    Verdict,
    run_sync,
)


class _RecordingControl:
    """Captures what the session sends instead of running the engine."""

    def __init__(self) -> None:
        self.calls: list[tuple[object, dict, object]] = []

    async def evaluate_intervention_point(self, intervention_point, snapshot, mode):
        self.calls.append((intervention_point, dict(snapshot), mode))
        return InterventionPointResult(verdict=Verdict(decision=Decision.ALLOW))


def test_envelope_carries_identity_and_counters() -> None:
    builder = SnapshotBuilder(agent_id="bot", session_id="s-42", tenant_id="acme")
    builder.record_tool_call(2)
    builder.record_tokens(120)
    builder.record_cost(0.5)
    builder.record_elapsed(1.5)

    envelope = builder.snapshot("input")["envelope"]

    assert envelope["agent"]["id"] == "bot"
    assert envelope["session"]["id"] == "s-42"
    assert envelope["tenant"]["id"] == "acme"
    assert envelope["intervention_point"] == "input"
    assert envelope["budgets"] == {
        "tool_call_count": 2,
        "token_count": 120,
        "elapsed_seconds": 1.5,
        "cost_usd": 0.5,
    }


def test_counters_are_additive_and_resettable() -> None:
    builder = SnapshotBuilder(agent_id="bot")
    builder.record_tool_call()
    builder.record_tool_call()
    assert builder.tool_call_count == 2

    builder.reset_counters()
    assert builder.tool_call_count == 0
    assert builder.cost_usd == 0.0


def test_snapshot_body_rides_alongside_the_envelope() -> None:
    builder = SnapshotBuilder(agent_id="bot")

    snapshot = builder.snapshot("pre_tool_call", tool_call={"name": "lookup"})

    assert snapshot["tool_call"] == {"name": "lookup"}
    assert "envelope" in snapshot


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("tool_call_count", -1),
        ("tool_call_count", True),
        ("token_count", 1.5),
        ("cost_usd", float("inf")),
        ("elapsed_seconds", -0.1),
    ],
)
def test_out_of_range_counters_are_refused(field: str, value: object) -> None:
    with pytest.raises(ValueError):
        SnapshotBuilder(agent_id="bot", **{field: value})  # type: ignore[arg-type]


def test_empty_identifiers_are_refused() -> None:
    with pytest.raises(ValueError):
        SnapshotBuilder(agent_id="")
    with pytest.raises(ValueError):
        SnapshotBuilder(agent_id="bot", session_id="")


def test_session_sends_the_tool_call_and_the_current_counters() -> None:
    control = _RecordingControl()
    session = HostSession(control, agent_id="bot")
    session.builder.record_tool_call(3)

    session.pre_tool_call(tool_name="lookup", args={"q": "x"}, call_id="c1")

    intervention_point, snapshot, _mode = control.calls[0]
    assert intervention_point.value == "pre_tool_call"
    assert snapshot["tool_call"] == {"name": "lookup", "args": {"q": "x"}, "id": "c1"}
    assert snapshot["envelope"]["budgets"]["tool_call_count"] == 3


def test_session_covers_every_intervention_point() -> None:
    control = _RecordingControl()
    session = HostSession(control, agent_id="bot")

    session.agent_startup({"name": "bot"})
    session.input("hello")
    session.pre_model_call({"messages": []})
    session.post_model_call({"content": "hi"})
    session.pre_tool_call(tool_name="t", args={})
    session.post_tool_call(tool_name="t", args={}, result="ok")
    session.output("done")
    session.agent_shutdown({"turns": 1})

    assert [call[0].value for call in control.calls] == [
        "agent_startup",
        "input",
        "pre_model_call",
        "post_model_call",
        "pre_tool_call",
        "post_tool_call",
        "output",
        "agent_shutdown",
    ]


def test_counters_only_move_when_the_host_says_so() -> None:
    control = _RecordingControl()
    session = HostSession(control, agent_id="bot")

    session.pre_tool_call(tool_name="t", args={})
    session.pre_tool_call(tool_name="t", args={})

    for _, snapshot, _mode in control.calls:
        assert snapshot["envelope"]["budgets"]["tool_call_count"] == 0


def test_run_sync_works_inside_a_running_loop() -> None:
    """A sync callback inside an async host must not deadlock."""

    async def outer() -> str:
        async def inner() -> str:
            return "value"

        return run_sync(inner())

    assert asyncio.run(outer()) == "value"


def test_run_sync_propagates_the_error_from_a_running_loop() -> None:
    async def outer() -> None:
        async def inner() -> str:
            raise ValueError("boom")

        with pytest.raises(ValueError, match="boom"):
            run_sync(inner())

    asyncio.run(outer())


def test_run_sync_returns_the_awaited_value() -> None:
    async def coro() -> str:
        return "value"

    assert run_sync(coro()) == "value"


_ESCALATED = InterventionPointResult(
    verdict=Verdict(decision=Decision.ESCALATE, reason="needs-approval")
)


class _EscalatingControl:
    """Returns an escalate verdict, then fails ``enforce`` as configured.

    ``enforce`` is where the session resolves an escalation, so each test
    picks the outcome by giving this control the exception the real approval
    path would raise.
    """

    def __init__(self, on_enforce: BaseException | None = None) -> None:
        self.on_enforce = on_enforce
        self.enforced: list[object] = []

    async def evaluate_intervention_point(self, intervention_point, snapshot, mode):
        return InterventionPointResult(
            verdict=Verdict(decision=Decision.ESCALATE, reason="needs-approval")
        )

    async def enforce(self, intervention_point, result, mode):
        self.enforced.append(intervention_point)
        if self.on_enforce is not None:
            raise self.on_enforce
        return result


def _escalating_session(exc: BaseException | None = None, **kwargs) -> HostSession:
    return HostSession(_EscalatingControl(exc), **kwargs)


def test_escalation_approved_becomes_allow_keeping_its_reason() -> None:
    """An approval that returns cleanly folds the escalation into an allow."""
    result = _escalating_session().input("proceed")

    assert result.verdict.decision is Decision.ALLOW
    assert result.verdict.reason == "needs-approval"


def test_escalation_blocked_becomes_deny() -> None:
    """A refused approval folds into a deny the caller can act on."""
    result = _escalating_session(AgentControlBlocked(InterventionPoint.INPUT, _ESCALATED)).input("x")

    assert result.verdict.decision is Decision.DENY
    assert result.verdict.reason == "approval_denied"


def test_escalation_suspended_stays_escalated_for_later_resume() -> None:
    """A suspended approval is left escalated so the host can resume it."""
    result = _escalating_session(AgentControlSuspended(InterventionPoint.INPUT, _ESCALATED)).input("x")

    assert result.verdict.decision is Decision.ESCALATE
    assert result.verdict.reason == "needs-approval"


def test_escalation_with_a_broken_resolver_fails_closed() -> None:
    """A resolver that raises anything else denies rather than permitting."""
    result = _escalating_session(RuntimeError("resolver exploded")).input("x")

    assert result.verdict.decision is Decision.DENY
    assert result.verdict.reason == "approval_failed"


def test_escalation_timeout_denies_by_default() -> None:
    """A timed-out approval denies unless the host opted into allowing."""
    result = _escalating_session(TimeoutError()).input("x")

    assert result.verdict.decision is Decision.DENY
    assert result.verdict.reason == "runtime_error:approval_timeout"


def test_escalation_timeout_allows_only_when_configured() -> None:
    """approval_on_timeout='allow' is the one path a timeout may permit."""
    session = _escalating_session(TimeoutError(), approval_on_timeout="allow")

    result = session.input("x")

    assert result.verdict.decision is Decision.ALLOW
    assert result.verdict.reason == "approval_timeout"


def test_escalation_is_not_resolved_in_evaluate_only_mode() -> None:
    """evaluate_only reports the escalation instead of running approval."""
    control = _EscalatingControl()
    session = HostSession(control, mode="evaluate_only")

    result = session.input("x")

    assert result.verdict.decision is Decision.ESCALATE
    assert control.enforced == []


def test_approval_wait_is_bounded_by_default() -> None:
    """With nothing configured the wait is bounded, not infinite.

    An unbounded join cannot be interrupted, so a hung resolver would hold the
    agent forever instead of denying.
    """
    session = HostSession(_EscalatingControl())

    assert session._approval_timeout_seconds == DEFAULT_APPROVAL_TIMEOUT_SECONDS


def test_explicit_timeout_overrides_the_default() -> None:
    """A caller-supplied timeout wins over the default."""
    session = HostSession(_EscalatingControl(), approval_timeout_seconds=3)

    assert session._approval_timeout_seconds == 3


def test_a_hung_resolver_denies_rather_than_blocking() -> None:
    """The bound is real: a resolver that never returns still yields a deny."""
    import time

    class _HangingControl(_EscalatingControl):
        async def enforce(self, intervention_point, result, mode):
            time.sleep(30)
            return result

    started = time.monotonic()
    result = HostSession(
        _HangingControl(), approval_timeout_seconds=1
    ).input("x")
    elapsed = time.monotonic() - started

    assert elapsed < 5
    assert result.verdict.decision is Decision.DENY
    assert result.verdict.reason == "runtime_error:approval_timeout"
