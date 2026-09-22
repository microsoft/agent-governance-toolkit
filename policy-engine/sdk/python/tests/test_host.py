# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the synchronous host helpers."""

from __future__ import annotations

import asyncio
import pickle

import pytest

from agent_control_specification import (
    DEFAULT_APPROVAL_TIMEOUT_SECONDS,
    AgentControl,
    AgentControlBlocked,
    AgentControlSuspended,
    Decision,
    InterventionPoint,
    HostSession,
    InterventionPointResult,
    SnapshotBuilder,
    Verdict,
    guard_tool,
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


def test_session_matches_the_adapter_envelopes() -> None:
    """One manifest has to bind paths that work through either seam.

    The framework adapters and the snapshot contract carry the model request
    under ``model_request``, the response under ``model_response`` and the
    final response under ``output``, with ``tool_result`` as a mapping. If
    HostSession named those differently, a policy target that resolved for
    one caller would fail closed with a missing-path error for the other.
    """
    control = _RecordingControl()
    session = HostSession(control, agent_id="bot")

    session.post_tool_call(tool_name="t", args={}, result="ok")
    session.pre_model_call({"messages": [{"role": "user"}], "model": {"name": "m"}})
    session.post_model_call({"content": "hi"})
    session.output("done")

    _point, post_tool_snapshot, _mode = control.calls[0]
    assert post_tool_snapshot["tool_result"]["value"] == "ok"

    _point, pre_model_snapshot, _mode = control.calls[1]
    assert pre_model_snapshot["model_request"] == {"messages": [{"role": "user"}], "model": {"name": "m"}}
    assert "messages" not in pre_model_snapshot and "model" not in pre_model_snapshot

    _point, post_model_snapshot, _mode = control.calls[2]
    assert post_model_snapshot["model_response"] == {"content": "hi"}

    _point, output_snapshot, _mode = control.calls[3]
    assert output_snapshot["output"] == "done"
    assert "response" not in output_snapshot


def test_a_hook_body_cannot_replace_the_envelope() -> None:
    """The envelope is host-asserted; policies trust it for identity and budgets.

    If a body key could overwrite it, any caller passing an ``envelope`` field
    would forge its own identity and reset the counters behind max_tool_calls
    and max_tokens.
    """
    control = _RecordingControl()
    session = HostSession(control, agent_id="bot", session_id="sess")
    session.builder.record_tool_call(7)

    session.evaluate("input", envelope={"budgets": {"tool_call_count": 0}})
    session.pre_model_call(
        {"messages": [], "envelope": {"agent": {"id": "ATTACKER"}}}
    )

    for _point, snapshot, _mode in control.calls:
        assert snapshot["envelope"]["agent"]["id"] == "bot"
        assert snapshot["envelope"]["budgets"]["tool_call_count"] == 7


def test_pre_model_call_accepts_any_json_body() -> None:
    """The signature advertises JsonValue, so no body may raise."""
    control = _RecordingControl()
    session = HostSession(control, agent_id="bot")

    for body in (
        {"intervention_point": "input", "messages": []},
        {"self": 1, "messages": []},
        {1: "x"},
        "a bare string",
        [{"role": "user"}],
    ):
        session.pre_model_call(body)

    assert len(control.calls) == 5


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
    verdict=Verdict(decision=Decision.DENY, reason="needs-approval", approval={})
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
            verdict=Verdict(
                decision=Decision.DENY,
                reason="needs-approval",
                approval={},
            )
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
    # The blocking result's own reason survives rather than being replaced by
    # a name outside the reserved set.
    assert result.verdict.reason == _ESCALATED.verdict.reason


def test_escalation_blocked_keeps_the_blocking_message() -> None:
    """A resolver's refusal reason reaches the session caller on the verdict message."""
    blocked = InterventionPointResult(
        Verdict(Decision.DENY, reason="needs-approval", message="ticket CR-42 was rejected", approval={})
    )
    result = _escalating_session(AgentControlBlocked(InterventionPoint.INPUT, blocked)).input("x")

    assert result.verdict.decision is Decision.DENY
    assert result.verdict.reason == "needs-approval"
    assert result.verdict.message == "ticket CR-42 was rejected"


def test_escalation_blocked_without_a_message_keeps_the_policy_message() -> None:
    """A synthesized block with no message must not erase the policy's own."""
    blocked = InterventionPointResult(Verdict(Decision.DENY, reason="host_error:approval_identity_mismatch"))

    class _MessagedEscalatingControl(_EscalatingControl):
        async def evaluate_intervention_point(self, intervention_point, snapshot, mode):
            return InterventionPointResult(
                Verdict(Decision.DENY, reason="needs-approval", message="manager sign-off required", approval={})
            )

    result = HostSession(_MessagedEscalatingControl(AgentControlBlocked(InterventionPoint.INPUT, blocked))).input("x")

    assert result.verdict.decision is Decision.DENY
    assert result.verdict.reason == "host_error:approval_identity_mismatch"
    assert result.verdict.message == "manager sign-off required"


def test_escalation_suspended_stays_liftable_for_later_resume() -> None:
    """A suspended approval retains its liftable deny for later resume."""
    result = _escalating_session(AgentControlSuspended(InterventionPoint.INPUT, _ESCALATED)).input("x")

    assert result.verdict.decision is Decision.DENY
    assert result.verdict.approval == {}
    assert result.verdict.reason == "needs-approval"


def test_interruptions_survive_pickling() -> None:
    """Blocked and suspended errors cross process boundaries intact."""
    blocked = pickle.loads(pickle.dumps(AgentControlBlocked(InterventionPoint.INPUT, _ESCALATED)))
    assert isinstance(blocked, AgentControlBlocked)
    assert blocked.intervention_point is InterventionPoint.INPUT
    assert blocked.result == _ESCALATED
    assert str(blocked) == str(AgentControlBlocked(InterventionPoint.INPUT, _ESCALATED))

    suspended = pickle.loads(
        pickle.dumps(AgentControlSuspended(InterventionPoint.INPUT, _ESCALATED, handle={"ticket": "7"}))
    )
    assert isinstance(suspended, AgentControlSuspended)
    assert suspended.intervention_point is InterventionPoint.INPUT
    assert suspended.result == _ESCALATED
    assert suspended.handle == {"ticket": "7"}


def test_escalation_with_a_broken_resolver_fails_closed() -> None:
    """A resolver that raises anything else denies rather than permitting."""
    result = _escalating_session(RuntimeError("resolver exploded")).input("x")

    assert result.verdict.decision is Decision.DENY
    assert result.verdict.reason == "host_error:approval_resolver_failed"


def test_escalation_timeout_denies_by_default() -> None:
    """A timed-out approval denies unless the host opted into allowing."""
    result = _escalating_session(TimeoutError()).input("x")

    assert result.verdict.decision is Decision.DENY
    assert result.verdict.reason == "host_error:approval_unresolved"


def test_escalation_timeout_allows_only_when_configured() -> None:
    """approval_on_timeout='allow' is the one path a timeout may permit."""
    session = _escalating_session(TimeoutError(), approval_on_timeout="allow")

    result = session.input("x")

    assert result.verdict.decision is Decision.ALLOW
    assert result.verdict.reason == "approval_timeout"


def test_escalation_is_not_resolved_in_evaluate_only_mode() -> None:
    """evaluate_only reports the liftable deny instead of running approval."""
    control = _EscalatingControl()
    session = HostSession(control, mode="evaluate_only")

    result = session.input("x")

    assert result.verdict.decision is Decision.DENY
    assert result.verdict.approval == {}
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


class _ManifestControl(_EscalatingControl):
    """An escalating control whose manifest declares an ``approval`` section."""

    def __init__(self, approval, on_enforce: BaseException | None = None) -> None:
        super().__init__(on_enforce)
        self.approval_config = approval


def test_manifest_timeout_replaces_the_default() -> None:
    """``approval.timeout_seconds`` from the manifest bounds the wait."""
    session = HostSession(_ManifestControl({"timeout_seconds": 42, "on_timeout": "deny"}))

    assert session._approval_timeout_seconds == 42.0


def test_explicit_timeout_overrides_the_manifest() -> None:
    """A caller-supplied timeout still wins over the manifest's."""
    session = HostSession(_ManifestControl({"timeout_seconds": 42}), approval_timeout_seconds=3)

    assert session._approval_timeout_seconds == 3


@pytest.mark.parametrize(
    "approval",
    [
        {},
        {"default_resolver": "webhook"},
        {"timeout_seconds": "soon"},
        {"timeout_seconds": True},
        {"timeout_seconds": 0},
        {"timeout_seconds": -1},
        "not-a-mapping",
    ],
)
def test_manifest_without_a_usable_timeout_keeps_the_default(approval) -> None:
    """A manifest that declares no usable timeout leaves the default in place."""
    session = HostSession(_ManifestControl(approval))

    assert session._approval_timeout_seconds == DEFAULT_APPROVAL_TIMEOUT_SECONDS


@pytest.mark.parametrize("path", ["manifest", "argument"])
def test_oversized_timeout_is_clamped_to_what_join_accepts(path) -> None:
    """A u64 the core accepts must not turn every escalation into OverflowError."""
    import threading

    huge = 2**64 - 1
    if path == "manifest":
        session = HostSession(_ManifestControl({"timeout_seconds": huge}))
    else:
        session = HostSession(_ManifestControl({}), approval_timeout_seconds=huge)

    assert session._approval_timeout_seconds == threading.TIMEOUT_MAX


def test_manifest_timeout_bounds_a_hung_resolver() -> None:
    """The manifest bound is enforced, not just recorded."""
    import time

    class _HangingManifestControl(_ManifestControl):
        async def enforce(self, intervention_point, result, mode):
            time.sleep(30)
            return result

    started = time.monotonic()
    result = HostSession(_HangingManifestControl({"timeout_seconds": 1})).input("x")
    elapsed = time.monotonic() - started

    assert elapsed < 5
    assert result.verdict.decision is Decision.DENY
    assert result.verdict.reason == "host_error:approval_unresolved"


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
    assert result.verdict.reason == "host_error:approval_unresolved"


class _BudgetControl:
    """Denies pre_tool_call once the envelope's tool_call_count reaches the cap."""

    def __init__(self, cap: int) -> None:
        self.cap = cap
        self.snapshots: list[tuple[str, dict]] = []

    async def evaluate_intervention_point(self, request):
        # Yield like the native runtime does (run_in_executor), so concurrent
        # calls interleave here rather than running to completion in turn.
        await asyncio.sleep(0)
        point = request.intervention_point.value
        self.snapshots.append((point, dict(request.snapshot)))
        count = request.snapshot["envelope"]["budgets"]["tool_call_count"]
        if point == "pre_tool_call" and count >= self.cap:
            return InterventionPointResult(Verdict(Decision.DENY, reason="budget:max_tool_calls"))
        return InterventionPointResult(Verdict(Decision.ALLOW))


def _counts(control: _BudgetControl, point: str) -> list[int]:
    return [s["envelope"]["budgets"]["tool_call_count"] for p, s in control.snapshots if p == point]


def test_guard_tool_advances_the_tool_call_count_from_a_builder() -> None:
    runtime = _BudgetControl(cap=2)
    builder = SnapshotBuilder(agent_id="bot", session_id="s1")
    guarded = guard_tool(AgentControl(runtime), "lookup", lambda args: {"ok": args}, snapshot=builder)

    assert run_sync(guarded({"n": 1})) == {"ok": {"n": 1}}
    assert run_sync(guarded({"n": 2})) == {"ok": {"n": 2}}
    with pytest.raises(AgentControlBlocked) as blocked:
        run_sync(guarded({"n": 3}))

    assert blocked.value.result.verdict.reason == "budget:max_tool_calls"
    # The policy deciding call N reads the count as of N-1; the post check of
    # call N sees N; the denied third call left the counter alone.
    assert _counts(runtime, "pre_tool_call") == [0, 1, 2]
    assert _counts(runtime, "post_tool_call") == [1, 2]
    assert builder.tool_call_count == 2


def test_guard_tool_with_a_frozen_mapping_never_advances() -> None:
    """A plain mapping keeps today's behaviour: the host owns the counter."""
    runtime = _BudgetControl(cap=2)
    snapshot = SnapshotBuilder(agent_id="bot", session_id="s1").snapshot("pre_tool_call")
    guarded = guard_tool(AgentControl(runtime), "lookup", lambda args: args, snapshot=snapshot)

    for n in range(3):
        run_sync(guarded({"n": n}))

    assert _counts(runtime, "pre_tool_call") == [0, 0, 0]


def test_per_call_ambient_data_layers_over_a_builder_but_not_its_envelope() -> None:
    runtime = _BudgetControl(cap=10)
    builder = SnapshotBuilder(agent_id="bot", session_id="s1")
    guarded = guard_tool(AgentControl(runtime), "lookup", lambda args: args, snapshot=builder)

    run_sync(
        guarded(
            {},
            agent_control_snapshot={"turn": "t1", "envelope": "spoofed", "intervention_point": "also fine"},
        )
    )

    _point, snapshot = runtime.snapshots[0]
    assert snapshot["turn"] == "t1"
    assert snapshot["intervention_point"] == "also fine"
    assert snapshot["envelope"]["agent"]["id"] == "bot"
    assert snapshot["envelope"]["budgets"]["tool_call_count"] == 0


def test_concurrent_tool_calls_share_one_budget() -> None:
    """Five parallel calls at cap 2: two go ahead and the counter ends at 2.

    The slot is reserved before the first await, so each call's pre-check
    reads the earlier reservations instead of one stale count; the three
    denied calls give their reservations back.
    """
    runtime = _BudgetControl(cap=2)
    builder = SnapshotBuilder(agent_id="bot", session_id="s1")
    guarded = guard_tool(AgentControl(runtime), "lookup", lambda args: args, snapshot=builder)

    async def fan_out():
        return await asyncio.gather(*(guarded({"n": n}) for n in range(5)), return_exceptions=True)

    outcomes = asyncio.run(fan_out())

    assert sum(not isinstance(o, BaseException) for o in outcomes) == 2
    assert sum(isinstance(o, AgentControlBlocked) for o in outcomes) == 3
    assert builder.tool_call_count == 2
    assert sorted(_counts(runtime, "pre_tool_call")) == [0, 1, 2, 3, 4]


def test_a_denied_pre_check_gives_the_reservation_back() -> None:
    runtime = _BudgetControl(cap=0)
    builder = SnapshotBuilder(agent_id="bot", session_id="s1")
    guarded = guard_tool(AgentControl(runtime), "lookup", lambda args: args, snapshot=builder)

    with pytest.raises(AgentControlBlocked):
        run_sync(guarded({}))

    assert builder.tool_call_count == 0
    with pytest.raises(ValueError):
        builder.release_tool_call()


def test_run_tool_and_protect_tool_accept_a_builder() -> None:
    runtime = _BudgetControl(cap=10)
    control = AgentControl(runtime)
    builder = SnapshotBuilder(agent_id="bot", session_id="s1")

    run_sync(control.run_tool("t", {"a": 1}, lambda args: args, snapshot=builder))
    protected = control.protect_tool("t", lambda args: args, snapshot=builder)
    run_sync(protected({"a": 2}, snapshot={"turn": "t2"}))

    assert builder.tool_call_count == 2
    assert _counts(runtime, "pre_tool_call") == [0, 1]
    assert runtime.snapshots[-1][1]["turn"] == "t2"
