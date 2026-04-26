# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for kill switch."""

from datetime import datetime

from hypervisor.security.kill_switch import (
    HandoffStatus,
    KillReason,
    KillResult,
    KillSwitch,
    StepHandoff,
)


class TestKillReason:
    def test_enum_values(self):
        assert KillReason.BEHAVIORAL_DRIFT == "behavioral_drift"
        assert KillReason.RATE_LIMIT == "rate_limit"
        assert KillReason.RING_BREACH == "ring_breach"
        assert KillReason.MANUAL == "manual"
        assert KillReason.QUARANTINE_TIMEOUT == "quarantine_timeout"
        assert KillReason.SESSION_TIMEOUT == "session_timeout"

    def test_enum_count(self):
        assert len(KillReason) == 6

    def test_is_str_enum(self):
        assert isinstance(KillReason.MANUAL, str)


class TestHandoffStatus:
    def test_enum_values(self):
        assert HandoffStatus.PENDING == "pending"
        assert HandoffStatus.HANDED_OFF == "handed_off"
        assert HandoffStatus.FAILED == "failed"
        assert HandoffStatus.COMPENSATED == "compensated"

    def test_enum_count(self):
        assert len(HandoffStatus) == 4


class TestStepHandoff:
    def test_defaults(self):
        handoff = StepHandoff(
            step_id="step-1", saga_id="saga-1", from_agent="agent-1"
        )
        assert handoff.to_agent is None
        assert handoff.status == HandoffStatus.COMPENSATED


class TestKillResult:
    def test_defaults(self):
        result = KillResult()
        assert result.kill_id.startswith("kill:")
        assert result.agent_did == ""
        assert result.reason == KillReason.MANUAL
        assert isinstance(result.timestamp, datetime)
        assert result.handoffs == []
        assert result.handoff_success_count == 0
        assert result.compensation_triggered is False
        assert result.details == ""

    def test_unique_kill_ids(self):
        r1 = KillResult()
        r2 = KillResult()
        assert r1.kill_id != r2.kill_id


class TestKillSwitch:
    def test_init(self):
        ks = KillSwitch()
        assert ks.total_kills == 0
        assert ks.total_handoffs == 0
        assert ks.kill_history == []

    def test_kill_basic(self):
        ks = KillSwitch()
        result = ks.kill(
            agent_did="agent-1",
            session_id="sess-1",
            reason=KillReason.MANUAL,
        )
        assert result.agent_did == "agent-1"
        assert result.session_id == "sess-1"
        assert result.reason == KillReason.MANUAL
        assert result.handoffs == []
        assert result.compensation_triggered is False
        assert ks.total_kills == 1

    def test_kill_with_in_flight_steps(self):
        ks = KillSwitch()
        steps = [
            {"step_id": "s1", "saga_id": "saga-1"},
            {"step_id": "s2", "saga_id": "saga-1"},
        ]
        result = ks.kill(
            agent_did="agent-1",
            session_id="sess-1",
            reason=KillReason.RING_BREACH,
            in_flight_steps=steps,
            details="breach detected",
        )
        assert len(result.handoffs) == 2
        assert all(h.status == HandoffStatus.COMPENSATED for h in result.handoffs)
        assert result.compensation_triggered is True
        assert result.handoff_success_count == 0
        assert result.details == "breach detected"

    def test_kill_with_various_reasons(self):
        ks = KillSwitch()
        for reason in KillReason:
            result = ks.kill("a1", "s1", reason)
            assert result.reason == reason

    def test_kill_history_returns_copy(self):
        ks = KillSwitch()
        ks.kill("a1", "s1", KillReason.MANUAL)
        history = ks.kill_history
        assert len(history) == 1
        assert history is not ks._kill_history

    def test_total_handoffs_always_zero(self):
        """Public preview: handoffs not supported."""
        ks = KillSwitch()
        ks.kill("a1", "s1", KillReason.MANUAL, in_flight_steps=[{"step_id": "s", "saga_id": "x"}])
        assert ks.total_handoffs == 0

    def test_register_and_unregister_substitute(self):
        ks = KillSwitch()
        ks.register_substitute("sess-1", "agent-sub")
        assert "agent-sub" in ks._substitutes["sess-1"]
        ks.unregister_substitute("sess-1", "agent-sub")
        assert "agent-sub" not in ks._substitutes["sess-1"]

    def test_unregister_nonexistent_substitute(self):
        ks = KillSwitch()
        # Should not raise
        ks.unregister_substitute("sess-1", "nonexistent")

    def test_kill_unregisters_agent_substitute(self):
        ks = KillSwitch()
        ks.register_substitute("sess-1", "agent-1")
        ks.kill("agent-1", "sess-1", KillReason.MANUAL)
        assert "agent-1" not in ks._substitutes.get("sess-1", [])

    def test_find_substitute_returns_registered(self):
        """Substitute lookup returns a registered agent."""
        ks = KillSwitch()
        ks.register_substitute("s1", "backup-agent")
        assert ks._find_substitute("s1", "agent-1") == "backup-agent"

    def test_find_substitute_excludes_killed_agent(self):
        ks = KillSwitch()
        ks.register_substitute("s1", "agent-1")
        assert ks._find_substitute("s1", "agent-1") is None

    def test_find_substitute_no_session(self):
        ks = KillSwitch()
        assert ks._find_substitute("s1", "agent-1") is None

    def test_session_timeout_reason(self):
        ks = KillSwitch()
        result = ks.kill("a1", "s1", KillReason.SESSION_TIMEOUT)
        assert result.reason == KillReason.SESSION_TIMEOUT
        assert ks.total_kills == 1

    # ── Agent process registry ─────────────────────────────────────

    def test_register_and_unregister_agent(self):
        ks = KillSwitch()
        ks.register_agent("agent-1", lambda: None)
        assert "agent-1" in ks._agents
        ks.unregister_agent("agent-1")
        assert "agent-1" not in ks._agents

    def test_unregister_nonexistent_agent(self):
        ks = KillSwitch()
        ks.unregister_agent("nonexistent")  # Should not raise

    def test_kill_unregisters_agent(self):
        ks = KillSwitch()
        ks.register_agent("agent-1", lambda: None)
        ks.kill("agent-1", "sess-1", KillReason.MANUAL)
        assert "agent-1" not in ks._agents

    # ── Termination callback ───────────────────────────────────────

    def test_kill_with_registered_callback_terminates(self):
        """Registered termination callback is called and terminated=True."""
        ks = KillSwitch()
        terminated_agents: list[str] = []
        ks.register_agent("agent-1", lambda: terminated_agents.append("agent-1"))
        result = ks.kill("agent-1", "sess-1", KillReason.MANUAL)
        assert result.terminated is True
        assert "agent-1" in terminated_agents

    def test_kill_without_registered_callback(self):
        """Kill without registered callback sets terminated=False."""
        ks = KillSwitch()
        result = ks.kill("agent-1", "sess-1", KillReason.MANUAL)
        assert result.terminated is False

    # ── Handoff vs compensation ────────────────────────────────────

    def test_kill_with_substitute_hands_off_steps(self):
        """Steps are handed off to substitute when available."""
        ks = KillSwitch()
        ks.register_substitute("sess-1", "backup-agent")
        steps = [
            {"step_id": "s1", "saga_id": "saga-1"},
            {"step_id": "s2", "saga_id": "saga-1"},
        ]
        result = ks.kill(
            "agent-1", "sess-1", KillReason.RING_BREACH, in_flight_steps=steps
        )
        assert result.handoff_success_count == 2
        assert all(h.status == HandoffStatus.HANDED_OFF for h in result.handoffs)
        assert all(h.to_agent == "backup-agent" for h in result.handoffs)
        assert result.compensation_triggered is False

    def test_kill_without_substitute_compensates_steps(self):
        """Steps are compensated when no substitute is available."""
        ks = KillSwitch()
        steps = [{"step_id": "s1", "saga_id": "saga-1"}]
        result = ks.kill("agent-1", "sess-1", KillReason.MANUAL, in_flight_steps=steps)
        assert result.handoff_success_count == 0
        assert all(h.status == HandoffStatus.COMPENSATED for h in result.handoffs)
        assert result.compensation_triggered is True

    def test_total_handoffs_counts_successes(self):
        """total_handoffs sums handoff_success_count across kills."""
        ks = KillSwitch()
        ks.register_substitute("s1", "backup")
        ks.kill("a1", "s1", KillReason.MANUAL, [{"step_id": "s1", "saga_id": "sg1"}])
        assert ks.total_handoffs == 1
