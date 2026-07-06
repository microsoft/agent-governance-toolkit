# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Unit tests for agt.policies.kernel.KernelBridge.

These exercise the mediator with dependency-injected fakes so the trust / audit
/ ring wiring is verified without importing agentmesh, agent_os or hypervisor.
The runnable example (examples/acs_kernel_wiring) covers the real subsystems.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from agt.policies.kernel import (
    AuditEmissionResult,
    GovernanceEventSpec,
    KernelBridge,
    KernelDecision,
)


class FakeTrust:
    """Minimal TrustTrackerLike: reward +0.1, penalty -0.2, clamp 0..1."""

    def __init__(self, initial: float = 0.5) -> None:
        self._scores: dict[str, float] = {}
        self._initial = initial
        self.calls: list[tuple[str, str, str, bool]] = []

    def get_score(self, agent_id: str) -> float:
        return self._scores.get(agent_id, self._initial)

    def record_interaction(
        self, agent_id: str, peer_id: str, action: str, success: bool
    ) -> float:
        self.calls.append((agent_id, peer_id, action, success))
        current = self.get_score(agent_id)
        delta = 0.1 if success else -0.2
        new = max(0.0, min(1.0, current + delta))
        self._scores[agent_id] = new
        return new


class FakeRing:
    """RingEnforcerLike fake. ``allow_check`` toggles the action gate."""

    def __init__(self, allow_check: bool = True, demote: bool = False) -> None:
        self.allow_check = allow_check
        self.demote = demote
        self.checked: list[tuple] = []

    def compute_ring(self, eff_score, has_consensus=False):
        return 3 if eff_score < 0.6 else 2

    def should_demote(self, current_ring, eff_score) -> bool:
        return self.demote

    def check(self, agent_ring, action, eff_score, has_consensus=False, has_sre_witness=False):
        self.checked.append((agent_ring, action, eff_score))
        reason = "ok" if self.allow_check else "ring insufficient"
        return SimpleNamespace(allowed=self.allow_check, reason=reason)


class FakeClassifier:
    def classify(self, action):
        return SimpleNamespace(ring=1, risk_weight=0.9)


def _ring(value: int) -> SimpleNamespace:
    """A duck-typed ExecutionRing (only ``.value`` is read by the mediator)."""
    return SimpleNamespace(value=value)


class RingByRequirement:
    """RingEnforcerLike that honors the action's required_ring like the real one.

    Allowed when ``agent_ring.value <= required_ring.value`` (lower value = more
    privileged), matching hypervisor RingEnforcer.check semantics.
    """

    def __init__(self) -> None:
        self.checked: list[tuple] = []

    def compute_ring(self, eff_score, has_consensus=False):
        return _ring(3 if eff_score < 0.6 else 2)

    def should_demote(self, current_ring, eff_score) -> bool:
        return False

    def check(self, agent_ring, action, eff_score, has_consensus=False, has_sre_witness=False):
        req = action.required_ring
        req_val = getattr(req, "value", req)
        ag_val = getattr(agent_ring, "value", agent_ring)
        allowed = ag_val <= req_val
        self.checked.append((ag_val, req_val))
        return SimpleNamespace(allowed=allowed, reason="ok" if allowed else "ring insufficient")


class TighteningClassifier:
    """Classifier that reclassifies every action to a stricter ring."""

    def __init__(self, ring_value: int) -> None:
        self._ring = _ring(ring_value)

    def classify(self, action):
        return SimpleNamespace(ring=self._ring, risk_weight=0.9)


def _emitter(result: AuditEmissionResult = AuditEmissionResult.ACCEPTED):
    events: list[GovernanceEventSpec] = []

    def emit(event: GovernanceEventSpec) -> AuditEmissionResult:
        events.append(event)
        return result

    emit.events = events  # type: ignore[attr-defined]
    return emit


def _tool_action(required_ring: int) -> SimpleNamespace:
    """A duck-typed ActionDescriptor with the ring surface check() reads."""
    return SimpleNamespace(name="send_email", action_id="send_email", required_ring=required_ring)


def _bridge(trust=None, emit=None, rings=None, classifier=None) -> KernelBridge:
    return KernelBridge(
        trust_tracker=trust or FakeTrust(),
        emit_event=emit or _emitter(),
        ring_enforcer=rings,
        action_classifier=classifier,
    )


def test_deny_penalizes_trust_emits_violation_and_blocks():
    trust = FakeTrust()
    emit = _emitter()
    bridge = _bridge(trust=trust, emit=emit)

    out = bridge.apply(
        KernelDecision.from_decision("deny", reason="blocked_pattern_input"),
        agent_id="a1",
        peer_id="p1",
    )

    assert out.proceeds is False
    assert out.trust_delta == pytest.approx(-0.2)
    assert trust.get_score("a1") == pytest.approx(0.3)
    assert emit.events[0].kind == "policy_violation"
    assert emit.events[0].severity == "high"
    assert out.blocked_reason == "blocked_pattern_input"


def test_allow_rewards_trust_emits_policy_check_and_proceeds():
    trust = FakeTrust()
    emit = _emitter()
    bridge = _bridge(trust=trust, emit=emit)

    out = bridge.apply(KernelDecision.from_decision("allow"), agent_id="a1")

    assert out.proceeds is True
    assert out.trust_delta == pytest.approx(0.1)
    assert emit.events[0].kind == "policy_check"
    assert out.audit is AuditEmissionResult.ACCEPTED


@pytest.mark.parametrize("decision", ["warn", "transform"])
def test_permitting_but_not_allow_is_trust_neutral(decision):
    trust = FakeTrust()
    bridge = _bridge(trust=trust)

    out = bridge.apply(KernelDecision.from_decision(decision), agent_id="a1")

    assert out.proceeds is True
    assert out.trust_delta == 0.0
    assert trust.calls == []  # no record_interaction for neutral verdicts


def test_escalate_is_neutral_blocks_and_preserves_raw():
    trust = FakeTrust()
    emit = _emitter()
    bridge = _bridge(trust=trust, emit=emit)

    out = bridge.apply(KernelDecision.from_decision("escalate"), agent_id="a1")

    assert out.proceeds is False
    assert out.trust_delta == 0.0
    assert out.raw_decision == "escalate"
    assert emit.events[0].kind == "escalation_requested"


def test_ring_gate_blocks_permitted_decision_when_ring_insufficient():
    rings = FakeRing(allow_check=False)
    out = _bridge(rings=rings).apply(
        KernelDecision.from_decision("allow"),
        agent_id="a1",
        action=_tool_action(required_ring=1),
        current_ring=3,
    )

    assert out.ring_allowed is False
    assert out.proceeds is False  # ACS allow is necessary but not sufficient
    assert out.blocked_reason == "ring insufficient"
    assert rings.checked  # check() actually ran


def test_ring_gate_allows_when_ring_sufficient():
    rings = FakeRing(allow_check=True)
    out = _bridge(rings=rings).apply(
        KernelDecision.from_decision("allow"),
        agent_id="a1",
        action=_tool_action(required_ring=3),
        current_ring=2,
    )
    assert out.ring_allowed is True
    assert out.proceeds is True


def test_strict_audit_failure_blocks_proceed():
    emit = _emitter(AuditEmissionResult.NO_SINK)
    out = _bridge(emit=emit).apply(
        KernelDecision.from_decision("allow"), agent_id="a1", strict_audit=True
    )
    assert out.audit is AuditEmissionResult.NO_SINK
    assert out.proceeds is False
    assert out.blocked_reason == "audit:no_sink"


def test_non_strict_audit_failure_still_proceeds():
    emit = _emitter(AuditEmissionResult.DROPPED)
    out = _bridge(emit=emit).apply(
        KernelDecision.from_decision("allow"), agent_id="a1", strict_audit=False
    )
    assert out.audit is AuditEmissionResult.DROPPED
    assert out.proceeds is True


def test_emitter_returning_non_result_is_failed():
    def bad_emit(event):
        return None

    out = _bridge(emit=bad_emit).apply(
        KernelDecision.from_decision("allow"), agent_id="a1", strict_audit=True
    )
    assert out.audit is AuditEmissionResult.FAILED
    assert out.proceeds is False


def test_emitter_raising_is_failed_not_propagated():
    def boom_emit(event):
        raise RuntimeError("sink down")

    out = _bridge(emit=boom_emit).apply(
        KernelDecision.from_decision("allow"), agent_id="a1", strict_audit=True
    )
    assert out.audit is AuditEmissionResult.FAILED
    assert out.proceeds is False


def test_fail_closed_on_none_decision():
    trust = FakeTrust()
    emit = _emitter()
    out = _bridge(trust=trust, emit=emit).apply(None, agent_id="a1")
    assert out.proceeds is False
    assert out.effective_decision == "deny"
    assert out.trust_delta == pytest.approx(-0.2)
    assert emit.events[0].kind == "policy_violation"


def test_fail_closed_on_unrecognized_decision():
    trust = FakeTrust()
    out = _bridge(trust=trust).apply(
        KernelDecision.from_decision("maybe"), agent_id="a1"
    )
    assert out.proceeds is False
    assert out.effective_decision == "deny"
    assert out.trust_delta == pytest.approx(-0.2)
    assert out.blocked_reason.startswith("fail_closed:unrecognized_decision")


def test_empty_agent_id_raises():
    with pytest.raises(ValueError):
        _bridge().apply(KernelDecision.from_decision("allow"), agent_id="  ")


def test_idempotency_key_prevents_double_apply():
    trust = FakeTrust()
    bridge = _bridge(trust=trust)

    first = bridge.apply(
        KernelDecision.from_decision("deny"), agent_id="a1", idempotency_key="k1"
    )
    second = bridge.apply(
        KernelDecision.from_decision("deny"), agent_id="a1", idempotency_key="k1"
    )

    assert first.trust_delta == pytest.approx(-0.2)
    assert second.trust_delta == 0.0  # retry does not re-penalize
    assert trust.get_score("a1") == pytest.approx(0.3)


def test_penalty_trust_error_fails_closed():
    # On the penalty path trust is a gate input (it drives demotion), so a trust
    # backend error must fail closed.
    class BoomTrust(FakeTrust):
        def record_interaction(self, *a, **k):
            raise RuntimeError("trust backend down")

    out = _bridge(trust=BoomTrust()).apply(
        KernelDecision.from_decision("deny"), agent_id="a1"
    )
    assert out.proceeds is False
    assert out.blocked_reason.startswith("trust_error:")


def test_get_score_error_fails_closed_on_allow():
    # get_score is read before any gate; if the trust backend is unreadable we
    # cannot govern, so even an allow fails closed.
    class UnreadableTrust(FakeTrust):
        def get_score(self, agent_id):
            raise RuntimeError("trust backend unreadable")

    out = _bridge(trust=UnreadableTrust()).apply(
        KernelDecision.from_decision("allow"), agent_id="a1"
    )
    assert out.proceeds is False
    assert out.blocked_reason.startswith("trust_error:")


def test_reward_record_failure_does_not_block_authorized_action():
    # The reward is deferred until the gate passes and is telemetry, not a gate
    # input; a failure to RECORD it must not block an already-authorized action.
    class RewardBoomTrust(FakeTrust):
        def record_interaction(self, agent_id, peer_id, action, success):
            if success:
                raise RuntimeError("reward write failed")
            return super().record_interaction(agent_id, peer_id, action, success)

    out = _bridge(trust=RewardBoomTrust()).apply(
        KernelDecision.from_decision("allow"), agent_id="a1"
    )
    assert out.proceeds is True
    assert out.trust_delta == 0.0


def test_demotion_recomputes_ring_on_penalty():
    rings = FakeRing(allow_check=True, demote=True)
    out = _bridge(rings=rings).apply(
        KernelDecision.from_decision("deny"),
        agent_id="a1",
        action=_tool_action(required_ring=3),
        current_ring=2,
    )
    assert out.demoted is True
    assert out.ring == 3  # compute_ring result for the dropped score


def test_from_evaluation_result_recovers_escalate_from_category():
    result = SimpleNamespace(
        verdict="allow",
        audit_entry={},
        category="HUMAN_APPROVAL",
        reason="approved",
        input_identity="id-in",
        enforced_identity="id-enf",
        transform=None,
        evidence=None,
    )
    decision = KernelDecision.from_evaluation_result(result)
    assert decision.effective_decision == "allow"
    assert decision.raw_decision == "escalate"
    assert decision.was_escalated is True


def test_from_evaluation_result_prefers_audit_entry_raw():
    result = SimpleNamespace(
        verdict="deny",
        audit_entry={"raw_decision": "escalate"},
        category=None,
        reason="",
        input_identity=None,
        enforced_identity=None,
        transform=None,
        evidence=None,
    )
    decision = KernelDecision.from_evaluation_result(result)
    assert decision.raw_decision == "escalate"
    assert decision.effective_decision == "deny"


def test_from_intervention_point_result_preserves_escalate():
    ipr = SimpleNamespace(
        verdict=SimpleNamespace(
            decision=SimpleNamespace(value="escalate"),
            reason="needs approval",
            transform=None,
            evidence=None,
        ),
        input_identity="id-in",
        enforced_identity="id-enf",
    )
    decision = KernelDecision.from_intervention_point_result(ipr)
    assert decision.effective_decision == "escalate"
    assert decision.raw_decision == "escalate"
    assert decision.reason == "needs approval"


# --- Remediation regression tests (deep-review Stage 4) ---------------------


def test_from_evaluation_result_recovers_escalate_from_audit_verdict_key():
    # AgtRuntime writes the raw verdict to audit_entry["verdict"] and the
    # approval outcome to audit_entry["approval_outcome"]; an approved escalate
    # arrives with effective verdict "allow".
    result = SimpleNamespace(
        verdict="allow",
        audit_entry={"verdict": "escalate", "approval_outcome": "allow"},
        category=None,
        reason="approved",
        input_identity=None,
        enforced_identity=None,
        transform=None,
        evidence=None,
    )
    decision = KernelDecision.from_evaluation_result(result)
    assert decision.effective_decision == "allow"
    assert decision.raw_decision == "escalate"
    assert decision.was_escalated is True
    assert decision.approval_outcome == "allow"


def test_approved_escalate_is_trust_neutral_and_audited_as_escalation():
    # effective=allow permits, so it PROCEEDS, but the escalation semantics hold:
    # trust neutral, event escalation_requested. This is the load-bearing use of
    # the preserved raw verdict.
    trust = FakeTrust()
    emit = _emitter()
    out = _bridge(trust=trust, emit=emit).apply(
        KernelDecision.from_decision("allow", raw_decision="escalate"),
        agent_id="a1",
    )
    assert out.proceeds is True
    assert out.trust_delta == 0.0
    assert trust.calls == []  # no reward for an approved escalation
    assert emit.events[0].kind == "escalation_requested"
    assert emit.events[0].attributes["was_escalated"] is True


def test_ring_gate_fails_closed_when_current_ring_missing():
    # Enforcer configured + descriptor action but no agent ring: block, do not skip.
    rings = FakeRing(allow_check=True)
    out = _bridge(rings=rings).apply(
        KernelDecision.from_decision("allow"),
        agent_id="a1",
        action=_tool_action(required_ring=1),
        current_ring=None,
    )
    assert out.ring_allowed is False
    assert out.proceeds is False
    assert out.blocked_reason == "ring_state_missing:current_ring"
    assert rings.checked == []  # check() never reached


def test_ring_check_without_allowed_attr_fails_closed():
    class NoAllowedRing(FakeRing):
        def check(self, agent_ring, action, eff_score, has_consensus=False, has_sre_witness=False):
            return SimpleNamespace(reason="weird")  # no .allowed

    out = _bridge(rings=NoAllowedRing()).apply(
        KernelDecision.from_decision("allow"),
        agent_id="a1",
        action=_tool_action(required_ring=3),
        current_ring=_ring(2),
    )
    assert out.ring_allowed is False
    assert out.proceeds is False


def test_classifier_tightens_required_ring_and_blocks():
    # Action declares a permissive RING_3; classifier reclassifies to RING_1.
    # Agent at RING_2 passes the declared ring but must fail the tightened one.
    rings = RingByRequirement()
    action = _tool_action_v(required_value=3)
    out = _bridge(rings=rings, classifier=TighteningClassifier(ring_value=1)).apply(
        KernelDecision.from_decision("allow"),
        agent_id="a1",
        action=action,
        current_ring=_ring(2),
    )
    assert out.ring_allowed is False
    assert out.proceeds is False
    assert rings.checked == [(2, 1)]  # checked against the tightened requirement


def test_classifier_never_loosens_required_ring():
    # Classifier returns a MORE permissive ring; the declared stricter ring stands.
    rings = RingByRequirement()
    action = _tool_action_v(required_value=1)  # strict
    out = _bridge(rings=rings, classifier=TighteningClassifier(ring_value=3)).apply(
        KernelDecision.from_decision("allow"),
        agent_id="a1",
        action=action,
        current_ring=_ring(2),
    )
    assert out.ring_allowed is False  # 2 > 1, still denied by the declared ring
    assert rings.checked == [(2, 1)]  # never loosened to 3


def test_idempotency_key_is_scoped_per_agent():
    # The same key on a different agent must NOT suppress that agent's penalty.
    trust = FakeTrust()
    bridge = _bridge(trust=trust)
    o1 = bridge.apply(KernelDecision.from_decision("deny"), agent_id="a1", idempotency_key="k")
    o2 = bridge.apply(KernelDecision.from_decision("deny"), agent_id="a2", idempotency_key="k")
    assert o1.trust_delta == pytest.approx(-0.2)
    assert o2.trust_delta == pytest.approx(-0.2)  # a2 not suppressed by a1's key
    assert trust.get_score("a2") == pytest.approx(0.3)


def test_dep_error_event_relabeled_as_violation():
    class UnreadableTrust(FakeTrust):
        def get_score(self, agent_id):
            raise RuntimeError("trust backend unreadable")

    emit = _emitter()
    out = _bridge(trust=UnreadableTrust(), emit=emit).apply(
        KernelDecision.from_decision("allow"), agent_id="a1"
    )
    assert out.proceeds is False
    ev = emit.events[0]
    # The audit record must reflect the block, not a benign policy_check/info.
    assert ev.kind == "policy_violation"
    assert ev.severity == "high"


def test_ring_denied_event_relabeled_as_violation():
    emit = _emitter()
    out = _bridge(rings=FakeRing(allow_check=False), emit=emit).apply(
        KernelDecision.from_decision("allow"),
        agent_id="a1",
        action=_tool_action(required_ring=1),
        current_ring=3,
    )
    assert out.proceeds is False
    assert emit.events[0].kind == "policy_violation"
    assert emit.events[0].severity == "high"


def _tool_action_v(required_value: int) -> SimpleNamespace:
    """Descriptor whose required_ring carries a ``.value`` (like ExecutionRing)."""
    return SimpleNamespace(
        name="send_email", action_id="send_email", required_ring=_ring(required_value)
    )


def test_blocked_allow_does_not_reward_trust():
    # An ACS allow that the ring gate blocks must NOT be recorded as a trust
    # success (the deferred-reward fix). No record_interaction, no delta.
    trust = FakeTrust()
    out = _bridge(trust=trust, rings=FakeRing(allow_check=False)).apply(
        KernelDecision.from_decision("allow"),
        agent_id="a1",
        action=_tool_action(required_ring=1),
        current_ring=3,
    )
    assert out.proceeds is False
    assert out.trust_delta == 0.0
    assert trust.get_score("a1") == pytest.approx(0.5)  # unchanged
    assert trust.calls == []  # no success recorded for a blocked action


def test_audit_blocked_allow_does_not_reward_trust():
    # Same principle for a strict-audit block: no reward for a non-proceeding action.
    trust = FakeTrust()
    out = _bridge(trust=trust, emit=_emitter(AuditEmissionResult.NO_SINK)).apply(
        KernelDecision.from_decision("allow"), agent_id="a1", strict_audit=True
    )
    assert out.proceeds is False
    assert out.trust_delta == 0.0
    assert trust.calls == []


def test_tool_intervention_point_deny_emits_tool_call_blocked():
    emit = _emitter()
    out = _bridge(emit=emit).apply(
        KernelDecision(
            effective_decision="deny",
            raw_decision="deny",
            reason="blocked",
            intervention_point="pre_tool_call",
        ),
        agent_id="a1",
    )
    assert out.proceeds is False
    assert emit.events[0].kind == "tool_call_blocked"


def test_non_tool_deny_stays_policy_violation():
    emit = _emitter()
    _bridge(emit=emit).apply(
        KernelDecision(
            effective_decision="deny",
            raw_decision="deny",
            reason="blocked",
            intervention_point="input",
        ),
        agent_id="a1",
    )
    assert emit.events[0].kind == "policy_violation"


def test_tool_point_allow_blocked_by_ring_relabels_to_tool_call_blocked():
    emit = _emitter()
    out = _bridge(emit=emit, rings=FakeRing(allow_check=False)).apply(
        KernelDecision(
            effective_decision="allow",
            raw_decision="allow",
            intervention_point="pre_tool_call",
        ),
        agent_id="a1",
        action=_tool_action(required_ring=1),
        current_ring=3,
    )
    assert out.proceeds is False
    assert emit.events[0].kind == "tool_call_blocked"


def test_from_evaluation_result_reads_intervention_point():
    result = SimpleNamespace(
        verdict="deny",
        audit_entry={"verdict": "deny", "intervention_point": "pre_tool_call"},
        category=None,
        reason="",
        input_identity=None,
        enforced_identity=None,
        transform=None,
        evidence=None,
    )
    decision = KernelDecision.from_evaluation_result(result)
    assert decision.intervention_point == "pre_tool_call"


def test_locks_are_a_bounded_striped_pool():
    from agt.policies.kernel import _LOCK_STRIPES

    bridge = _bridge()
    for i in range(500):
        bridge.apply(KernelDecision.from_decision("deny"), agent_id=f"agent-{i}")
    # The lock pool is fixed size regardless of agent-id cardinality.
    assert len(bridge._locks) == _LOCK_STRIPES


def test_seen_keys_are_bounded_and_evict_oldest():
    bridge = KernelBridge(
        trust_tracker=FakeTrust(),
        emit_event=_emitter(),
        max_seen_keys=3,
    )
    for i in range(10):
        bridge.apply(
            KernelDecision.from_decision("deny"),
            agent_id=f"a{i}",
            idempotency_key="k",
        )
    assert len(bridge._seen_keys) <= 3


# --- Real-runtime escalate round-trip (deep-review Stage 4, #5) --------------
#
# Pins the coupling between KernelDecision.from_evaluation_result and the actual
# AgtRuntime output: the raw escalate must be recoverable from a REAL approved
# escalation, not just a hand-built EvaluationResult. Guards against a future
# runtime refactor silently moving the audit_entry["verdict"] key.

_ESCALATE_MANIFEST = (
    "agent_control_specification_version: 0.3.0-alpha-agt\n"
    "metadata:\n  name: kernel_escalate_test\n"
    "extends: []\n"
    "policies:\n  test_policy:\n    type: custom\n    adapter: kernel_escalate_adapter\n"
    "intervention_points:\n  pre_tool_call:\n"
    "    policy_target: $.tool_call.args\n"
    "    policy_target_kind: tool_args\n"
    "    tool_name_from: $.tool_call.name\n"
    "    policy:\n      id: test_policy\n"
    "tools:\n  lookup:\n    clearance: public\n"
)


def _run_real_escalate(tmp_path, *, approve: bool):
    """Drive the real AgtRuntime through an escalate -> approve/deny cycle."""
    from agt.policies import SnapshotBuilder
    from agt.policies.runtime import AgtRuntime, ApprovalDecision

    manifest = tmp_path / "manifest.yaml"
    manifest.write_text(_ESCALATE_MANIFEST, encoding="utf-8")

    class _EscalatePolicy:
        def evaluate(self, invocation):  # noqa: ANN001
            return {"decision": "escalate", "reason": "approval_required"}

    def resolver(ip, result):  # noqa: ANN001
        if approve:
            return ApprovalDecision.allow(result.enforced_identity)
        return ApprovalDecision.deny()

    runtime = AgtRuntime(
        manifest, policy_dispatcher=_EscalatePolicy(), approval_resolver=resolver
    )
    snapshot = SnapshotBuilder(agent_id="bot", session_id="s-1").pre_tool_call(
        tool_name="lookup", args={"q": "x"}
    )
    return runtime.evaluate_intervention_point("pre_tool_call", snapshot)


def test_real_runtime_approved_escalate_is_recovered_and_neutral(tmp_path):
    pytest.importorskip("agent_control_specification")
    result = _run_real_escalate(tmp_path, approve=True)
    # The runtime rewrote the effective verdict to allow after approval.
    assert result.verdict == "allow"

    decision = KernelDecision.from_evaluation_result(result)
    # ...but the raw escalate is recovered from the real runtime output.
    assert decision.raw_decision == "escalate"
    assert decision.was_escalated is True
    assert decision.intervention_point == "pre_tool_call"

    trust = FakeTrust()
    emit = _emitter()
    out = KernelBridge(trust_tracker=trust, emit_event=emit).apply(
        decision, agent_id="bot"
    )
    # Approved escalate proceeds (effective allow) but earns no trust and audits
    # as an escalation, not a reward.
    assert out.proceeds is True
    assert out.trust_delta == 0.0
    assert trust.calls == []
    assert emit.events[0].kind == "escalation_requested"


def test_real_runtime_rejected_escalate_blocks_and_is_neutral(tmp_path):
    pytest.importorskip("agent_control_specification")
    result = _run_real_escalate(tmp_path, approve=False)
    decision = KernelDecision.from_evaluation_result(result)
    assert decision.was_escalated is True

    trust = FakeTrust()
    emit = _emitter()
    out = KernelBridge(trust_tracker=trust, emit_event=emit).apply(
        decision, agent_id="bot"
    )
    assert out.proceeds is False
    assert out.trust_delta == 0.0  # rejection is the human's call, not the agent's fault
    assert emit.events[0].kind == "escalation_requested"


def test_concurrent_same_key_reward_applied_once():
    # Two+ concurrent allows sharing (agent_id, idempotency_key) must reward the
    # agent exactly once: phase 2 re-checks the ledger under the stripe lock.
    import threading

    trust = FakeTrust()
    bridge = _bridge(trust=trust)
    n = 8
    barrier = threading.Barrier(n)
    results = []
    lock = threading.Lock()

    def worker():
        barrier.wait()
        out = bridge.apply(
            KernelDecision.from_decision("allow"),
            agent_id="racer",
            idempotency_key="dup",
        )
        with lock:
            results.append(out.trust_delta)

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Exactly one call recorded a success; the score moved by one reward only.
    success_calls = [c for c in trust.calls if c[3] is True]
    assert len(success_calls) == 1
    assert trust.get_score("racer") == pytest.approx(0.6)
    assert sum(1 for d in results if d != 0.0) == 1
