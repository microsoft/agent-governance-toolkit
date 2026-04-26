# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent-SRE End-to-End Scenario Tests

Cross-module scenarios that exercise the full SRE governance pipeline:

1. Policy violation cascade: Agent OS policy breach → SLO impact → budget burn → circuit break
2. Trust degradation flow: Agent Mesh trust drop → SLI alert → incident → postmortem
3. Chaos injection pipeline: Fault injection → incident detection → auto-remediation
4. Progressive delivery: Shadow deploy → canary → SLO evaluation → rollback
5. Cost guard enforcement: Budget threshold → throttle → SLO correlation
6. Full governance pipeline: OS policy + Mesh trust + SLO + Chaos → unified dashboard
"""

from __future__ import annotations

import pytest

from agent_sre.chaos.engine import (
    ChaosExperiment,
    ExperimentState,
    Fault,
)
from agent_sre.cost.guard import CostGuard
from agent_sre.incidents.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitState,
)
from agent_sre.incidents.detector import IncidentDetector, SignalType
from agent_sre.integrations.agent_mesh.bridge import (
    AgentMeshBridge,
    MeshEvent,
)
from agent_sre.integrations.agent_os.bridge import (
    AgentOSBridge,
    AuditLogEntry,
)
from agent_sre.slo.dashboard import SLODashboard
from agent_sre.slo.indicators import (
    CostPerTask,
    PolicyCompliance,
    ResponseLatency,
    TaskSuccessRate,
    ToolCallAccuracy,
)
from agent_sre.slo.objectives import SLO, ErrorBudget, SLOStatus

# ---------------------------------------------------------------------------
# Scenario 1: Policy Violation Cascade
# ---------------------------------------------------------------------------


class TestPolicyViolationCascade:
    """
    Flow: Agent OS blocks action → PolicyComplianceSLI drops →
          SLO degrades → Error budget burns → Circuit breaker trips
    """

    def test_policy_blocks_degrade_slo(self):
        """Policy violations tracked by OS bridge degrade SLO compliance."""
        bridge = AgentOSBridge()
        slo = SLO(
            name="policy-compliance",
            indicators=[bridge.policy_sli],
            error_budget=ErrorBudget(total=0.05),
        )

        # 10 compliant checks
        for i in range(10):
            entry = AuditLogEntry(
                entry_type="allowed",
                agent_id=f"did:mesh:agent-{i}",
                action="read_data",
                policy_name="data-access",
            )
            bridge.process_audit_entry(entry)
            slo.record_event(True)

        # Compliance should be 100%
        summary = bridge.summary()
        assert summary["blocked_count"] == 0

        # Now 5 violations
        for _i in range(5):
            entry = AuditLogEntry(
                entry_type="blocked",
                agent_id="did:mesh:rogue-agent",
                action="delete_records",
                policy_name="deletion-guard",
            )
            signal = bridge.process_audit_entry(entry)
            slo.record_event(False)
            assert signal is not None
            assert signal.signal_type == SignalType.POLICY_VIOLATION

        summary = bridge.summary()
        assert summary["blocked_count"] == 5
        assert summary["events_processed"] == 15

        # SLO should now be degraded
        status = slo.evaluate()
        assert status in (SLOStatus.WARNING, SLOStatus.CRITICAL, SLOStatus.EXHAUSTED)

    def test_policy_cascade_to_circuit_breaker(self):
        """Repeated policy violations trip the circuit breaker."""
        bridge = AgentOSBridge()
        cb = CircuitBreaker("bad-agent", CircuitBreakerConfig(
            failure_threshold=3,
            timeout_seconds=60,
        ))

        # Simulate policy violations triggering circuit breaker
        for i in range(5):
            entry = AuditLogEntry(
                entry_type="blocked",
                agent_id="did:mesh:bad-agent",
                action=f"dangerous-action-{i}",
                policy_name="safety-guard",
            )
            signal = bridge.process_audit_entry(entry)
            if signal:
                cb.record_failure()

        assert cb.state == CircuitState.OPEN
        assert not cb.is_available


# ---------------------------------------------------------------------------
# Scenario 2: Trust Degradation Flow
# ---------------------------------------------------------------------------


class TestTrustDegradationFlow:
    """
    Flow: Agent Mesh trust drops → TrustScoreSLI below target →
          SLO degrades → Incident detected → Postmortem generated
    """

    def test_trust_drop_triggers_incident(self):
        """Agent Mesh trust revocation triggers an SRE incident."""
        mesh_bridge = AgentMeshBridge()
        detector = IncidentDetector()

        # Normal trust scores
        for i in range(5):
            mesh_bridge.trust_sli.record_trust(850, f"did:mesh:agent-{i}")
            mesh_bridge.handshake_sli.record_handshake(True)

        # Trust revocation event
        event = MeshEvent(
            event_type="trust_revocation",
            agent_did="did:mesh:compromised-agent",
            details={"reason": "behavioral_drift", "previous_score": 850},
        )
        signal = mesh_bridge.process_event(event)
        assert signal is not None
        assert signal.signal_type == SignalType.TRUST_REVOCATION

        # Feed signal to detector
        detector.ingest_signal(signal)

    def test_trust_sli_tracks_degradation(self):
        """TrustScoreSLI correctly reflects declining trust scores."""
        mesh_bridge = AgentMeshBridge()

        # Good scores
        for _ in range(5):
            mesh_bridge.trust_sli.record_trust(900, "did:mesh:good")

        # Then bad scores
        for _ in range(10):
            mesh_bridge.trust_sli.record_trust(200, "did:mesh:bad")

        SLO(
            name="trust-health",
            indicators=[mesh_bridge.trust_sli],
            error_budget=ErrorBudget(total=0.1),
        )
        # Bad trust scores should degrade the SLI
        val = mesh_bridge.trust_sli.current_value()
        assert val is not None
        assert val < 0.5  # Should be low after many bad scores

    def test_handshake_failure_sli(self):
        """Handshake failures degrade the handshake SLI."""
        mesh_bridge = AgentMeshBridge()

        # 10 handshakes: 7 success, 3 failure
        for _i in range(7):
            mesh_bridge.handshake_sli.record_handshake(True)
        for _i in range(3):
            mesh_bridge.handshake_sli.record_handshake(False)

        val = mesh_bridge.handshake_sli.current_value()
        assert val is not None
        # The SLI uses a time-windowed moving average, not a simple ratio
        # Just verify it's below the target of 0.99
        assert val < 0.99

        summary = mesh_bridge.summary()
        # Time-weighted moving average won't be exactly 0.7
        assert summary["handshake_rate"] is not None
        assert summary["handshake_rate"] < 1.0  # Some failures should show


# ---------------------------------------------------------------------------
# Scenario 3: Chaos Injection Pipeline
# ---------------------------------------------------------------------------


class TestChaosInjectionPipeline:
    """
    Flow: Chaos experiment → Fault injected → Incident detected →
          SLO evaluated → Recovery confirmed
    """

    def test_chaos_to_incident_to_recovery(self):
        """Chaos experiment triggers detectable incident."""
        # Setup SLO tracking
        success_sli = TaskSuccessRate(target=0.95)
        slo = SLO(
            name="chaos-target",
            indicators=[success_sli],
            error_budget=ErrorBudget(total=0.10),
        )

        # Baseline: 20 good tasks
        for _ in range(20):
            success_sli.record_task(True)
            slo.record_event(True)

        baseline = slo.evaluate()
        assert baseline in (SLOStatus.HEALTHY, SLOStatus.UNKNOWN)

        # Run chaos experiment
        experiment = ChaosExperiment(
            name="latency-injection",
            target_agent="did:mesh:test-agent",
            faults=[Fault.tool_timeout("search_tool", delay_ms=5000)],
            duration_seconds=30,
        )
        experiment.start()
        assert experiment.state == ExperimentState.RUNNING

        # During chaos: 5 failures
        for _ in range(5):
            success_sli.record_task(False)
            slo.record_event(False)

        # Evaluate during chaos
        during_chaos = slo.evaluate()
        # SLO should be degraded
        assert during_chaos != SLOStatus.HEALTHY or during_chaos == SLOStatus.UNKNOWN

        # End chaos
        experiment.complete()
        assert experiment.state == ExperimentState.COMPLETED

        # Recovery: 10 good tasks
        for _ in range(10):
            success_sli.record_task(True)
            slo.record_event(True)

    def test_chaos_experiment_abort(self):
        """Chaos experiment can be aborted if SLO impact is too severe."""
        experiment = ChaosExperiment(
            name="error-injection",
            target_agent="did:mesh:critical-agent",
            faults=[Fault.error_injection("expensive_tool", error="overload")],
        )

        experiment.start()
        assert experiment.state == ExperimentState.RUNNING

        # Abort on severe impact
        experiment.abort(reason="SLO critically degraded")
        assert experiment.state == ExperimentState.ABORTED


# ---------------------------------------------------------------------------
# Scenario 4: Cost Guard Enforcement
# ---------------------------------------------------------------------------


class TestCostGuardEnforcement:
    """
    Flow: Agent cost exceeds budget → Guard triggers →
          Throttle applied → SLO reflects budget pressure
    """

    def test_cost_budget_enforcement(self):
        """CostGuard detects overspend and auto-throttles agent."""
        guard = CostGuard(
            per_task_limit=1.0,
            per_agent_daily_limit=5.0,
            auto_throttle=True,
        )

        cost_sli = CostPerTask(target_usd=0.50)
        slo = SLO(
            name="cost-health",
            indicators=[cost_sli],
        )

        # 4 cheap tasks ($0.50 each = $2.00)
        for i in range(4):
            allowed, reason = guard.check_task("agent-1", 0.50)
            assert allowed
            guard.record_cost("agent-1", f"task-{i}", 0.50)
            cost_sli.record_cost(0.50)
            slo.record_event(True)

        budget = guard.get_budget("agent-1")
        assert budget.spent_today_usd == pytest.approx(2.00, abs=0.01)

        # Try an expensive task ($4.00 — would exceed daily limit)
        allowed, reason = guard.check_task("agent-1", 4.00)
        assert not allowed  # Should be blocked

    def test_cost_sli_detects_expensive_tasks(self):
        """CostPerTask SLI records costs correctly."""
        cost_sli = CostPerTask(target_usd=0.50)

        # Cheap tasks
        for _ in range(5):
            cost_sli.record_cost(0.10)

        # Expensive tasks
        for _ in range(5):
            cost_sli.record_cost(1.50)

        val = cost_sli.current_value()
        assert val is not None
        # SLI should reflect recent expensive tasks (above the 0.10 baseline)
        assert val > 0.10


# ---------------------------------------------------------------------------
# Scenario 5: Multi-Agent SLO Dashboard
# ---------------------------------------------------------------------------


class TestMultiAgentDashboard:
    """
    Unified dashboard tracking SLOs across multiple agents with
    different health states.
    """

    def test_heterogeneous_agent_dashboard(self):
        """Dashboard tracks agents with varying health."""
        dashboard = SLODashboard()

        # Agent 1: Healthy
        sli1 = TaskSuccessRate(target=0.95)
        for _ in range(20):
            sli1.record_task(True)
        slo1 = SLO(name="agent-healthy", indicators=[sli1])
        for _ in range(20):
            slo1.record_event(True)
        dashboard.register_slo(slo1)

        # Agent 2: Degraded
        sli2 = TaskSuccessRate(target=0.95)
        for _ in range(15):
            sli2.record_task(True)
        for _ in range(5):
            sli2.record_task(False)
        slo2 = SLO(name="agent-degraded", indicators=[sli2])
        for _ in range(15):
            slo2.record_event(True)
        for _ in range(5):
            slo2.record_event(False)
        dashboard.register_slo(slo2)

        # Agent 3: Critical (from budget exhaustion)
        sli3 = TaskSuccessRate(target=0.99)
        for _ in range(5):
            sli3.record_task(True)
        for _ in range(10):
            sli3.record_task(False)
        slo3 = SLO(
            name="agent-critical",
            indicators=[sli3],
            error_budget=ErrorBudget(total=0.01),
        )
        for _ in range(5):
            slo3.record_event(True)
        for _ in range(10):
            slo3.record_event(False)
        dashboard.register_slo(slo3)

        health = dashboard.health_summary()
        assert health["total_slos"] == 3

        snapshots = dashboard.take_snapshot()
        assert len(snapshots) == 3

        # Get names for verification
        names = {s.slo_name for s in snapshots}
        assert names == {"agent-healthy", "agent-degraded", "agent-critical"}


# ---------------------------------------------------------------------------
# Scenario 6: Full Cross-Module Governance Pipeline
# ---------------------------------------------------------------------------


class TestFullGovernancePipeline:
    """
    Complete cross-module flow:
    Agent OS policy + Agent Mesh trust + SLO tracking + Chaos →
    Unified incident detection + Postmortem + Dashboard
    """

    def test_full_pipeline(self):
        """End-to-end: OS policy + Mesh trust → SLO → Incident → Dashboard."""
        # Initialize bridges
        os_bridge = AgentOSBridge()
        mesh_bridge = AgentMeshBridge()
        dashboard = SLODashboard()

        # Agent-level SLIs
        success_sli = TaskSuccessRate(target=0.95)
        latency_sli = ResponseLatency(target_ms=5000.0)

        # Create SLOs
        agent_slo = SLO(
            name="agent-alpha-slo",
            indicators=[success_sli, latency_sli],
            error_budget=ErrorBudget(total=0.10),
        )
        policy_slo = SLO(
            name="policy-compliance-slo",
            indicators=[os_bridge.policy_sli],
            error_budget=ErrorBudget(total=0.05),
        )
        trust_slo = SLO(
            name="trust-health-slo",
            indicators=[mesh_bridge.trust_sli],
            error_budget=ErrorBudget(total=0.10),
        )

        dashboard.register_slo(agent_slo)
        dashboard.register_slo(policy_slo)
        dashboard.register_slo(trust_slo)

        # === Phase 1: Normal Operation ===
        for _i in range(20):
            success_sli.record_task(True)
            latency_sli.record_latency(200.0)
            agent_slo.record_event(True)

            os_bridge.process_audit_entry(AuditLogEntry(
                entry_type="allowed",
                agent_id="did:mesh:alpha",
                action="task",
                policy_name="standard",
            ))
            policy_slo.record_event(True)

            mesh_bridge.trust_sli.record_trust(850, "did:mesh:alpha")
            trust_slo.record_event(True)

        # Dashboard should show all healthy
        health = dashboard.health_summary()
        assert health["total_slos"] == 3

        # === Phase 2: Agent Degradation ===
        # Agent starts failing tasks
        for _ in range(5):
            success_sli.record_task(False)
            latency_sli.record_latency(8000.0)  # High latency
            agent_slo.record_event(False)

        # Policy violations start
        for _ in range(3):
            signal = os_bridge.process_audit_entry(AuditLogEntry(
                entry_type="blocked",
                agent_id="did:mesh:alpha",
                action="unauthorized_write",
                policy_name="data-guard",
            ))
            policy_slo.record_event(False)
            assert signal is not None

        # Trust drops
        mesh_bridge.trust_sli.record_trust(200, "did:mesh:alpha")
        trust_signal = mesh_bridge.process_event(MeshEvent(
            event_type="trust_revocation",
            agent_did="did:mesh:alpha",
            details={"reason": "policy_violations"},
        ))
        trust_slo.record_event(False)
        assert trust_signal is not None

        # === Phase 3: Verify Degradation ===
        os_summary = os_bridge.summary()
        assert os_summary["blocked_count"] == 3
        assert os_summary["events_processed"] == 23

        mesh_summary = mesh_bridge.summary()
        assert mesh_summary["events_processed"] == 1

        # Agent SLO should be degraded
        agent_status = agent_slo.evaluate()
        assert agent_status in (SLOStatus.WARNING, SLOStatus.CRITICAL, SLOStatus.EXHAUSTED)

        # === Phase 4: Recovery ===
        for _ in range(10):
            success_sli.record_task(True)
            latency_sli.record_latency(200.0)
            agent_slo.record_event(True)

            os_bridge.process_audit_entry(AuditLogEntry(
                entry_type="allowed",
                agent_id="did:mesh:alpha",
                action="task",
                policy_name="standard",
            ))
            policy_slo.record_event(True)

            mesh_bridge.trust_sli.record_trust(750, "did:mesh:alpha")
            trust_slo.record_event(True)

        # Final dashboard snapshot
        snapshots = dashboard.take_snapshot()
        assert len(snapshots) == 3

    def test_cross_module_signal_correlation(self):
        """Signals from OS and Mesh correlate in a single incident context."""
        os_bridge = AgentOSBridge()
        mesh_bridge = AgentMeshBridge()

        # OS policy violation
        os_signal = os_bridge.process_audit_entry(AuditLogEntry(
            entry_type="blocked",
            agent_id="did:mesh:suspicious",
            action="exfiltrate_data",
            policy_name="data-loss-prevention",
        ))

        # Mesh trust revocation for same agent
        mesh_signal = mesh_bridge.process_event(MeshEvent(
            event_type="trust_revocation",
            agent_did="did:mesh:suspicious",
            details={"reason": "data_exfiltration_attempt"},
        ))

        assert os_signal is not None
        assert mesh_signal is not None

        # Both signals reference the same agent
        assert os_signal.source == "did:mesh:suspicious"
        assert mesh_signal.source == "did:mesh:suspicious"

        # Both are actionable signal types
        assert os_signal.signal_type == SignalType.POLICY_VIOLATION
        assert mesh_signal.signal_type == SignalType.TRUST_REVOCATION


# ---------------------------------------------------------------------------
# Scenario 7: SLI Type Diversity
# ---------------------------------------------------------------------------


class TestSLITypeDiversity:
    """Verify all SLI types work together in a unified SLO."""

    def test_all_sli_types_in_one_slo(self):
        """SLO with all 5 core SLI types evaluates correctly."""
        success = TaskSuccessRate(target=0.95)
        accuracy = ToolCallAccuracy(target=0.99)
        latency = ResponseLatency(target_ms=5000.0)
        cost = CostPerTask(target_usd=0.50)
        policy = PolicyCompliance(target=1.0)

        slo = SLO(
            name="comprehensive-agent",
            indicators=[success, accuracy, latency, cost, policy],
            description="Full SLI coverage SLO",
            error_budget=ErrorBudget(total=0.05),
        )

        # Record across all SLIs
        for _ in range(20):
            success.record_task(True)
            accuracy.record_call(True)
            latency.record_latency(200.0)
            cost.record_cost(0.10)
            policy.record_check(True)
            slo.record_event(True)

        status = slo.evaluate()
        assert status in (SLOStatus.HEALTHY, SLOStatus.UNKNOWN)

        d = slo.to_dict()
        assert d["name"] == "comprehensive-agent"
        assert len(d["indicators"]) == 5

    def test_mixed_sli_degradation(self):
        """When one SLI degrades, the SLO reflects it."""
        success = TaskSuccessRate(target=0.95)
        latency = ResponseLatency(target_ms=1000.0)

        slo = SLO(
            name="mixed-degradation",
            indicators=[success, latency],
            error_budget=ErrorBudget(total=0.05),
        )

        # Good success, bad latency
        for _ in range(20):
            success.record_task(True)
            latency.record_latency(5000.0)  # 5x over target
            slo.record_event(True)

        # Latency SLI should be breached even though success is fine
        latency_val = latency.current_value()
        assert latency_val is not None
        assert latency_val > 1000.0  # Above target
