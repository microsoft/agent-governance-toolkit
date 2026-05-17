# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Conformance tests for AGENT-SRE-GOVERNANCE-1.0.

Every test references a specific section of the specification.
Tests marked [Pure Specification] verify normative requirements.
Tests marked [Default Implementation] verify reference defaults.
"""

from __future__ import annotations

import hashlib
import json
import time
import unittest
from unittest.mock import patch

# ---------------------------------------------------------------------------
# Imports under test
# ---------------------------------------------------------------------------

from agent_sre.slo.objectives import (
    BurnRateAlert,
    ErrorBudget,
    ExhaustionAction,
    SLO,
    SLOStatus,
)
from agent_sre.slo.indicators import (
    CalibrationDeltaSLI,
    CostPerTask,
    DelegationChainDepth,
    HallucinationRate,
    PolicyCompliance,
    ResponseLatency,
    SLI,
    SLIRegistry,
    SLIValue,
    TaskSuccessRate,
    TimeWindow,
    ToolCallAccuracy,
)
from agent_sre.incidents.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerRegistry,
    CircuitEvent,
    CircuitState,
)
from agent_sre.chaos.engine import (
    AbortCondition,
    ChaosExperiment,
    ExperimentState,
    Fault,
    FaultInjectionEvent,
    FaultType,
    ResilienceScore,
)
from agent_sre.alerts import (
    Alert,
    AlertChannel,
    AlertManager,
    AlertSeverity,
    ChannelConfig,
    DeliveryResult,
)
from agent_sre.replay.capture import (
    Span,
    SpanKind,
    SpanStatus,
    Trace,
    TraceCapture,
)
from agent_sre.signing import (
    ArtifactSigner,
    SignatureBundle,
)
from agent_sre.incidents.detector import (
    Incident,
    IncidentDetector,
    IncidentSeverity,
    IncidentState,
    Signal,
    SignalType,
)


# ═══════════════════════════════════════════════════════════════════════════
# Section 3: SLO Objectives
# ═══════════════════════════════════════════════════════════════════════════


class TestSLOObjectives(unittest.TestCase):
    """Spec S3 -- SLO Objectives."""

    def test_exhaustion_action_alert(self):
        """S3.1 -- ExhaustionAction.ALERT has value 'alert'."""
        self.assertEqual(ExhaustionAction.ALERT.value, "alert")

    def test_exhaustion_action_freeze(self):
        """S3.2 -- ExhaustionAction.FREEZE_DEPLOYMENTS has value 'freeze_deployments'."""
        self.assertEqual(ExhaustionAction.FREEZE_DEPLOYMENTS.value, "freeze_deployments")

    def test_exhaustion_action_circuit_break(self):
        """S3.3 -- ExhaustionAction.CIRCUIT_BREAK has value 'circuit_break'."""
        self.assertEqual(ExhaustionAction.CIRCUIT_BREAK.value, "circuit_break")

    def test_exhaustion_action_throttle(self):
        """S3.4 -- ExhaustionAction.THROTTLE has value 'throttle'."""
        self.assertEqual(ExhaustionAction.THROTTLE.value, "throttle")

    def test_burn_rate_alert_defaults(self):
        """S3.5 -- BurnRateAlert defaults: severity='warning', window=3600."""
        alert = BurnRateAlert(name="test", rate=2.0)
        self.assertEqual(alert.severity, "warning")
        self.assertEqual(alert.window_seconds, 3600)

    def test_burn_rate_alert_is_firing(self):
        """S3.6 -- BurnRateAlert fires when current >= rate."""
        alert = BurnRateAlert(name="test", rate=5.0)
        self.assertTrue(alert.is_firing(5.0))
        self.assertTrue(alert.is_firing(10.0))
        self.assertFalse(alert.is_firing(4.9))

    def test_slo_status_enum_values(self):
        """S3.7 -- SLOStatus has all required values."""
        self.assertEqual(SLOStatus.HEALTHY.value, "healthy")
        self.assertEqual(SLOStatus.WARNING.value, "warning")
        self.assertEqual(SLOStatus.CRITICAL.value, "critical")
        self.assertEqual(SLOStatus.EXHAUSTED.value, "exhausted")
        self.assertEqual(SLOStatus.UNKNOWN.value, "unknown")

    def test_slo_model_required_fields(self):
        """S3.8 -- SLO model has name, indicators, error_budget."""
        sli = TaskSuccessRate()
        slo = SLO(name="test-slo", indicators=[sli])
        self.assertEqual(slo.name, "test-slo")
        self.assertIsInstance(slo.indicators, list)
        self.assertIsInstance(slo.error_budget, ErrorBudget)

    def test_slo_default_description_empty(self):
        """S3.9 -- SLO default description is empty string."""
        sli = TaskSuccessRate()
        slo = SLO(name="test", indicators=[sli])
        self.assertEqual(slo.description, "")

    def test_slo_default_labels_empty(self):
        """S3.10 -- SLO default labels is empty dict."""
        sli = TaskSuccessRate()
        slo = SLO(name="test", indicators=[sli])
        self.assertEqual(slo.labels, {})

    def test_slo_to_dict_has_required_keys(self):
        """S3.11 -- SLO.to_dict() contains all required keys."""
        sli = TaskSuccessRate()
        slo = SLO(name="test", indicators=[sli])
        d = slo.to_dict()
        for key in ("name", "description", "status", "labels", "error_budget", "indicators"):
            self.assertIn(key, d)

    def test_slo_evaluate_unknown_when_no_data(self):
        """S3.12 -- SLO evaluates to UNKNOWN when no SLI data present."""
        sli = TaskSuccessRate()
        slo = SLO(name="test", indicators=[sli])
        self.assertEqual(slo.evaluate(), SLOStatus.UNKNOWN)


# ═══════════════════════════════════════════════════════════════════════════
# Section 4: Service Level Indicators
# ═══════════════════════════════════════════════════════════════════════════


class TestServiceLevelIndicators(unittest.TestCase):
    """Spec S4 -- Service Level Indicators."""

    def test_time_window_values(self):
        """S4.1 -- TimeWindow enum has all standard windows."""
        self.assertEqual(TimeWindow.HOUR_1.value, "1h")
        self.assertEqual(TimeWindow.HOUR_6.value, "6h")
        self.assertEqual(TimeWindow.DAY_1.value, "24h")
        self.assertEqual(TimeWindow.DAY_7.value, "7d")
        self.assertEqual(TimeWindow.DAY_30.value, "30d")

    def test_time_window_seconds(self):
        """S4.2 -- TimeWindow.seconds maps correctly."""
        self.assertEqual(TimeWindow.HOUR_1.seconds, 3600)
        self.assertEqual(TimeWindow.DAY_1.seconds, 86400)
        self.assertEqual(TimeWindow.DAY_30.seconds, 2592000)

    def test_task_success_rate_defaults(self):
        """S4.3 -- TaskSuccessRate default target=0.995, window=30d."""
        sli = TaskSuccessRate()
        self.assertEqual(sli.target, 0.995)
        self.assertEqual(sli.window, TimeWindow.DAY_30)

    def test_tool_call_accuracy_defaults(self):
        """S4.4 -- ToolCallAccuracy default target=0.999, window=7d."""
        sli = ToolCallAccuracy()
        self.assertEqual(sli.target, 0.999)
        self.assertEqual(sli.window, TimeWindow.DAY_7)

    def test_response_latency_defaults(self):
        """S4.5 -- ResponseLatency default target_ms=5000, percentile=0.95, window=1h."""
        sli = ResponseLatency()
        self.assertEqual(sli.target, 5000.0)
        self.assertEqual(sli.percentile, 0.95)
        self.assertEqual(sli.window, TimeWindow.HOUR_1)

    def test_cost_per_task_defaults(self):
        """S4.6 -- CostPerTask default target_usd=0.50, window=24h."""
        sli = CostPerTask()
        self.assertEqual(sli.target, 0.50)
        self.assertEqual(sli.window, TimeWindow.DAY_1)

    def test_policy_compliance_defaults(self):
        """S4.7 -- PolicyCompliance default target=1.0, window=24h."""
        sli = PolicyCompliance()
        self.assertEqual(sli.target, 1.0)
        self.assertEqual(sli.window, TimeWindow.DAY_1)

    def test_delegation_chain_depth_defaults(self):
        """S4.8 -- DelegationChainDepth default max_depth=3, window=24h."""
        sli = DelegationChainDepth()
        self.assertEqual(sli.max_depth, 3)
        self.assertEqual(sli.target, 3.0)
        self.assertEqual(sli.window, TimeWindow.DAY_1)

    def test_hallucination_rate_defaults(self):
        """S4.9 -- HallucinationRate default target=0.05, window=24h."""
        sli = HallucinationRate()
        self.assertEqual(sli.target, 0.05)
        self.assertEqual(sli.window, TimeWindow.DAY_1)

    def test_calibration_delta_defaults(self):
        """S4.10 -- CalibrationDeltaSLI default target_delta=0.05, window=30d."""
        sli = CalibrationDeltaSLI()
        self.assertEqual(sli.target, 0.05)
        self.assertEqual(sli.window, TimeWindow.DAY_30)

    def test_sli_registry_built_in_types(self):
        """S4.11 -- SLIRegistry registers all built-in SLI types."""
        registry = SLIRegistry()
        expected = [
            "TaskSuccessRate", "ToolCallAccuracy", "ResponseLatency",
            "CostPerTask", "PolicyCompliance", "DelegationChainDepth",
            "HallucinationRate", "CalibrationDeltaSLI",
        ]
        for name in expected:
            self.assertIn(name, registry.list_types())

    def test_sli_value_is_good_when_meets_target(self):
        """S4.12 -- SLIValue.is_good is True when value >= target."""
        v = SLIValue(name="test", value=0.99, metadata={"target": 0.95})
        self.assertTrue(v.is_good)

    def test_sli_value_is_bad_when_below_target(self):
        """S4.13 -- SLIValue.is_good is False when value < target."""
        v = SLIValue(name="test", value=0.80, metadata={"target": 0.95})
        self.assertFalse(v.is_good)

    def test_sli_value_is_good_when_no_target(self):
        """S4.14 -- SLIValue.is_good is True when no target in metadata."""
        v = SLIValue(name="test", value=0.5)
        self.assertTrue(v.is_good)


# ═══════════════════════════════════════════════════════════════════════════
# Section 5: Error Budgets
# ═══════════════════════════════════════════════════════════════════════════


class TestErrorBudgets(unittest.TestCase):
    """Spec S5 -- Error Budgets."""

    def test_error_budget_default_window(self):
        """S5.1 -- ErrorBudget default window is 30 days (2592000s)."""
        eb = ErrorBudget()
        self.assertEqual(eb.window_seconds, 2592000)

    def test_error_budget_default_burn_rates(self):
        """S5.2 -- ErrorBudget default burn rate thresholds: alert=2.0, critical=10.0."""
        eb = ErrorBudget()
        self.assertEqual(eb.burn_rate_alert, 2.0)
        self.assertEqual(eb.burn_rate_critical, 10.0)

    def test_error_budget_default_exhaustion_action(self):
        """S5.3 -- ErrorBudget default exhaustion action is ALERT."""
        eb = ErrorBudget()
        self.assertEqual(eb.exhaustion_action, ExhaustionAction.ALERT)

    def test_remaining_full_when_no_consumption(self):
        """S5.4 -- remaining is 1.0 when nothing consumed."""
        eb = ErrorBudget(total=0.05)
        self.assertEqual(eb.remaining, 1.0)

    def test_remaining_zero_when_fully_consumed(self):
        """S5.5 -- remaining is 0.0 when budget fully consumed."""
        eb = ErrorBudget(total=0.05, consumed=0.05)
        self.assertEqual(eb.remaining, 0.0)

    def test_remaining_percent(self):
        """S5.6 -- remaining_percent is remaining * 100."""
        eb = ErrorBudget(total=0.10, consumed=0.05)
        self.assertEqual(eb.remaining_percent, 50.0)

    def test_is_exhausted_true(self):
        """S5.7 -- is_exhausted is True when consumed >= total."""
        eb = ErrorBudget(total=0.05, consumed=0.05)
        self.assertTrue(eb.is_exhausted)

    def test_is_exhausted_false(self):
        """S5.8 -- is_exhausted is False when consumed < total."""
        eb = ErrorBudget(total=0.05, consumed=0.01)
        self.assertFalse(eb.is_exhausted)

    def test_record_bad_event_increments_consumed(self):
        """S5.9 -- recording a bad event increments consumed by 1.0."""
        eb = ErrorBudget(total=10.0)
        eb.record_event(good=False)
        self.assertEqual(eb.consumed, 1.0)

    def test_record_good_event_no_consumption(self):
        """S5.10 -- recording a good event does not increment consumed."""
        eb = ErrorBudget(total=10.0)
        eb.record_event(good=True)
        self.assertEqual(eb.consumed, 0.0)

    def test_to_dict_has_required_keys(self):
        """S5.11 -- ErrorBudget.to_dict() has all required keys."""
        eb = ErrorBudget(total=0.05)
        d = eb.to_dict()
        for key in ("total", "consumed", "remaining_percent", "is_exhausted",
                     "burn_rate", "exhaustion_action", "firing_alerts"):
            self.assertIn(key, d)

    def test_max_events_default(self):
        """S5.12 -- ErrorBudget default max_events is 100_000."""
        eb = ErrorBudget()
        self.assertEqual(eb.max_events, 100_000)


# ═══════════════════════════════════════════════════════════════════════════
# Section 6: Circuit Breaker
# ═══════════════════════════════════════════════════════════════════════════


class TestCircuitBreaker(unittest.TestCase):
    """Spec S6 -- Circuit Breaker."""

    def test_circuit_state_enum_values(self):
        """S6.1 -- CircuitState has CLOSED, OPEN, HALF_OPEN."""
        self.assertEqual(CircuitState.CLOSED.value, "closed")
        self.assertEqual(CircuitState.OPEN.value, "open")
        self.assertEqual(CircuitState.HALF_OPEN.value, "half_open")

    def test_config_default_failure_threshold(self):
        """S6.2 -- default failure_threshold is 5."""
        config = CircuitBreakerConfig()
        self.assertEqual(config.failure_threshold, 5)

    def test_config_default_success_threshold(self):
        """S6.3 -- default success_threshold is 3 (reserved for half-open)."""
        config = CircuitBreakerConfig()
        self.assertEqual(config.success_threshold, 3)

    def test_config_default_timeout(self):
        """S6.4 -- default timeout_seconds is 60.0."""
        config = CircuitBreakerConfig()
        self.assertEqual(config.timeout_seconds, 60.0)

    def test_config_default_half_open_max_calls(self):
        """S6.5 -- default half_open_max_calls is 3."""
        config = CircuitBreakerConfig()
        self.assertEqual(config.half_open_max_calls, 3)

    def test_initial_state_closed(self):
        """S6.6 -- circuit breaker starts in CLOSED state."""
        cb = CircuitBreaker("agent-1")
        self.assertEqual(cb.state, CircuitState.CLOSED)

    def test_available_when_closed(self):
        """S6.7 -- is_available is True when CLOSED."""
        cb = CircuitBreaker("agent-1")
        self.assertTrue(cb.is_available)

    def test_opens_on_threshold_failures(self):
        """S6.8 -- circuit opens after failure_threshold failures."""
        cb = CircuitBreaker("agent-1", CircuitBreakerConfig(failure_threshold=3))
        for _ in range(3):
            cb.record_failure("error")
        self.assertEqual(cb.state, CircuitState.OPEN)
        self.assertFalse(cb.is_available)

    def test_does_not_open_below_threshold(self):
        """S6.9 -- circuit stays closed below threshold."""
        cb = CircuitBreaker("agent-1", CircuitBreakerConfig(failure_threshold=5))
        for _ in range(4):
            cb.record_failure("error")
        self.assertEqual(cb.state, CircuitState.CLOSED)

    def test_force_open(self):
        """S6.10 -- force_open transitions to OPEN."""
        cb = CircuitBreaker("agent-1")
        cb.force_open("manual test")
        self.assertEqual(cb.state, CircuitState.OPEN)

    def test_force_close(self):
        """S6.11 -- force_close transitions to CLOSED."""
        cb = CircuitBreaker("agent-1")
        cb.force_open()
        cb.force_close()
        self.assertEqual(cb.state, CircuitState.CLOSED)

    def test_reset_clears_counters(self):
        """S6.12 -- reset clears all counters and closes circuit."""
        cb = CircuitBreaker("agent-1", CircuitBreakerConfig(failure_threshold=2))
        cb.record_failure()
        cb.record_failure()
        self.assertEqual(cb.state, CircuitState.OPEN)
        cb.reset()
        self.assertEqual(cb.state, CircuitState.CLOSED)
        self.assertTrue(cb.is_available)

    def test_events_recorded_on_transition(self):
        """S6.13 -- state transitions are recorded as CircuitEvents."""
        cb = CircuitBreaker("agent-1")
        cb.force_open("test reason")
        self.assertEqual(len(cb.events), 1)
        evt = cb.events[0]
        self.assertIsInstance(evt, CircuitEvent)
        self.assertEqual(evt.from_state, CircuitState.CLOSED)
        self.assertEqual(evt.to_state, CircuitState.OPEN)
        self.assertEqual(evt.reason, "test reason")

    def test_registry_get_or_create(self):
        """S6.14 -- CircuitBreakerRegistry.get creates breaker on first call."""
        reg = CircuitBreakerRegistry()
        cb = reg.get("agent-1")
        self.assertIsInstance(cb, CircuitBreaker)
        self.assertIs(reg.get("agent-1"), cb)  # same instance

    def test_record_success_decrements_failure_count(self):
        """S6.15 -- record_success decrements failure_count when CLOSED."""
        cb = CircuitBreaker("agent-1")
        cb.record_failure()
        cb.record_failure()
        cb.record_success()
        self.assertEqual(cb._failure_count, 1)


# ═══════════════════════════════════════════════════════════════════════════
# Section 7: Chaos Engineering
# ═══════════════════════════════════════════════════════════════════════════


class TestChaosEngineering(unittest.TestCase):
    """Spec S7 -- Chaos Engineering."""

    def test_fault_type_enum_basic_values(self):
        """S7.1 -- FaultType has basic injection types."""
        self.assertEqual(FaultType.LATENCY_INJECTION.value, "latency_injection")
        self.assertEqual(FaultType.ERROR_INJECTION.value, "error_injection")
        self.assertEqual(FaultType.TIMEOUT_INJECTION.value, "timeout_injection")

    def test_fault_type_adversarial_values(self):
        """S7.2 -- FaultType has adversarial types."""
        self.assertEqual(FaultType.PROMPT_INJECTION.value, "prompt_injection")
        self.assertEqual(FaultType.POLICY_BYPASS.value, "policy_bypass")
        self.assertEqual(FaultType.PRIVILEGE_ESCALATION.value, "privilege_escalation")
        self.assertEqual(FaultType.DATA_EXFILTRATION.value, "data_exfiltration")
        self.assertEqual(FaultType.TOOL_ABUSE.value, "tool_abuse")
        self.assertEqual(FaultType.IDENTITY_SPOOFING.value, "identity_spoofing")

    def test_fault_type_behavioral_values(self):
        """S7.3 -- FaultType has behavioral types."""
        self.assertEqual(FaultType.DEADLOCK_INJECTION.value, "deadlock_injection")
        self.assertEqual(FaultType.CONTRADICTORY_INSTRUCTION.value, "contradictory_instruction")
        self.assertEqual(FaultType.TRUST_PERTURBATION.value, "trust_perturbation")

    def test_experiment_state_enum_values(self):
        """S7.4 -- ExperimentState has all lifecycle states."""
        self.assertEqual(ExperimentState.PENDING.value, "pending")
        self.assertEqual(ExperimentState.RUNNING.value, "running")
        self.assertEqual(ExperimentState.COMPLETED.value, "completed")
        self.assertEqual(ExperimentState.ABORTED.value, "aborted")
        self.assertEqual(ExperimentState.FAILED.value, "failed")

    def test_blast_radius_clipping_upper(self):
        """S7.5 -- blast_radius is clipped to [0.0, 1.0] upper bound."""
        exp = ChaosExperiment("test", "agent-1", [], blast_radius=5.0)
        self.assertEqual(exp.blast_radius, 1.0)

    def test_blast_radius_clipping_lower(self):
        """S7.6 -- blast_radius is clipped to [0.0, 1.0] lower bound."""
        exp = ChaosExperiment("test", "agent-1", [], blast_radius=-1.0)
        self.assertEqual(exp.blast_radius, 0.0)

    def test_duration_default(self):
        """S7.7 -- default duration_seconds is 1800 (30 min)."""
        exp = ChaosExperiment("test", "agent-1", [])
        self.assertEqual(exp.duration_seconds, 1800)

    def test_experiment_starts_pending(self):
        """S7.8 -- experiment starts in PENDING state."""
        exp = ChaosExperiment("test", "agent-1", [])
        self.assertEqual(exp.state, ExperimentState.PENDING)

    def test_experiment_start_transitions_to_running(self):
        """S7.9 -- start() transitions to RUNNING."""
        exp = ChaosExperiment("test", "agent-1", [])
        exp.start()
        self.assertEqual(exp.state, ExperimentState.RUNNING)
        self.assertIsNotNone(exp.started_at)

    def test_experiment_abort(self):
        """S7.10 -- abort() transitions to ABORTED with reason."""
        exp = ChaosExperiment("test", "agent-1", [])
        exp.start()
        exp.abort("safety limit")
        self.assertEqual(exp.state, ExperimentState.ABORTED)
        self.assertEqual(exp.abort_reason, "safety limit")

    def test_experiment_complete(self):
        """S7.11 -- complete() transitions to COMPLETED."""
        exp = ChaosExperiment("test", "agent-1", [])
        exp.start()
        exp.complete()
        self.assertEqual(exp.state, ExperimentState.COMPLETED)
        self.assertIsNotNone(exp.ended_at)

    def test_fault_factory_latency(self):
        """S7.12 -- Fault.latency_injection creates correct fault."""
        f = Fault.latency_injection("tool-x", delay_ms=3000)
        self.assertEqual(f.fault_type, FaultType.LATENCY_INJECTION)
        self.assertEqual(f.target, "tool-x")
        self.assertEqual(f.params["delay_ms"], 3000)

    def test_abort_condition_lte(self):
        """S7.13 -- AbortCondition with 'lte' aborts when value <= threshold."""
        ac = AbortCondition(metric="success_rate", threshold=0.5, comparator="lte")
        self.assertTrue(ac.should_abort(0.5))
        self.assertTrue(ac.should_abort(0.3))
        self.assertFalse(ac.should_abort(0.6))

    def test_resilience_score_defaults(self):
        """S7.14 -- ResilienceScore defaults: overall=0.0, passed=False."""
        rs = ResilienceScore()
        self.assertEqual(rs.overall, 0.0)
        self.assertFalse(rs.passed)


# ═══════════════════════════════════════════════════════════════════════════
# Section 8: Alerting
# ═══════════════════════════════════════════════════════════════════════════


class TestAlerting(unittest.TestCase):
    """Spec S8 -- Alerting."""

    def test_alert_channel_enum_values(self):
        """S8.1 -- AlertChannel has all supported channel types."""
        self.assertEqual(AlertChannel.SLACK.value, "slack")
        self.assertEqual(AlertChannel.PAGERDUTY.value, "pagerduty")
        self.assertEqual(AlertChannel.GENERIC_WEBHOOK.value, "generic_webhook")
        self.assertEqual(AlertChannel.CALLBACK.value, "callback")
        self.assertEqual(AlertChannel.OPSGENIE.value, "opsgenie")
        self.assertEqual(AlertChannel.TEAMS.value, "teams")

    def test_alert_severity_enum_values(self):
        """S8.2 -- AlertSeverity has info, warning, critical, resolved."""
        self.assertEqual(AlertSeverity.INFO.value, "info")
        self.assertEqual(AlertSeverity.WARNING.value, "warning")
        self.assertEqual(AlertSeverity.CRITICAL.value, "critical")
        self.assertEqual(AlertSeverity.RESOLVED.value, "resolved")

    def test_alert_manager_dedup_window_default(self):
        """S8.3 -- AlertManager default dedup_window is 300s."""
        mgr = AlertManager()
        self.assertEqual(mgr._dedup_window_seconds, 300.0)

    def test_alert_default_source(self):
        """S8.4 -- Alert default source is 'agent-sre'."""
        a = Alert(title="test", message="msg")
        self.assertEqual(a.source, "agent-sre")

    def test_alert_default_severity(self):
        """S8.5 -- Alert default severity is WARNING."""
        a = Alert(title="test", message="msg")
        self.assertEqual(a.severity, AlertSeverity.WARNING)

    def test_alert_to_dict_keys(self):
        """S8.6 -- Alert.to_dict() has all required keys."""
        a = Alert(title="t", message="m")
        d = a.to_dict()
        for key in ("title", "message", "severity", "source", "agent_id",
                     "slo_name", "timestamp", "metadata"):
            self.assertIn(key, d)

    def test_callback_channel_delivery(self):
        """S8.7 -- CALLBACK channel delivers via in-process function."""
        received = []
        mgr = AlertManager()
        mgr.add_channel(ChannelConfig(
            channel_type=AlertChannel.CALLBACK,
            name="test-cb",
            callback=lambda a: received.append(a),
        ))
        mgr.send(Alert(title="hello", message="world"))
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0].title, "hello")

    def test_dedup_suppresses_duplicate(self):
        """S8.8 -- dedup suppresses same dedup_key within window."""
        mgr = AlertManager(dedup_window_seconds=60.0)
        mgr.add_channel(ChannelConfig(
            channel_type=AlertChannel.CALLBACK,
            name="test-cb",
            callback=lambda a: None,
        ))
        a1 = Alert(title="t", message="m", dedup_key="key1")
        a2 = Alert(title="t", message="m", dedup_key="key1")
        r1 = mgr.send(a1)
        r2 = mgr.send(a2)
        self.assertEqual(len(r1), 1)
        self.assertEqual(len(r2), 0)  # suppressed
        self.assertEqual(mgr.suppressed_count, 1)


# ═══════════════════════════════════════════════════════════════════════════
# Section 10: Replay Capture
# ═══════════════════════════════════════════════════════════════════════════


class TestReplayCapture(unittest.TestCase):
    """Spec S10 -- Replay Capture."""

    def test_span_kind_enum_values(self):
        """S10.1 -- SpanKind has all required agent span types."""
        self.assertEqual(SpanKind.AGENT_TASK.value, "agent_task")
        self.assertEqual(SpanKind.TOOL_CALL.value, "tool_call")
        self.assertEqual(SpanKind.LLM_INFERENCE.value, "llm_inference")
        self.assertEqual(SpanKind.DELEGATION.value, "delegation")
        self.assertEqual(SpanKind.POLICY_CHECK.value, "policy_check")
        self.assertEqual(SpanKind.INTERNAL.value, "internal")

    def test_span_status_enum_values(self):
        """S10.2 -- SpanStatus has ok, error, timeout."""
        self.assertEqual(SpanStatus.OK.value, "ok")
        self.assertEqual(SpanStatus.ERROR.value, "error")
        self.assertEqual(SpanStatus.TIMEOUT.value, "timeout")

    def test_span_default_status_ok(self):
        """S10.3 -- Span default status is OK."""
        s = Span()
        self.assertEqual(s.status, SpanStatus.OK)

    def test_span_finish_sets_error_status(self):
        """S10.4 -- Span.finish(error=...) sets status to ERROR."""
        s = Span()
        s.finish(error="something broke")
        self.assertEqual(s.status, SpanStatus.ERROR)
        self.assertEqual(s.error, "something broke")

    def test_span_duration_ms(self):
        """S10.5 -- Span.duration_ms computed from start/end times."""
        s = Span(start_time=100.0, end_time=100.5)
        self.assertAlmostEqual(s.duration_ms, 500.0, places=1)

    def test_span_duration_none_when_unfinished(self):
        """S10.6 -- Span.duration_ms is None when end_time is None."""
        s = Span()
        self.assertIsNone(s.duration_ms)

    def test_trace_content_hash_deterministic(self):
        """S10.7 -- Trace.content_hash is deterministic for same inputs."""
        t1 = Trace(trace_id="abc", agent_id="agent-1", task_input="hello")
        t2 = Trace(trace_id="abc", agent_id="agent-1", task_input="hello")
        self.assertEqual(t1.content_hash, t2.content_hash)

    def test_trace_content_hash_differs_for_different_inputs(self):
        """S10.8 -- Trace.content_hash differs for different task_input."""
        t1 = Trace(trace_id="abc", agent_id="agent-1", task_input="hello")
        t2 = Trace(trace_id="abc", agent_id="agent-1", task_input="world")
        self.assertNotEqual(t1.content_hash, t2.content_hash)

    def test_trace_add_span_sets_trace_id(self):
        """S10.9 -- Trace.add_span sets the span's trace_id."""
        trace = Trace(trace_id="my-trace")
        span = Span(name="step-1")
        trace.add_span(span)
        self.assertEqual(span.trace_id, "my-trace")

    def test_trace_root_spans(self):
        """S10.10 -- Trace.root_spans returns spans with no parent."""
        trace = Trace()
        root = Span(span_id="root", parent_id=None)
        child = Span(span_id="child", parent_id="root")
        trace.add_span(root)
        trace.add_span(child)
        roots = trace.root_spans()
        self.assertEqual(len(roots), 1)
        self.assertEqual(roots[0].span_id, "root")

    def test_trace_capture_context_manager(self):
        """S10.11 -- TraceCapture as context manager sets success on exit."""
        with TraceCapture(agent_id="test-agent") as cap:
            cap.start_span("step-1", SpanKind.TOOL_CALL)
            cap.end_span(output={"result": "ok"})
        self.assertTrue(cap.trace.success)
        self.assertIsNotNone(cap.trace.end_time)

    def test_span_round_trip_serialization(self):
        """S10.12 -- Span.to_dict / from_dict round-trip is lossless."""
        s = Span(
            span_id="s1", trace_id="t1", kind=SpanKind.TOOL_CALL,
            name="call", status=SpanStatus.OK, cost_usd=0.01,
        )
        d = s.to_dict()
        s2 = Span.from_dict(d)
        self.assertEqual(s2.span_id, "s1")
        self.assertEqual(s2.kind, SpanKind.TOOL_CALL)
        self.assertEqual(s2.cost_usd, 0.01)


# ═══════════════════════════════════════════════════════════════════════════
# Section 13: Artifact Signing
# ═══════════════════════════════════════════════════════════════════════════


class TestArtifactSigning(unittest.TestCase):
    """Spec S13 -- Artifact Signing."""

    def _skip_if_no_crypto(self):
        try:
            import cryptography  # noqa: F401
        except ImportError:
            self.skipTest("cryptography package not installed")

    def test_signer_generates_keypair(self):
        """S13.1 -- ArtifactSigner generates ephemeral Ed25519 keypair."""
        self._skip_if_no_crypto()
        signer = ArtifactSigner()
        self.assertEqual(len(signer.public_key_bytes), 32)

    def test_sign_verify_round_trip(self):
        """S13.2 -- sign then verify round-trip succeeds."""
        self._skip_if_no_crypto()
        import tempfile, os
        signer = ArtifactSigner()
        # Create a temp artifact
        fd, path = tempfile.mkstemp(suffix=".txt")
        try:
            os.write(fd, b"test artifact content")
            os.close(fd)
            bundle = signer.sign_artifact(path)
            self.assertIsInstance(bundle, SignatureBundle)
            result = signer.verify_artifact(path, bundle.signature, bundle.public_key)
            self.assertTrue(result)
        finally:
            os.unlink(path)

    def test_verify_fails_with_wrong_key(self):
        """S13.3 -- verification fails with wrong public key."""
        self._skip_if_no_crypto()
        import tempfile, os
        signer1 = ArtifactSigner()
        signer2 = ArtifactSigner()
        fd, path = tempfile.mkstemp(suffix=".txt")
        try:
            os.write(fd, b"test content")
            os.close(fd)
            bundle = signer1.sign_artifact(path)
            result = signer2.verify_artifact(path, bundle.signature, signer2.public_key_bytes)
            self.assertFalse(result)
        finally:
            os.unlink(path)

    def test_signature_bundle_fields(self):
        """S13.4 -- SignatureBundle has required fields."""
        self._skip_if_no_crypto()
        signer = ArtifactSigner()
        import tempfile, os
        fd, path = tempfile.mkstemp(suffix=".txt")
        try:
            os.write(fd, b"data")
            os.close(fd)
            bundle = signer.sign_artifact(path)
            self.assertIsInstance(bundle.signature, bytes)
            self.assertIsInstance(bundle.public_key, bytes)
            self.assertIsInstance(bundle.artifact_hash, str)
            self.assertIsInstance(bundle.timestamp, str)
        finally:
            os.unlink(path)

    def test_signature_bundle_to_dict_round_trip(self):
        """S13.5 -- SignatureBundle.to_dict / from_dict round-trip."""
        bundle = SignatureBundle(
            signature=b"\x01\x02\x03",
            public_key=b"\x04\x05\x06",
            artifact_hash="abc123",
            timestamp="2024-01-01T00:00:00+00:00",
            signer_did="did:key:test",
        )
        d = bundle.to_dict()
        b2 = SignatureBundle.from_dict(d)
        self.assertEqual(b2.signature, bundle.signature)
        self.assertEqual(b2.public_key, bundle.public_key)
        self.assertEqual(b2.artifact_hash, bundle.artifact_hash)
        self.assertEqual(b2.signer_did, "did:key:test")

    def test_signature_bundle_signer_did_optional(self):
        """S13.6 -- SignatureBundle.signer_did defaults to None."""
        bundle = SignatureBundle(
            signature=b"\x01",
            public_key=b"\x02",
            artifact_hash="hash",
            timestamp="now",
        )
        self.assertIsNone(bundle.signer_did)


# ═══════════════════════════════════════════════════════════════════════════
# Section 14: Incident Detection
# ═══════════════════════════════════════════════════════════════════════════


class TestIncidentDetection(unittest.TestCase):
    """Spec S14 -- Incident Detection."""

    def test_incident_severity_values(self):
        """S14.1 -- IncidentSeverity has P1-P4."""
        self.assertEqual(IncidentSeverity.P1.value, "p1")
        self.assertEqual(IncidentSeverity.P2.value, "p2")
        self.assertEqual(IncidentSeverity.P3.value, "p3")
        self.assertEqual(IncidentSeverity.P4.value, "p4")

    def test_incident_state_lifecycle(self):
        """S14.2 -- IncidentState has full lifecycle."""
        self.assertEqual(IncidentState.DETECTED.value, "detected")
        self.assertEqual(IncidentState.ACKNOWLEDGED.value, "acknowledged")
        self.assertEqual(IncidentState.INVESTIGATING.value, "investigating")
        self.assertEqual(IncidentState.MITIGATING.value, "mitigating")
        self.assertEqual(IncidentState.RESOLVED.value, "resolved")

    def test_signal_type_enum_values(self):
        """S14.3 -- SignalType has all signal types."""
        self.assertEqual(SignalType.SLO_BREACH.value, "slo_breach")
        self.assertEqual(SignalType.ERROR_BUDGET_EXHAUSTED.value, "error_budget_exhausted")
        self.assertEqual(SignalType.COST_ANOMALY.value, "cost_anomaly")
        self.assertEqual(SignalType.POLICY_VIOLATION.value, "policy_violation")
        self.assertEqual(SignalType.TRUST_REVOCATION.value, "trust_revocation")
        self.assertEqual(SignalType.TOOL_FAILURE_SPIKE.value, "tool_failure_spike")
        self.assertEqual(SignalType.LATENCY_SPIKE.value, "latency_spike")

    def test_signal_severity_hint_p1(self):
        """S14.4 -- critical signals hint P1."""
        for st in (SignalType.ERROR_BUDGET_EXHAUSTED, SignalType.POLICY_VIOLATION,
                    SignalType.TRUST_REVOCATION):
            sig = Signal(signal_type=st, source="agent-1")
            self.assertEqual(sig.severity_hint, IncidentSeverity.P1)

    def test_signal_severity_hint_p2(self):
        """S14.5 -- warning signals hint P2."""
        for st in (SignalType.SLO_BREACH, SignalType.COST_ANOMALY,
                    SignalType.LATENCY_SPIKE):
            sig = Signal(signal_type=st, source="agent-1")
            self.assertEqual(sig.severity_hint, IncidentSeverity.P2)

    def test_signal_severity_hint_p3_default(self):
        """S14.6 -- TOOL_FAILURE_SPIKE hints P3."""
        sig = Signal(signal_type=SignalType.TOOL_FAILURE_SPIKE, source="agent-1")
        self.assertEqual(sig.severity_hint, IncidentSeverity.P3)

    def test_incident_initial_state_detected(self):
        """S14.7 -- Incident starts in DETECTED state."""
        inc = Incident(title="test", severity=IncidentSeverity.P1)
        self.assertEqual(inc.state, IncidentState.DETECTED)

    def test_incident_lifecycle_transitions(self):
        """S14.8 -- Incident transitions through lifecycle."""
        inc = Incident(title="test", severity=IncidentSeverity.P2)
        inc.acknowledge()
        self.assertEqual(inc.state, IncidentState.ACKNOWLEDGED)
        inc.investigate()
        self.assertEqual(inc.state, IncidentState.INVESTIGATING)
        inc.mitigate()
        self.assertEqual(inc.state, IncidentState.MITIGATING)
        inc.resolve("fixed it")
        self.assertEqual(inc.state, IncidentState.RESOLVED)
        self.assertIsNotNone(inc.resolved_at)
        self.assertIn("fixed it", inc.notes)

    def test_incident_detector_creates_incident_for_p1(self):
        """S14.9 -- IncidentDetector creates incident for P1 signal."""
        detector = IncidentDetector()
        sig = Signal(
            signal_type=SignalType.ERROR_BUDGET_EXHAUSTED,
            source="agent-1",
            message="budget gone",
        )
        incident = detector.ingest_signal(sig)
        self.assertIsNotNone(incident)
        self.assertEqual(incident.severity, IncidentSeverity.P1)

    def test_incident_detector_skips_p3(self):
        """S14.10 -- IncidentDetector does not create incident for P3 signal."""
        detector = IncidentDetector()
        sig = Signal(
            signal_type=SignalType.TOOL_FAILURE_SPIKE,
            source="agent-1",
        )
        incident = detector.ingest_signal(sig)
        self.assertIsNone(incident)

    def test_incident_to_dict_keys(self):
        """S14.11 -- Incident.to_dict() has all required keys."""
        inc = Incident(title="t", severity=IncidentSeverity.P2, agent_id="a1")
        d = inc.to_dict()
        for key in ("incident_id", "title", "severity", "state", "agent_id",
                     "detected_at", "signals", "actions", "notes"):
            self.assertIn(key, d)


# ═══════════════════════════════════════════════════════════════════════════
# Section 17: Failure Semantics
# ═══════════════════════════════════════════════════════════════════════════


class TestFailureSemantics(unittest.TestCase):
    """Spec S17 -- Failure Semantics (fail-closed behaviors)."""

    def test_circuit_breaker_fail_closed(self):
        """S17.1 -- open circuit rejects calls (fail-closed)."""
        cb = CircuitBreaker("agent-1")
        cb.force_open("fail-closed test")
        self.assertFalse(cb.is_available)

    def test_error_budget_exhaustion_detected(self):
        """S17.2 -- exhausted budget is detected as failure."""
        eb = ErrorBudget(total=2.0)
        eb.record_event(good=False)
        eb.record_event(good=False)
        self.assertTrue(eb.is_exhausted)

    def test_slo_evaluates_exhausted_on_budget_depletion(self):
        """S17.3 -- SLO evaluates EXHAUSTED when budget consumed."""
        sli = TaskSuccessRate()
        eb = ErrorBudget(total=1.0, consumed=1.0)
        slo = SLO(name="test", indicators=[sli], error_budget=eb)
        self.assertEqual(slo.evaluate(), SLOStatus.EXHAUSTED)

    def test_abort_condition_halts_experiment(self):
        """S17.4 -- abort condition halts chaos experiment."""
        exp = ChaosExperiment("test", "agent-1", [],
                              abort_conditions=[
                                  AbortCondition("success_rate", 0.5, "lte"),
                              ])
        exp.start()
        halted = exp.check_abort({"success_rate": 0.3})
        self.assertTrue(halted)
        self.assertEqual(exp.state, ExperimentState.ABORTED)

    def test_circuit_breaker_total_trips_counted(self):
        """S17.5 -- total_trips increments on each open transition."""
        cb = CircuitBreaker("agent-1")
        cb.force_open("trip 1")
        cb.force_close("recover")
        cb.force_open("trip 2")
        self.assertEqual(cb._total_trips, 2)

    def test_dedup_allows_after_resolved(self):
        """S17.6 -- resolved alert clears dedup, allowing re-alert."""
        mgr = AlertManager(dedup_window_seconds=60.0)
        mgr.add_channel(ChannelConfig(
            channel_type=AlertChannel.CALLBACK,
            name="cb",
            callback=lambda a: None,
        ))
        # First alert
        mgr.send(Alert(title="t", message="m", dedup_key="k1"))
        # Resolve clears dedup cache
        mgr.send(Alert(title="t", message="m", dedup_key="k1",
                        severity=AlertSeverity.RESOLVED))
        # Re-alert should work
        results = mgr.send(Alert(title="t", message="m", dedup_key="k1"))
        self.assertEqual(len(results), 1)

    def test_chaos_experiment_inject_fault_recorded(self):
        """S17.7 -- injected faults are recorded as FaultInjectionEvents."""
        exp = ChaosExperiment("test", "agent-1", [])
        exp.start()
        fault = Fault.error_injection("tool-x")
        exp.inject_fault(fault)
        self.assertEqual(len(exp.injection_events), 1)
        self.assertIsInstance(exp.injection_events[0], FaultInjectionEvent)
        self.assertEqual(exp.injection_events[0].fault_type, FaultType.ERROR_INJECTION)


if __name__ == "__main__":
    unittest.main()
