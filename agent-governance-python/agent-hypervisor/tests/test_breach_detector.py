# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for ring breach detector — behavioral anomaly detection."""

from datetime import UTC, datetime

from hypervisor.models import ExecutionRing
from hypervisor.rings.breach_detector import (
    BreachEvent,
    BreachSeverity,
    RingBreachDetector,
)


class TestBreachSeverity:
    def test_enum_values(self):
        assert BreachSeverity.NONE == "none"
        assert BreachSeverity.LOW == "low"
        assert BreachSeverity.MEDIUM == "medium"
        assert BreachSeverity.HIGH == "high"
        assert BreachSeverity.CRITICAL == "critical"

    def test_enum_count(self):
        assert len(BreachSeverity) == 5

    def test_is_str_enum(self):
        assert isinstance(BreachSeverity.LOW, str)


class TestBreachEvent:
    def test_creation_with_defaults(self):
        event = BreachEvent(
            agent_did="did:example:agent1",
            session_id="sess-1",
            severity=BreachSeverity.HIGH,
            anomaly_score=0.95,
            call_count_window=10,
            expected_rate=5.0,
            actual_rate=15.0,
        )
        assert event.agent_did == "did:example:agent1"
        assert event.session_id == "sess-1"
        assert event.severity == BreachSeverity.HIGH
        assert event.anomaly_score == 0.95
        assert event.call_count_window == 10
        assert event.expected_rate == 5.0
        assert event.actual_rate == 15.0
        assert event.details == ""
        assert isinstance(event.timestamp, datetime)

    def test_creation_with_details(self):
        ts = datetime(2025, 1, 1, tzinfo=UTC)
        event = BreachEvent(
            agent_did="did:example:a",
            session_id="s1",
            severity=BreachSeverity.CRITICAL,
            anomaly_score=1.0,
            call_count_window=100,
            expected_rate=10.0,
            actual_rate=50.0,
            timestamp=ts,
            details="anomalous ring-0 calls",
        )
        assert event.timestamp == ts
        assert event.details == "anomalous ring-0 calls"


class TestRingBreachDetector:
    def test_init_defaults(self):
        detector = RingBreachDetector()
        assert detector.window_seconds == 60
        assert detector.baseline_rate == 10.0
        assert detector.breach_count == 0
        assert detector.breach_history == []

    def test_init_custom_window(self):
        detector = RingBreachDetector(window_seconds=120)
        assert detector.window_seconds == 120

    def test_normal_rate_no_breach(self):
        """Calls below baseline threshold produce no breach event."""
        detector = RingBreachDetector(window_seconds=60, baseline_rate=10.0)
        result = detector.record_call(
            agent_did="did:example:agent1",
            session_id="sess-1",
            agent_ring=ExecutionRing.RING_2_STANDARD,
            called_ring=ExecutionRing.RING_2_STANDARD,
        )
        assert result is None
        assert detector.breach_count == 0

    def test_high_frequency_triggers_breach(self):
        """Rapid calls exceeding baseline trigger a breach event."""
        detector = RingBreachDetector(
            window_seconds=60, baseline_rate=0.1, max_events_per_agent=500
        )

        breach = None
        for _ in range(30):
            result = detector.record_call(
                agent_did="did:example:agent1",
                session_id="sess-1",
                agent_ring=ExecutionRing.RING_2_STANDARD,
                called_ring=ExecutionRing.RING_2_STANDARD,
            )
            if result is not None:
                breach = result

        assert breach is not None
        assert breach.severity in (
            BreachSeverity.LOW,
            BreachSeverity.MEDIUM,
            BreachSeverity.HIGH,
            BreachSeverity.CRITICAL,
        )
        assert breach.actual_rate > detector.baseline_rate
        assert breach.anomaly_score >= 2.0
        assert detector.breach_count >= 1

    def test_privilege_escalation_amplifies_severity(self):
        """Ring 3 → Ring 0 (distance 3) amplifies anomaly score vs same-ring."""
        detector_same = RingBreachDetector(
            window_seconds=60, baseline_rate=0.05
        )
        detector_escalate = RingBreachDetector(
            window_seconds=60, baseline_rate=0.05
        )

        breach_same = None
        breach_escalate = None
        for _ in range(20):
            r1 = detector_same.record_call(
                "did:example:a", "s1",
                ExecutionRing.RING_2_STANDARD,
                ExecutionRing.RING_2_STANDARD,
            )
            r2 = detector_escalate.record_call(
                "did:example:a", "s1",
                ExecutionRing.RING_3_SANDBOX,
                ExecutionRing.RING_0_ROOT,
            )
            if r1 is not None:
                breach_same = r1
            if r2 is not None:
                breach_escalate = r2

        assert breach_same is not None
        assert breach_escalate is not None
        assert breach_escalate.anomaly_score > breach_same.anomaly_score

    def test_breaker_trips_on_high_severity(self):
        """Circuit-breaker trips when HIGH or CRITICAL breach detected."""
        detector = RingBreachDetector(
            window_seconds=60, baseline_rate=0.01
        )

        assert detector.is_breaker_tripped("did:example:a", "s1") is False

        for _ in range(50):
            detector.record_call(
                "did:example:a", "s1",
                ExecutionRing.RING_3_SANDBOX,
                ExecutionRing.RING_0_ROOT,
            )

        assert detector.is_breaker_tripped("did:example:a", "s1") is True

    def test_breaker_reset(self):
        """reset_breaker() clears the trip and the call window."""
        detector = RingBreachDetector(
            window_seconds=60, baseline_rate=0.01
        )

        for _ in range(50):
            detector.record_call(
                "did:example:a", "s1",
                ExecutionRing.RING_3_SANDBOX,
                ExecutionRing.RING_0_ROOT,
            )
        assert detector.is_breaker_tripped("did:example:a", "s1") is True

        detector.reset_breaker("did:example:a", "s1")
        assert detector.is_breaker_tripped("did:example:a", "s1") is False

        result = detector.record_call(
            "did:example:a", "s1",
            ExecutionRing.RING_2_STANDARD,
            ExecutionRing.RING_2_STANDARD,
        )
        assert result is None
        assert detector.is_breaker_tripped("did:example:a", "s1") is False

    def test_breach_history_populated(self):
        """Breach events are stored in breach_history."""
        detector = RingBreachDetector(
            window_seconds=60, baseline_rate=0.01
        )
        for _ in range(20):
            detector.record_call(
                "did:example:a", "s1",
                ExecutionRing.RING_3_SANDBOX,
                ExecutionRing.RING_0_ROOT,
            )

        history = detector.breach_history
        assert len(history) >= 1
        assert all(isinstance(e, BreachEvent) for e in history)
        assert history is not detector._breach_history

    def test_breach_history_returns_copy(self):
        detector = RingBreachDetector()
        history = detector.breach_history
        assert history == []
        assert history is not detector._breach_history

    def test_bounded_event_storage(self):
        """Per-agent call window is bounded by max_events_per_agent."""
        detector = RingBreachDetector(
            window_seconds=3600,
            baseline_rate=100.0,
            max_events_per_agent=50,
        )
        for _ in range(200):
            detector.record_call(
                "did:example:a", "s1",
                ExecutionRing.RING_2_STANDARD,
                ExecutionRing.RING_2_STANDARD,
            )
        key = "did:example:a::s1"
        assert len(detector._call_windows[key]) <= 50

    def test_multiple_agents_independent(self):
        """Each agent has independent tracking and breaker state."""
        detector = RingBreachDetector(
            window_seconds=60, baseline_rate=0.01
        )

        for _ in range(50):
            detector.record_call(
                "did:example:agent1", "s1",
                ExecutionRing.RING_3_SANDBOX,
                ExecutionRing.RING_0_ROOT,
            )

        assert detector.is_breaker_tripped("did:example:agent1", "s1") is True
        assert detector.is_breaker_tripped("did:example:agent2", "s1") is False

    def test_reset_breaker_no_op_when_not_tripped(self):
        """Resetting a never-tripped breaker is a safe no-op."""
        detector = RingBreachDetector()
        detector.reset_breaker("did:example:a", "s1")
        assert detector.breach_count == 0
