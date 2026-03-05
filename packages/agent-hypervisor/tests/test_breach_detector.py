# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for ring breach detector."""

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
        assert detector.breach_count == 0
        assert detector.breach_history == []

    def test_init_custom_window(self):
        detector = RingBreachDetector(window_seconds=120)
        assert detector.window_seconds == 120

    def test_record_call_returns_none(self):
        """Community edition never detects a breach."""
        detector = RingBreachDetector()
        result = detector.record_call(
            agent_did="did:example:agent1",
            session_id="sess-1",
            agent_ring=ExecutionRing.RING_3_SANDBOX,
            called_ring=ExecutionRing.RING_0_ROOT,
        )
        assert result is None

    def test_is_breaker_tripped_always_false(self):
        detector = RingBreachDetector()
        assert detector.is_breaker_tripped("did:example:a", "s1") is False

    def test_reset_breaker_no_op(self):
        detector = RingBreachDetector()
        detector.reset_breaker("did:example:a", "s1")
        assert detector.breach_count == 0

    def test_breach_history_returns_copy(self):
        detector = RingBreachDetector()
        history = detector.breach_history
        assert history == []
        assert history is not detector._breach_history

    def test_multiple_record_calls_still_safe(self):
        """Multiple calls should all return None in community edition."""
        detector = RingBreachDetector()
        for _ in range(100):
            result = detector.record_call(
                agent_did="did:example:agent1",
                session_id="s1",
                agent_ring=ExecutionRing.RING_2_STANDARD,
                called_ring=ExecutionRing.RING_1_PRIVILEGED,
            )
            assert result is None
        assert detector.breach_count == 0
