# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for incident detection and response."""

import time

from agent_sre.incidents.detector import (
    Incident,
    IncidentDetector,
    IncidentSeverity,
    IncidentState,
    Signal,
    SignalType,
)


class TestSignal:
    def test_severity_hint_critical(self) -> None:
        s = Signal(signal_type=SignalType.POLICY_VIOLATION, source="bot-1")
        assert s.severity_hint == IncidentSeverity.P1

    def test_severity_hint_warning(self) -> None:
        s = Signal(signal_type=SignalType.SLO_BREACH, source="bot-1")
        assert s.severity_hint == IncidentSeverity.P2

    def test_severity_hint_low(self) -> None:
        s = Signal(signal_type=SignalType.TOOL_FAILURE_SPIKE, source="bot-1")
        assert s.severity_hint == IncidentSeverity.P3

    def test_to_dict(self) -> None:
        s = Signal(signal_type=SignalType.COST_ANOMALY, source="bot-1", message="cost spike")
        d = s.to_dict()
        assert d["type"] == "cost_anomaly"
        assert d["source"] == "bot-1"


class TestIncident:
    def test_lifecycle(self) -> None:
        inc = Incident(title="SLO breach", severity=IncidentSeverity.P2, agent_id="bot-1")
        assert inc.state == IncidentState.DETECTED

        inc.acknowledge()
        assert inc.state == IncidentState.ACKNOWLEDGED

        inc.investigate()
        assert inc.state == IncidentState.INVESTIGATING

        inc.mitigate()
        assert inc.state == IncidentState.MITIGATING

        inc.resolve(note="Fixed by rollback")
        assert inc.state == IncidentState.RESOLVED
        assert inc.resolved_at is not None
        assert "Fixed by rollback" in inc.notes

    def test_add_action(self) -> None:
        inc = Incident(title="test", severity=IncidentSeverity.P1)
        action = inc.add_action("auto_rollback", result="rolled back to v2")
        assert action.executed is True
        assert len(inc.actions) == 1

    def test_duration(self) -> None:
        inc = Incident(title="test", severity=IncidentSeverity.P1)
        assert inc.duration_seconds >= 0

    def test_to_dict(self) -> None:
        inc = Incident(title="test", severity=IncidentSeverity.P2, agent_id="bot-1")
        d = inc.to_dict()
        assert d["title"] == "test"
        assert d["severity"] == "p2"
        assert d["agent_id"] == "bot-1"


class TestIncidentDetector:
    def test_critical_signal_creates_incident(self) -> None:
        detector = IncidentDetector()
        signal = Signal(
            signal_type=SignalType.POLICY_VIOLATION,
            source="bot-1",
            message="blocked write to /etc",
        )
        incident = detector.ingest_signal(signal)
        assert incident is not None
        assert incident.severity == IncidentSeverity.P1
        assert len(incident.signals) == 1

    def test_warning_signal_creates_incident(self) -> None:
        detector = IncidentDetector()
        signal = Signal(signal_type=SignalType.SLO_BREACH, source="bot-1", message="success rate < 99%")
        incident = detector.ingest_signal(signal)
        assert incident is not None
        assert incident.severity == IncidentSeverity.P2

    def test_deduplication(self) -> None:
        detector = IncidentDetector()
        s1 = Signal(signal_type=SignalType.POLICY_VIOLATION, source="bot-1", message="violation 1")
        s2 = Signal(signal_type=SignalType.POLICY_VIOLATION, source="bot-1", message="violation 2")
        inc1 = detector.ingest_signal(s1)
        inc2 = detector.ingest_signal(s2)
        assert inc1 is not None
        assert inc2 is None  # Deduplicated

    def test_auto_response(self) -> None:
        detector = IncidentDetector()
        detector.register_response("policy_violation", ["auto_rollback", "circuit_breaker"])
        signal = Signal(signal_type=SignalType.POLICY_VIOLATION, source="bot-1")
        incident = detector.ingest_signal(signal)
        assert incident is not None
        action_types = [a.action_type for a in incident.actions]
        assert "auto_rollback" in action_types
        assert "circuit_breaker" in action_types

    def test_open_incidents(self) -> None:
        detector = IncidentDetector()
        signal = Signal(signal_type=SignalType.TRUST_REVOCATION, source="bot-1")
        incident = detector.ingest_signal(signal)
        assert incident is not None
        assert len(detector.open_incidents) == 1

        incident.resolve()
        assert len(detector.open_incidents) == 0

    def test_summary(self) -> None:
        detector = IncidentDetector()
        detector.ingest_signal(Signal(signal_type=SignalType.POLICY_VIOLATION, source="bot-1"))
        s = detector.summary()
        assert s["total_incidents"] == 1
        assert s["open_incidents"] == 1
        assert s["by_severity"]["p1"] == 1


class TestIncidentCorrelation:
    """Signals from one source within the correlation window form one incident."""

    def test_correlated_signals_join_one_incident(self) -> None:
        detector = IncidentDetector(correlation_window_seconds=300)
        first = detector.ingest_signal(Signal(signal_type=SignalType.SLO_BREACH, source="bot-1"))
        second = detector.ingest_signal(Signal(signal_type=SignalType.COST_ANOMALY, source="bot-1"))
        third = detector.ingest_signal(Signal(signal_type=SignalType.LATENCY_SPIKE, source="bot-1"))

        assert first is not None
        assert second is None  # joined the open incident, no new one
        assert third is None
        assert detector.all_incidents == [first]
        assert [s.signal_type for s in first.signals] == [
            SignalType.SLO_BREACH,
            SignalType.COST_ANOMALY,
            SignalType.LATENCY_SPIKE,
        ]
        assert first.title == "Correlated: cost_anomaly, latency_spike, slo_breach from bot-1"

    def test_correlated_signal_runs_each_action_once(self) -> None:
        detector = IncidentDetector()
        detector.register_response("slo_breach", ["manual_rollback", "notify_oncall"])
        detector.register_response("cost_anomaly", ["throttle_agent", "notify_oncall"])
        incident = detector.ingest_signal(Signal(signal_type=SignalType.SLO_BREACH, source="bot-1"))
        detector.ingest_signal(Signal(signal_type=SignalType.COST_ANOMALY, source="bot-1"))

        assert incident is not None
        assert [a.action_type for a in incident.actions] == [
            "manual_rollback",
            "notify_oncall",
            "throttle_agent",
        ]

    def test_correlated_signal_raises_incident_severity(self) -> None:
        detector = IncidentDetector()
        incident = detector.ingest_signal(Signal(signal_type=SignalType.SLO_BREACH, source="bot-1"))
        assert incident is not None
        assert incident.severity == IncidentSeverity.P2

        detector.ingest_signal(Signal(signal_type=SignalType.TRUST_REVOCATION, source="bot-1"))

        assert incident.severity == IncidentSeverity.P1

    def test_signal_after_resolution_opens_incident_without_handled_signals(self) -> None:
        detector = IncidentDetector()
        detector.register_response("slo_breach", ["manual_rollback"])
        first = detector.ingest_signal(Signal(signal_type=SignalType.SLO_BREACH, source="bot-1"))
        assert first is not None
        first.resolve()

        second = detector.ingest_signal(Signal(signal_type=SignalType.COST_ANOMALY, source="bot-1"))

        assert second is not None
        assert [s.signal_type for s in second.signals] == [SignalType.COST_ANOMALY]
        assert "manual_rollback" not in [a.action_type for a in second.actions]

    def test_signal_outside_correlation_window_opens_new_incident(self) -> None:
        detector = IncidentDetector(correlation_window_seconds=300)
        old = Signal(signal_type=SignalType.SLO_BREACH, source="bot-1", timestamp=time.time() - 400)
        first = detector.ingest_signal(old)

        second = detector.ingest_signal(Signal(signal_type=SignalType.COST_ANOMALY, source="bot-1"))

        assert first is not None
        assert second is not None
        assert [s.signal_type for s in second.signals] == [SignalType.COST_ANOMALY]

    def test_signals_from_different_sources_stay_separate(self) -> None:
        detector = IncidentDetector()
        a = detector.ingest_signal(Signal(signal_type=SignalType.SLO_BREACH, source="bot-1"))
        b = detector.ingest_signal(Signal(signal_type=SignalType.COST_ANOMALY, source="bot-2"))

        assert a is not None
        assert b is not None
        assert len(detector.open_incidents) == 2
