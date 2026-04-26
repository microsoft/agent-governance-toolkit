# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for behavioral anomaly detection.

NOTE: Behavioral anomaly detection is implemented in the Agent SRE package
(agent_sre.anomaly.rogue_detector), not in Agent Mesh. The Agent SRE module
provides tool-call frequency analysis, action entropy scoring, and capability
profile violation detection. See agent-governance-python/agent-sre/tests/unit/test_rogue_detector.py
and agent-governance-python/agent-sre/tests/unit/test_anomaly_detection.py for the canonical tests
(72 tests covering all ASI-10 behavioral detection scenarios).
"""

import pytest

pytestmark = pytest.mark.skip(
    reason="Behavioral anomaly detection moved to agent-sre package; "
    "see agent-governance-python/agent-sre/tests/unit/test_rogue_detector.py"
)


class TestRapidFire:
    """Detect too many actions in a short window."""

    def test_no_anomaly_below_threshold(self):
        detector = BehavioralAnomalyDetector(rapid_fire_threshold=10, rapid_fire_window_seconds=5)
        for _ in range(5):
            anomalies = detector.observe("did:mesh:a1", "read")
        assert anomalies == []

    def test_rapid_fire_detected(self):
        detector = BehavioralAnomalyDetector(rapid_fire_threshold=5, rapid_fire_window_seconds=10)
        anomalies = []
        for _ in range(6):
            anomalies = detector.observe("did:mesh:a1", "read")
        # At least one rapid_fire anomaly should be detected
        rapid = [a for a in detector.check("did:mesh:a1") if a.anomaly_type == "rapid_fire"]
        assert len(rapid) >= 1
        assert rapid[0].severity == "high"
        assert "read" in rapid[0].description

    def test_different_actions_no_rapid_fire(self):
        detector = BehavioralAnomalyDetector(rapid_fire_threshold=5, rapid_fire_window_seconds=5)
        # Different actions should not trigger rapid_fire for any single action
        actions = ["read", "write", "delete", "list", "update"]
        for action in actions:
            detector.observe("did:mesh:a1", action)
        rapid = [a for a in detector.check("did:mesh:a1") if a.anomaly_type == "rapid_fire"]
        assert len(rapid) == 0


class TestActionDrift:
    """Detect agents using new actions after established baseline."""

    def test_no_drift_during_baseline(self):
        detector = BehavioralAnomalyDetector()
        # Under 50 observations — no drift detection yet
        for _ in range(30):
            detector.observe("did:mesh:a1", "read")
        anomalies = detector.observe("did:mesh:a1", "delete")
        drift = [a for a in anomalies if a.anomaly_type == "action_drift"]
        assert len(drift) == 0

    def test_drift_after_baseline(self):
        detector = BehavioralAnomalyDetector()
        # Build baseline
        for _ in range(60):
            detector.observe("did:mesh:a1", "read")
        # New action after baseline
        anomalies = detector.observe("did:mesh:a1", "delete_everything")
        drift = [a for a in anomalies if a.anomaly_type == "action_drift"]
        assert len(drift) == 1
        assert drift[0].severity == "medium"
        assert "delete_everything" in drift[0].description

    def test_known_action_no_drift(self):
        detector = BehavioralAnomalyDetector()
        for _ in range(30):
            detector.observe("did:mesh:a1", "read")
        for _ in range(30):
            detector.observe("did:mesh:a1", "write")
        # Using a known action should not trigger drift
        anomalies = detector.observe("did:mesh:a1", "read")
        drift = [a for a in anomalies if a.anomaly_type == "action_drift"]
        assert len(drift) == 0


class TestTrustDegradation:
    """Detect significant trust score drops."""

    def test_stable_trust_no_anomaly(self):
        detector = BehavioralAnomalyDetector()
        for _ in range(10):
            detector.observe("did:mesh:a1", "read", trust_score=0.85)
        trust = [a for a in detector.check("did:mesh:a1") if a.anomaly_type == "trust_degradation"]
        assert len(trust) == 0

    def test_trust_drop_detected(self):
        detector = BehavioralAnomalyDetector(trust_drop_threshold=0.15)
        # Good trust initially
        for _ in range(6):
            detector.observe("did:mesh:a1", "read", trust_score=0.90)
        # Then a significant drop
        for _ in range(3):
            anomalies = detector.observe("did:mesh:a1", "read", trust_score=0.60)
        trust = [a for a in detector.check("did:mesh:a1") if a.anomaly_type == "trust_degradation"]
        assert len(trust) >= 1
        assert trust[0].severity == "high"

    def test_gradual_decline_no_alert(self):
        detector = BehavioralAnomalyDetector(trust_drop_threshold=0.15)
        scores = [0.90, 0.88, 0.86, 0.84, 0.82, 0.80, 0.78, 0.77]
        for score in scores:
            detector.observe("did:mesh:a1", "read", trust_score=score)
        trust = [a for a in detector.check("did:mesh:a1") if a.anomaly_type == "trust_degradation"]
        assert len(trust) == 0  # Gradual decline < threshold


class TestAnomalyReport:
    def test_report_fields(self):
        report = AnomalyReport(
            agent_did="did:mesh:a1",
            anomaly_type="rapid_fire",
            severity="high",
            description="test",
            recommended_action="investigate",
        )
        assert report.agent_did == "did:mesh:a1"
        assert report.anomaly_type == "rapid_fire"
        assert report.detected_at  # auto-populated


class TestDetectorManagement:
    def test_summary(self):
        detector = BehavioralAnomalyDetector()
        detector.observe("did:mesh:a1", "read")
        s = detector.summary()
        assert s["agents_tracked"] == 1
        assert "total_anomalies" in s

    def test_clear_anomalies(self):
        detector = BehavioralAnomalyDetector(rapid_fire_threshold=3, rapid_fire_window_seconds=10)
        for _ in range(5):
            detector.observe("did:mesh:a1", "read")
        assert len(detector.check("did:mesh:a1")) > 0
        detector.clear_anomalies("did:mesh:a1")
        assert len(detector.check("did:mesh:a1")) == 0

    def test_get_profile(self):
        detector = BehavioralAnomalyDetector()
        detector.observe("did:mesh:a1", "read")
        profile = detector.get_profile("did:mesh:a1")
        assert profile is not None
        assert profile.total_observations == 1
        assert profile.action_counts["read"] == 1

    def test_nonexistent_profile(self):
        detector = BehavioralAnomalyDetector()
        assert detector.get_profile("did:mesh:unknown") is None

    def test_multiple_agents(self):
        detector = BehavioralAnomalyDetector()
        detector.observe("did:mesh:a1", "read")
        detector.observe("did:mesh:a2", "write")
        assert detector.summary()["agents_tracked"] == 2
        assert len(detector.check("did:mesh:a1")) == 0
        assert len(detector.check("did:mesh:a2")) == 0

    def test_get_all_anomalies_by_severity(self):
        detector = BehavioralAnomalyDetector(rapid_fire_threshold=3, rapid_fire_window_seconds=10)
        for _ in range(5):
            detector.observe("did:mesh:a1", "read")
        high = detector.get_all_anomalies(severity="high")
        low = detector.get_all_anomalies(severity="low")
        assert all(a.severity == "high" for a in high)
        assert all(a.severity == "low" for a in low)
