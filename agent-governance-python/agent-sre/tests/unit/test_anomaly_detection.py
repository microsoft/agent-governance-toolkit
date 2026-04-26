# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for behavioral anomaly detection module."""

from agent_sre.anomaly.detector import (
    AnomalyAlert,
    AnomalyDetector,
    AnomalySeverity,
    AnomalyType,
    BehaviorBaseline,
    DetectorConfig,
    _infer_anomaly_type,
)
from agent_sre.anomaly.strategies import (
    ResourceStrategy,
    SequentialStrategy,
    StatisticalStrategy,
)

# ── DetectorConfig ──────────────────────────────────────────────────

class TestDetectorConfig:
    def test_defaults(self) -> None:
        cfg = DetectorConfig()
        assert cfg.window_size == 1000
        assert cfg.z_threshold == 2.5
        assert cfg.iqr_multiplier == 1.5
        assert cfg.min_samples == 20
        assert "statistical" in cfg.enabled_strategies

    def test_custom_config(self) -> None:
        cfg = DetectorConfig(window_size=500, z_threshold=3.0, min_samples=10)
        assert cfg.window_size == 500
        assert cfg.z_threshold == 3.0
        assert cfg.min_samples == 10


# ── BehaviorBaseline ────────────────────────────────────────────────

class TestBehaviorBaseline:
    def test_defaults(self) -> None:
        b = BehaviorBaseline()
        assert b.mean == 0.0
        assert b.std_dev == 0.0
        assert b.sample_count == 0

    def test_to_dict(self) -> None:
        b = BehaviorBaseline(mean=1.5, std_dev=0.3, sample_count=100, min_val=0.5, max_val=3.0)
        d = b.to_dict()
        assert d["mean"] == 1.5
        assert d["sample_count"] == 100

    def test_baseline_computed_by_detector(self) -> None:
        det = AnomalyDetector(DetectorConfig(min_samples=5))
        for v in [1.0, 2.0, 3.0, 4.0, 5.0]:
            det.ingest("metric_a", v)
        bl = det.get_baseline("metric_a")
        assert bl is not None
        assert bl.sample_count == 5
        assert bl.min_val == 1.0
        assert bl.max_val == 5.0
        assert abs(bl.mean - 3.0) < 0.01

    def test_baseline_percentiles(self) -> None:
        det = AnomalyDetector(DetectorConfig(min_samples=5))
        for v in range(1, 101):
            det.ingest("pct_metric", float(v))
        bl = det.get_baseline("pct_metric")
        assert bl is not None
        assert bl.p95 >= 90.0
        assert bl.p99 >= 95.0


# ── StatisticalStrategy ─────────────────────────────────────────────

class TestStatisticalStrategy:
    def test_zscore_normal(self) -> None:
        s = StatisticalStrategy(z_threshold=2.5)
        is_a, z = s.check_zscore(10.0, mean=10.0, std_dev=1.0)
        assert is_a is False
        assert z == 0.0

    def test_zscore_anomaly(self) -> None:
        s = StatisticalStrategy(z_threshold=2.5)
        is_a, z = s.check_zscore(15.0, mean=10.0, std_dev=1.0)
        assert is_a is True
        assert z == 5.0

    def test_zscore_zero_std(self) -> None:
        s = StatisticalStrategy()
        is_a, z = s.check_zscore(5.0, mean=5.0, std_dev=0.0)
        assert is_a is False
        assert z == 0.0

    def test_iqr_normal(self) -> None:
        s = StatisticalStrategy(iqr_multiplier=1.5)
        vals = list(range(1, 101))
        is_a, dist = s.check_iqr(50.0, vals)
        assert is_a is False

    def test_iqr_outlier(self) -> None:
        s = StatisticalStrategy(iqr_multiplier=1.5)
        vals = list(range(1, 101))
        is_a, dist = s.check_iqr(500.0, vals)
        assert is_a is True
        assert dist > 0

    def test_iqr_too_few_values(self) -> None:
        s = StatisticalStrategy()
        is_a, dist = s.check_iqr(10.0, [1.0, 2.0])
        assert is_a is False

    def test_severity_info(self) -> None:
        s = StatisticalStrategy()
        assert s.determine_severity(2.0) == AnomalySeverity.INFO

    def test_severity_warning(self) -> None:
        s = StatisticalStrategy()
        assert s.determine_severity(3.5) == AnomalySeverity.WARNING

    def test_severity_critical(self) -> None:
        s = StatisticalStrategy()
        assert s.determine_severity(5.0) == AnomalySeverity.CRITICAL


# ── SequentialStrategy ───────────────────────────────────────────────

class TestSequentialStrategy:
    def test_empty_sequence(self) -> None:
        s = SequentialStrategy()
        is_a, score, msg = s.check_sequence([], "tool_a")
        assert is_a is False

    def test_insufficient_data(self) -> None:
        s = SequentialStrategy(min_pattern_frequency=5)
        seq = ["a", "b"]
        is_a, score, msg = s.check_sequence(seq, "c")
        assert is_a is False
        assert "insufficient" in msg

    def test_common_transition_ok(self) -> None:
        s = SequentialStrategy(min_pattern_frequency=3)
        seq = ["a", "b", "a", "b", "a", "b", "a"]
        is_a, score, msg = s.check_sequence(seq, "b")
        assert is_a is False

    def test_rare_transition_detected(self) -> None:
        s = SequentialStrategy(min_pattern_frequency=3)
        # Build a strong a->b pattern, then check a->z (never seen)
        seq = ["a", "b", "a", "b", "a", "b", "a"]
        is_a, score, msg = s.check_sequence(seq, "z")
        assert is_a is True
        assert score > 0
        assert "never seen" in msg


# ── ResourceStrategy ────────────────────────────────────────────────

class TestResourceStrategy:
    def test_no_limits(self) -> None:
        r = ResourceStrategy()
        bl = BehaviorBaseline(p99=10.0, sample_count=50)
        is_a, score = r.check_resource("latency", 12.0, bl)
        assert is_a is False

    def test_token_budget_exceeded(self) -> None:
        r = ResourceStrategy(token_budget=1000)
        bl = BehaviorBaseline(p99=500.0, sample_count=50)
        is_a, score = r.check_resource("token_usage", 1500.0, bl)
        assert is_a is True
        assert score > 1.0

    def test_api_rate_limit(self) -> None:
        r = ResourceStrategy(api_rate_limit=100)
        bl = BehaviorBaseline(p99=80.0, sample_count=50)
        is_a, score = r.check_resource("api_calls", 150.0, bl)
        assert is_a is True

    def test_p99_breach(self) -> None:
        r = ResourceStrategy()
        bl = BehaviorBaseline(p99=10.0, sample_count=50)
        # value > p99 * 1.5
        is_a, score = r.check_resource("token_count", 20.0, bl)
        assert is_a is True

    def test_within_p99(self) -> None:
        r = ResourceStrategy()
        bl = BehaviorBaseline(p99=10.0, sample_count=50)
        is_a, score = r.check_resource("token_count", 12.0, bl)
        assert is_a is False


# ── AnomalyDetector (integration) ───────────────────────────────────

class TestAnomalyDetector:
    def test_normal_values_no_alert(self) -> None:
        det = AnomalyDetector(DetectorConfig(min_samples=10))
        for v in [1.0] * 30:
            result = det.ingest("stable_metric", v)
        # All identical values → std_dev == 0 → no alert
        assert result is None
        assert len(det.alerts) == 0

    def test_anomalous_value_triggers_alert(self) -> None:
        det = AnomalyDetector(DetectorConfig(min_samples=10, z_threshold=2.0))
        for v in [10.0] * 25:
            det.ingest("latency", v)
        # Inject spike
        alert = det.ingest("latency", 100.0)
        assert alert is not None
        assert alert.anomaly_type == AnomalyType.LATENCY_SPIKE
        assert alert.score > 2.0

    def test_multiple_metrics_independent(self) -> None:
        det = AnomalyDetector(DetectorConfig(min_samples=5))
        for v in [1.0] * 10:
            det.ingest("metric_a", v)
            det.ingest("metric_b", v * 100)
        bl_a = det.get_baseline("metric_a")
        bl_b = det.get_baseline("metric_b")
        assert bl_a is not None
        assert bl_b is not None
        assert abs(bl_a.mean - 1.0) < 0.01
        assert abs(bl_b.mean - 100.0) < 0.01

    def test_min_samples_respected(self) -> None:
        det = AnomalyDetector(DetectorConfig(min_samples=20))
        for _i in range(15):
            alert = det.ingest("latency", 10.0)
        # Not enough samples yet — even a spike should not alert
        alert = det.ingest("latency", 999.0)
        assert alert is None

    def test_tool_call_sequence_tracking(self) -> None:
        det = AnomalyDetector()
        for _ in range(10):
            det.record_tool_call("agent-1", "search")
            det.record_tool_call("agent-1", "read")
        # Known pattern: search → read.  Now introduce novel transition.
        det.record_tool_call("agent-1", "delete")
        # May or may not trigger depending on min_pattern_frequency, but
        # sequence buffer should be populated.
        buf = det._sequence_buffer.get("agent-1")
        assert buf is not None
        assert "delete" in buf

    def test_alert_history(self) -> None:
        det = AnomalyDetector(DetectorConfig(min_samples=10, z_threshold=2.0))
        for v in [5.0] * 20:
            det.ingest("latency", v)
        det.ingest("latency", 500.0)
        assert len(det.alerts) >= 1
        assert det.alerts[0].anomaly_type == AnomalyType.LATENCY_SPIKE

    def test_summary(self) -> None:
        det = AnomalyDetector(DetectorConfig(min_samples=10, z_threshold=2.0))
        for v in [5.0] * 20:
            det.ingest("latency", v)
        det.ingest("latency", 500.0)
        s = det.summary()
        assert s["total_alerts"] >= 1
        assert s["baselines_count"] >= 1
        assert isinstance(s["alerts_by_type"], dict)
        assert isinstance(s["alerts_by_severity"], dict)

    def test_reset_single_metric(self) -> None:
        det = AnomalyDetector(DetectorConfig(min_samples=5))
        for v in [1.0] * 10:
            det.ingest("m1", v)
            det.ingest("m2", v)
        det.reset("m1")
        assert det.get_baseline("m1") is None
        assert det.get_baseline("m2") is not None

    def test_reset_all(self) -> None:
        det = AnomalyDetector(DetectorConfig(min_samples=5))
        for v in [1.0] * 10:
            det.ingest("m1", v)
        det.ingest("m1", 999.0)
        assert len(det.alerts) >= 0  # may or may not have alerts
        det.reset()
        assert det.get_baseline("m1") is None
        assert len(det.alerts) == 0

    def test_get_baseline_missing(self) -> None:
        det = AnomalyDetector()
        assert det.get_baseline("nonexistent") is None

    def test_alert_to_dict(self) -> None:
        alert = AnomalyAlert(
            anomaly_type=AnomalyType.LATENCY_SPIKE,
            severity=AnomalySeverity.WARNING,
            score=3.5,
            message="test",
            agent_id="a1",
        )
        d = alert.to_dict()
        assert d["anomaly_type"] == "latency_spike"
        assert d["severity"] == "warning"
        assert d["agent_id"] == "a1"


# ── Severity levels ─────────────────────────────────────────────────

class TestSeverityLevels:
    def test_info_severity(self) -> None:
        s = StatisticalStrategy()
        assert s.determine_severity(1.0) == AnomalySeverity.INFO
        assert s.determine_severity(2.9) == AnomalySeverity.INFO

    def test_warning_severity(self) -> None:
        s = StatisticalStrategy()
        assert s.determine_severity(3.0) == AnomalySeverity.WARNING
        assert s.determine_severity(4.0) == AnomalySeverity.WARNING

    def test_critical_severity(self) -> None:
        s = StatisticalStrategy()
        assert s.determine_severity(4.1) == AnomalySeverity.CRITICAL
        assert s.determine_severity(10.0) == AnomalySeverity.CRITICAL

    def test_boundary_values(self) -> None:
        s = StatisticalStrategy()
        # Exactly 3.0 → WARNING
        assert s.determine_severity(3.0) == AnomalySeverity.WARNING
        # Exactly 4.0 → WARNING (> 4.0 is CRITICAL)
        assert s.determine_severity(4.0) == AnomalySeverity.WARNING


# ── Anomaly type inference ──────────────────────────────────────────

class TestAnomalyTypeInference:
    def test_latency(self) -> None:
        assert _infer_anomaly_type("request_latency") == AnomalyType.LATENCY_SPIKE

    def test_duration(self) -> None:
        assert _infer_anomaly_type("task_duration") == AnomalyType.LATENCY_SPIKE

    def test_error(self) -> None:
        assert _infer_anomaly_type("error_count") == AnomalyType.ERROR_RATE_SURGE

    def test_token(self) -> None:
        assert _infer_anomaly_type("token_usage") == AnomalyType.TOKEN_USAGE_SPIKE

    def test_api(self) -> None:
        assert _infer_anomaly_type("api_calls") == AnomalyType.API_CALL_VOLUME

    def test_fallback(self) -> None:
        assert _infer_anomaly_type("something_random") == AnomalyType.OUTPUT_DRIFT
