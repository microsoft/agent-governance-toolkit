"""
Unit tests for CMVK enhanced features (v0.2.0).

Tests for:
    - CMVK-001: Euclidean Distance Support
    - CMVK-002: Configurable Distance Metrics
    - CMVK-003: Metric Selection API
    - CMVK-004: Batch Verification
    - CMVK-005: Threshold Profiles
    - CMVK-006: Verification Audit Trail
    - CMVK-008: Dimensional Weighting
    - CMVK-010: Explainable Drift
"""

import tempfile
from datetime import UTC
from pathlib import Path

import numpy as np
import pytest

from cmvk import (  # Core; Metrics (CMVK-001/002/003); Profiles (CMVK-005); Audit (CMVK-006)
    AuditTrail,
    DistanceMetric,
    VerificationScore,
    aggregate_embedding_scores,
    calculate_distance,
    calculate_weighted_distance,
    create_profile,
    get_available_metrics,
    get_profile,
    list_profiles,
    verify_embeddings,
    verify_embeddings_batch,
)


class TestDistanceMetrics:
    """Tests for distance metric calculations (CMVK-001/002)."""

    def test_euclidean_distance_basic(self):
        """Euclidean distance should be calculated correctly."""
        vec_a = np.array([0.0, 0.0])
        vec_b = np.array([3.0, 4.0])

        result = calculate_distance(vec_a, vec_b, metric="euclidean")

        assert result.metric == DistanceMetric.EUCLIDEAN
        assert result.distance == pytest.approx(5.0, rel=1e-6)

    def test_euclidean_preserves_magnitude(self):
        """Euclidean distance should detect magnitude differences that cosine misses."""
        # Same direction, different magnitude
        vec_a = np.array([0.82, 150.0])  # Claimed NDVI, carbon
        vec_b = np.array([0.316, 95.0])  # Observed (61% NDVI discrepancy)

        cosine_result = calculate_distance(vec_a, vec_b, metric="cosine")
        euclidean_result = calculate_distance(vec_a, vec_b, metric="euclidean")

        # Cosine similarity is high because vectors point in similar direction
        assert cosine_result.normalized < 0.1, "Cosine distance should be low"

        # Euclidean distance catches the magnitude difference
        assert euclidean_result.distance > 50, "Euclidean should detect large magnitude diff"
        assert euclidean_result.normalized > cosine_result.normalized

    def test_cosine_distance_basic(self):
        """Cosine distance should be calculated correctly."""
        vec_a = np.array([1.0, 0.0])
        vec_b = np.array([0.0, 1.0])  # Orthogonal

        result = calculate_distance(vec_a, vec_b, metric="cosine")

        assert result.metric == DistanceMetric.COSINE
        assert result.distance == pytest.approx(1.0, rel=1e-6)  # 1 = orthogonal

    def test_manhattan_distance_basic(self):
        """Manhattan distance should be sum of absolute differences."""
        vec_a = np.array([1.0, 2.0, 3.0])
        vec_b = np.array([4.0, 1.0, 5.0])

        result = calculate_distance(vec_a, vec_b, metric="manhattan")

        # |4-1| + |1-2| + |5-3| = 3 + 1 + 2 = 6
        assert result.metric == DistanceMetric.MANHATTAN
        assert result.distance == pytest.approx(6.0, rel=1e-6)

    def test_chebyshev_distance_basic(self):
        """Chebyshev distance should be max absolute difference."""
        vec_a = np.array([1.0, 2.0, 3.0])
        vec_b = np.array([4.0, 1.0, 5.0])

        result = calculate_distance(vec_a, vec_b, metric="chebyshev")

        # max(|4-1|, |1-2|, |5-3|) = max(3, 1, 2) = 3
        assert result.metric == DistanceMetric.CHEBYSHEV
        assert result.distance == pytest.approx(3.0, rel=1e-6)

    def test_mahalanobis_distance_identity(self):
        """Mahalanobis with identity covariance equals Euclidean."""
        vec_a = np.array([0.0, 0.0])
        vec_b = np.array([3.0, 4.0])

        mahal_result = calculate_distance(vec_a, vec_b, metric="mahalanobis")
        eucl_result = calculate_distance(vec_a, vec_b, metric="euclidean")

        assert mahal_result.distance == pytest.approx(eucl_result.distance, rel=1e-6)

    def test_available_metrics(self):
        """get_available_metrics should return all supported metrics."""
        metrics = get_available_metrics()

        assert "cosine" in metrics
        assert "euclidean" in metrics
        assert "manhattan" in metrics
        assert "chebyshev" in metrics
        assert "mahalanobis" in metrics
        assert len(metrics) == 5

    def test_invalid_metric_raises(self):
        """Unknown metric should raise ValueError."""
        vec_a = np.array([1.0, 2.0])
        vec_b = np.array([3.0, 4.0])

        with pytest.raises(ValueError, match="Unknown metric"):
            calculate_distance(vec_a, vec_b, metric="invalid")


class TestMetricSelectionAPI:
    """Tests for metric selection in verify_embeddings (CMVK-003)."""

    def test_default_metric_is_cosine(self):
        """Default metric should be cosine."""
        vec_a = np.array([1.0, 0.0])
        vec_b = np.array([0.0, 1.0])

        score = verify_embeddings(vec_a, vec_b)

        assert score.details["metric"] == "cosine"

    def test_euclidean_metric_selection(self):
        """Should use euclidean when specified."""
        vec_a = np.array([0.82, 150.0])
        vec_b = np.array([0.316, 95.0])

        score = verify_embeddings(vec_a, vec_b, metric="euclidean")

        assert score.details["metric"] == "euclidean"
        assert "raw_distance" in score.details

    def test_all_metrics_work(self):
        """All supported metrics should work in verify_embeddings."""
        vec_a = np.array([1.0, 2.0, 3.0])
        vec_b = np.array([2.0, 3.0, 4.0])

        for metric in get_available_metrics():
            score = verify_embeddings(vec_a, vec_b, metric=metric)
            assert score.details["metric"] == metric


class TestDimensionalWeighting:
    """Tests for dimensional weighting (CMVK-008)."""

    def test_weighted_euclidean_basic(self):
        """Weighted Euclidean should weight dimensions differently."""
        vec_a = np.array([1.0, 1.0])
        vec_b = np.array([2.0, 2.0])  # Equal diff in both dimensions

        # Weight first dimension more
        result = calculate_weighted_distance(vec_a, vec_b, weights=[2.0, 0.5], metric="euclidean")

        assert result.details.get("weighted") is True

    def test_weights_in_verify_embeddings(self):
        """verify_embeddings should accept weights parameter."""
        vec_a = np.array([0.82, 150.0])
        vec_b = np.array([0.316, 95.0])

        # NDVI (dimension 0) weighted higher
        score = verify_embeddings(vec_a, vec_b, metric="euclidean", weights=[0.6, 0.4])

        assert score.drift_score > 0

    def test_weight_mismatch_raises(self):
        """Mismatched weight length should raise."""
        vec_a = np.array([1.0, 2.0, 3.0])
        vec_b = np.array([2.0, 3.0, 4.0])

        with pytest.raises(ValueError, match="Weight length"):
            calculate_weighted_distance(vec_a, vec_b, weights=[0.5, 0.5])  # 2 != 3


class TestThresholdProfiles:
    """Tests for threshold profiles (CMVK-005)."""

    def test_list_profiles(self):
        """Should list all available profiles."""
        profiles = list_profiles()

        assert "general" in profiles
        assert "carbon" in profiles
        assert "financial" in profiles
        assert "medical" in profiles
        assert "strict" in profiles
        assert "lenient" in profiles

    def test_get_carbon_profile(self):
        """Carbon profile should have specific settings."""
        profile = get_profile("carbon")

        assert profile.name == "carbon"
        assert profile.drift_threshold == 0.15
        assert profile.default_metric == "euclidean"
        assert profile.flags.get("fraud_detection_mode") is True

    def test_get_financial_profile(self):
        """Financial profile should be very strict."""
        profile = get_profile("financial")

        assert profile.name == "financial"
        assert profile.drift_threshold == 0.10
        assert profile.default_metric == "chebyshev"
        assert profile.confidence_threshold >= 0.90

    def test_profile_is_within_threshold(self):
        """Profile should correctly evaluate pass/fail."""
        profile = get_profile("carbon")

        assert profile.is_within_threshold(0.10, 0.90) is True
        assert profile.is_within_threshold(0.20, 0.90) is False  # Over drift
        assert profile.is_within_threshold(0.10, 0.50) is False  # Under confidence

    def test_profile_severity_classification(self):
        """Profile should classify severity levels."""
        profile = get_profile("carbon")  # threshold = 0.15

        assert profile.get_severity(0.10) == "pass"
        assert profile.get_severity(0.20) == "warning"  # 1.33x
        assert profile.get_severity(0.25) == "critical"  # 1.67x
        assert profile.get_severity(0.50) == "severe"  # 3.33x

    def test_verify_embeddings_with_profile(self):
        """verify_embeddings should use profile settings."""
        vec_a = np.array([0.82, 150.0])
        vec_b = np.array([0.80, 145.0])  # Small difference

        score = verify_embeddings(vec_a, vec_b, threshold_profile="carbon")

        assert score.details["metric"] == "euclidean"  # From carbon profile
        assert "profile" in score.details
        assert score.details["profile"]["name"] == "carbon"

    def test_create_custom_profile(self):
        """Should be able to create custom profiles."""
        profile = create_profile(
            name="my_domain",
            drift_threshold=0.25,
            confidence_threshold=0.80,
            default_metric="manhattan",
            description="Custom profile",
        )

        assert profile.name == "my_domain"
        assert profile.drift_threshold == 0.25
        assert profile.default_metric == "manhattan"

    def test_invalid_profile_raises(self):
        """Unknown profile name should raise."""
        with pytest.raises(ValueError, match="Unknown profile"):
            get_profile("nonexistent")


class TestBatchVerification:
    """Tests for batch verification (CMVK-004)."""

    def test_batch_verification_basic(self):
        """Batch verification should process multiple pairs."""
        embeddings_a = [
            np.array([1.0, 0.0]),
            np.array([0.0, 1.0]),
            np.array([1.0, 1.0]),
        ]
        embeddings_b = [
            np.array([1.0, 0.0]),  # Identical
            np.array([0.0, 1.1]),  # Small diff
            np.array([0.5, 0.5]),  # Different
        ]

        scores = verify_embeddings_batch(embeddings_a, embeddings_b)

        assert len(scores) == 3
        assert scores[0].drift_score == pytest.approx(0.0, abs=0.01)
        assert all(isinstance(s, VerificationScore) for s in scores)

    def test_batch_with_metric(self):
        """Batch should apply same metric to all pairs."""
        embeddings_a = [np.array([1.0, 2.0]), np.array([3.0, 4.0])]
        embeddings_b = [np.array([2.0, 3.0]), np.array([4.0, 5.0])]

        scores = verify_embeddings_batch(embeddings_a, embeddings_b, metric="euclidean")

        for score in scores:
            assert score.details["metric"] == "euclidean"

    def test_batch_length_mismatch_raises(self):
        """Mismatched batch lengths should raise."""
        embeddings_a = [np.array([1.0]), np.array([2.0])]
        embeddings_b = [np.array([1.0])]

        with pytest.raises(ValueError, match="Length mismatch"):
            verify_embeddings_batch(embeddings_a, embeddings_b)

    def test_aggregate_embedding_scores(self):
        """Should aggregate batch results with statistics."""
        embeddings_a = [
            np.array([1.0, 0.0]),
            np.array([0.0, 1.0]),
            np.array([1.0, 1.0]),
        ]
        embeddings_b = [
            np.array([1.0, 0.0]),
            np.array([0.5, 0.5]),
            np.array([0.0, 0.0]),
        ]

        scores = verify_embeddings_batch(embeddings_a, embeddings_b)
        summary = aggregate_embedding_scores(scores)

        assert summary["count"] == 3
        assert "mean_drift" in summary
        assert "std_drift" in summary
        assert "pass_rate" in summary

    def test_aggregate_with_profile(self):
        """Aggregation should include severity distribution with profile."""
        embeddings_a = [np.array([1.0, 2.0]) for _ in range(5)]
        embeddings_b = [np.array([1.0 + i * 0.1, 2.0]) for i in range(5)]

        scores = verify_embeddings_batch(embeddings_a, embeddings_b, metric="euclidean")
        summary = aggregate_embedding_scores(scores, threshold_profile="carbon")

        assert "severity_distribution" in summary
        assert summary["profile_used"] == "carbon"


class TestExplainableDrift:
    """Tests for explainable drift (CMVK-010)."""

    def test_explanation_when_requested(self):
        """Should include explanation when explain=True."""
        vec_a = np.array([0.82, 150.0])
        vec_b = np.array([0.316, 95.0])

        score = verify_embeddings(vec_a, vec_b, metric="euclidean", explain=True)

        assert score.explanation is not None
        assert "primary_drift_dimension" in score.explanation
        assert "dimension_contributions" in score.explanation

    def test_no_explanation_by_default(self):
        """Should not include explanation by default."""
        vec_a = np.array([1.0, 2.0])
        vec_b = np.array([1.5, 2.5])

        score = verify_embeddings(vec_a, vec_b)

        assert score.explanation is None

    def test_explanation_with_dimension_names(self):
        """Should use dimension names in explanation."""
        vec_a = np.array([0.82, 150.0])
        vec_b = np.array([0.316, 95.0])

        score = verify_embeddings(
            vec_a, vec_b, metric="euclidean", explain=True, dimension_names=["ndvi", "carbon_stock"]
        )

        assert score.explanation is not None
        # Primary dimension should be named
        assert score.explanation["primary_drift_dimension"] in ["ndvi", "carbon_stock"]
        # Contributions should use names
        contrib_keys = list(score.explanation["dimension_contributions"].keys())
        assert "ndvi" in contrib_keys or "carbon_stock" in contrib_keys

    def test_top_contributors_limited(self):
        """Top contributors should be limited to reasonable count."""
        vec_a = np.random.randn(100)
        vec_b = vec_a + np.random.randn(100) * 0.1

        score = verify_embeddings(vec_a, vec_b, metric="euclidean", explain=True)

        top_contributors = score.explanation["top_contributors"]
        assert len(top_contributors) <= 5

    def test_interpretation_human_readable(self):
        """Interpretation should be human-readable text."""
        vec_a = np.array([0.82, 150.0])
        vec_b = np.array([0.316, 95.0])

        score = verify_embeddings(
            vec_a, vec_b, metric="euclidean", explain=True, dimension_names=["ndvi", "carbon_stock"]
        )

        interpretation = score.explanation["interpretation"]
        assert isinstance(interpretation, str)
        assert len(interpretation) > 10


class TestAuditTrail:
    """Tests for audit trail (CMVK-006)."""

    def test_create_audit_trail(self):
        """Should be able to create audit trail."""
        audit = AuditTrail()

        assert len(audit.entries) == 0

    def test_log_verification(self):
        """Should log verification operations."""
        audit = AuditTrail()

        entry = audit.log(
            operation="verify_embeddings",
            inputs={"shape": (2,), "norm": 1.5},
            drift_score=0.15,
            confidence=0.92,
            metric_used="euclidean",
            passed=True,
        )

        assert len(audit.entries) == 1
        assert entry.operation == "verify_embeddings"
        assert entry.drift_score == 0.15

    def test_entry_immutability(self):
        """Audit entries should be immutable."""
        from dataclasses import FrozenInstanceError

        audit = AuditTrail()
        entry = audit.log(operation="test", inputs={}, drift_score=0.5, confidence=0.8, passed=True)

        with pytest.raises(FrozenInstanceError):
            entry.drift_score = 0.9

    def test_entry_has_timestamp(self):
        """Entries should have timestamp."""
        audit = AuditTrail()
        entry = audit.log(operation="test", inputs={}, drift_score=0.5, confidence=0.8, passed=True)

        assert entry.timestamp is not None
        assert "T" in entry.timestamp  # ISO format

    def test_entry_has_checksum(self):
        """Entries should have integrity checksum."""
        audit = AuditTrail()
        entry = audit.log(operation="test", inputs={}, drift_score=0.5, confidence=0.8, passed=True)

        assert entry.checksum is not None
        assert entry.verify_integrity() is True

    def test_inputs_are_hashed(self):
        """Input data should be hashed for privacy."""
        audit = AuditTrail()
        entry = audit.log(
            operation="test",
            inputs={"sensitive_data": "secret123"},
            drift_score=0.5,
            confidence=0.8,
            passed=True,
        )

        assert "secret123" not in entry.inputs_hash
        assert len(entry.inputs_hash) == 64  # SHA-256 hex

    def test_query_by_time(self):
        """Should filter entries by time range."""
        from datetime import datetime, timedelta

        audit = AuditTrail()
        audit.log("op1", {}, 0.1, 0.9, passed=True)
        audit.log("op2", {}, 0.2, 0.8, passed=True)

        now = datetime.now(UTC)
        future = now + timedelta(hours=1)

        entries = audit.get_entries(end_time=future)
        assert len(entries) == 2

    def test_query_by_operation(self):
        """Should filter entries by operation type."""
        audit = AuditTrail()
        audit.log("verify_embeddings", {}, 0.1, 0.9, passed=True)
        audit.log("verify_text", {}, 0.2, 0.8, passed=True)

        entries = audit.get_entries(operation="verify_embeddings")
        assert len(entries) == 1

    def test_audit_statistics(self):
        """Should calculate summary statistics."""
        audit = AuditTrail()
        audit.log("test", {}, 0.1, 0.9, passed=True)
        audit.log("test", {}, 0.2, 0.8, passed=True)
        audit.log("test", {}, 0.5, 0.7, passed=False)

        stats = audit.get_statistics()

        assert stats["total_entries"] == 3
        assert stats["passed_count"] == 2
        assert stats["pass_rate"] == pytest.approx(2 / 3)

    def test_verify_embeddings_with_audit(self):
        """verify_embeddings should log to audit trail."""
        audit = AuditTrail()

        vec_a = np.array([1.0, 2.0])
        vec_b = np.array([1.5, 2.5])

        verify_embeddings(vec_a, vec_b, metric="euclidean", audit_trail=audit)

        assert len(audit.entries) == 1
        assert audit.entries[0].operation == "verify_embeddings"

    def test_export_json(self):
        """Should export to JSON."""
        audit = AuditTrail()
        audit.log("test", {}, 0.1, 0.9, passed=True)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            audit.export_json(f.name)
            content = Path(f.name).read_text()

        assert "entries" in content
        assert "test" in content

    def test_export_csv(self):
        """Should export to CSV."""
        audit = AuditTrail()
        audit.log("test", {}, 0.1, 0.9, passed=True)

        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            audit.export_csv(f.name)
            content = Path(f.name).read_text()

        assert "timestamp" in content
        assert "drift_score" in content


class TestFraudDetectionScenario:
    """Integration test for the specific fraud detection scenario mentioned in requirements."""

    def test_ndvi_fraud_detection_with_euclidean(self):
        """
        Euclidean distance should detect obvious fraud where cosine fails.

        Scenario: Claimed NDVI=0.82, Observed NDVI=0.316 (61% discrepancy)
        Cosine returns ~0.08 drift (misses fraud)
        Euclidean should return high drift (catches fraud)
        """
        # The fraud case from requirements
        claim_vec = np.array([0.82])  # Claimed NDVI
        obs_vec = np.array([0.316])  # Observed NDVI

        # Cosine distance fails to catch this
        cosine_score = verify_embeddings(claim_vec, obs_vec, metric="cosine")

        # Euclidean distance catches it
        euclidean_score = verify_embeddings(
            claim_vec, obs_vec, metric="euclidean", threshold_profile="carbon", explain=True
        )

        # Cosine drift is low (misses fraud) because both vectors point same direction
        # But Euclidean drift should be high due to magnitude difference

        # The Euclidean should report higher drift than cosine
        assert (
            euclidean_score.drift_score > cosine_score.drift_score
        )  # Euclidean catches fraud better

        # With carbon profile, this should fail verification
        assert euclidean_score.details["profile"]["passed"] is False
        assert euclidean_score.details["profile"]["severity"] in ["warning", "critical", "severe"]

    def test_full_api_example_from_requirements(self):
        """Test the proposed API from requirements document."""
        claim_vector = np.array([0.82, 150.0])  # [ndvi, carbon_estimate]
        observation_vector = np.array([0.316, 95.0])

        result = verify_embeddings(
            claim_vector,
            observation_vector,
            metric="euclidean",  # NEW: distance metric selection
            weights=[0.6, 0.4],  # NEW: dimensional weighting
            threshold_profile="carbon",  # NEW: domain-specific thresholds
            explain=True,  # NEW: explainability
        )

        # Verify all new features work together
        assert result.drift_score > 0
        assert result.details["metric"] == "euclidean"
        assert result.explanation is not None
        assert "primary_drift_dimension" in result.explanation
        assert "dimension_contributions" in result.explanation
        assert result.details["profile"]["name"] == "carbon"
