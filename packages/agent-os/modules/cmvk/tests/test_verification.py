"""
Unit tests for CMVK verification module.

Tests pure verification functions.
"""

import numpy as np
import pytest

from cmvk import (
    DriftType,
    VerificationScore,
    aggregate_scores,
    verify,
    verify_batch,
    verify_distributions,
    verify_embeddings,
    verify_sequences,
)


class TestVerify:
    """Tests for the main verify() function."""

    def test_identical_outputs_have_zero_drift(self):
        """Identical outputs should have zero drift."""
        text = "def add(a, b): return a + b"
        score = verify(text, text)
        assert score.drift_score == 0.0
        assert score.confidence > 0.8

    def test_empty_outputs_have_zero_drift(self):
        """Two empty outputs should have zero drift."""
        score = verify("", "")
        assert score.drift_score == 0.0
        assert score.confidence == 1.0

    def test_one_empty_output_has_full_drift(self):
        """One empty, one non-empty should have full drift."""
        score = verify("some content", "")
        assert score.drift_score == 1.0

        score = verify("", "some content")
        assert score.drift_score == 1.0

    def test_similar_outputs_have_low_drift(self):
        """Similar outputs should have low drift."""
        a = "def add(a, b): return a + b"
        b = "def add(x, y): return x + y"
        score = verify(a, b)
        assert score.drift_score < 0.5
        assert score.confidence > 0.5

    def test_different_outputs_have_high_drift(self):
        """Very different outputs should have higher drift than similar ones."""
        similar_a = "def add(a, b): return a + b"
        similar_b = "def add(x, y): return x + y"
        different_a = "def add(a, b): return a + b"
        different_b = "The quick brown fox jumps over the lazy dog"

        similar_score = verify(similar_a, similar_b)
        different_score = verify(different_a, different_b)

        # Different outputs should have higher drift than similar ones
        assert different_score.drift_score > similar_score.drift_score
        # And should have some meaningful drift
        assert different_score.drift_score > 0.3

    def test_returns_verification_score(self):
        """verify() should return a VerificationScore."""
        score = verify("hello", "world")
        assert isinstance(score, VerificationScore)
        assert isinstance(score.drift_score, float)
        assert isinstance(score.confidence, float)
        assert isinstance(score.drift_type, DriftType)
        assert isinstance(score.details, dict)

    def test_drift_score_is_bounded(self):
        """Drift score should be between 0 and 1."""
        test_cases = [
            ("", ""),
            ("a", "b"),
            ("hello world", "goodbye world"),
            ("x" * 1000, "y" * 1000),
        ]
        for a, b in test_cases:
            score = verify(a, b)
            assert 0.0 <= score.drift_score <= 1.0
            assert 0.0 <= score.confidence <= 1.0

    def test_verification_score_is_immutable(self):
        """VerificationScore should be frozen/immutable."""
        score = verify("a", "b")
        with pytest.raises(AttributeError):
            score.drift_score = 0.5


class TestVerifyEmbeddings:
    """Tests for verify_embeddings()."""

    def test_identical_embeddings_have_zero_drift(self):
        """Identical embeddings should have zero drift."""
        emb = np.array([0.1, 0.2, 0.3, 0.4])
        score = verify_embeddings(emb, emb)
        assert score.drift_score < 0.01

    def test_orthogonal_embeddings_have_high_drift(self):
        """Orthogonal embeddings should have high drift."""
        emb_a = np.array([1.0, 0.0, 0.0, 0.0])
        emb_b = np.array([0.0, 1.0, 0.0, 0.0])
        score = verify_embeddings(emb_a, emb_b)
        assert score.drift_score >= 0.5  # Orthogonal = cosine distance 1.0, normalized to 0.5

    def test_opposite_embeddings_have_maximum_drift(self):
        """Opposite embeddings should have maximum drift."""
        emb_a = np.array([1.0, 1.0, 1.0, 1.0])
        emb_b = np.array([-1.0, -1.0, -1.0, -1.0])
        score = verify_embeddings(emb_a, emb_b)
        assert score.drift_score > 0.9

    def test_shape_mismatch_returns_high_drift(self):
        """Different shaped embeddings should return high drift."""
        emb_a = np.array([0.1, 0.2, 0.3])
        emb_b = np.array([0.1, 0.2, 0.3, 0.4])
        score = verify_embeddings(emb_a, emb_b)
        assert score.drift_score == 1.0
        assert "shape_mismatch" in score.details.get("reason", "")


class TestVerifyDistributions:
    """Tests for verify_distributions()."""

    def test_identical_distributions_have_zero_drift(self):
        """Identical distributions should have zero drift."""
        dist = np.array([0.2, 0.3, 0.5])
        score = verify_distributions(dist, dist)
        assert score.drift_score < 0.01

    def test_different_distributions_have_positive_drift(self):
        """Different distributions should have positive drift."""
        dist_a = np.array([0.9, 0.05, 0.05])
        dist_b = np.array([0.05, 0.05, 0.9])
        score = verify_distributions(dist_a, dist_b)
        assert score.drift_score > 0.5

    def test_details_include_divergence_metrics(self):
        """Details should include KL and JS divergence."""
        dist_a = np.array([0.5, 0.5])
        dist_b = np.array([0.7, 0.3])
        score = verify_distributions(dist_a, dist_b)
        assert "kl_divergence" in score.details
        assert "js_divergence" in score.details
        assert "total_variation" in score.details


class TestVerifySequences:
    """Tests for verify_sequences()."""

    def test_identical_sequences_have_zero_drift(self):
        """Identical sequences should have zero drift."""
        seq = ["a", "b", "c", "d"]
        score = verify_sequences(seq, seq)
        assert score.drift_score < 0.01

    def test_empty_sequences_have_zero_drift(self):
        """Two empty sequences should have zero drift."""
        score = verify_sequences([], [])
        assert score.drift_score == 0.0

    def test_different_sequences_have_positive_drift(self):
        """Different sequences should have positive drift."""
        seq_a = ["a", "b", "c"]
        seq_b = ["x", "y", "z"]
        score = verify_sequences(seq_a, seq_b)
        assert score.drift_score > 0.5

    def test_details_include_edit_distance(self):
        """Details should include edit distance."""
        seq_a = ["def", "add", "(", "a", ")"]
        seq_b = ["def", "add", "(", "x", ")"]
        score = verify_sequences(seq_a, seq_b)
        assert "edit_distance" in score.details
        assert "jaccard_similarity" in score.details
        assert "lcs_ratio" in score.details


class TestBatchOperations:
    """Tests for batch verification operations."""

    def test_verify_batch_processes_all_pairs(self):
        """verify_batch should process all pairs."""
        outputs_a = ["a", "b", "c"]
        outputs_b = ["x", "y", "z"]
        scores = verify_batch(outputs_a, outputs_b)
        assert len(scores) == 3
        assert all(isinstance(s, VerificationScore) for s in scores)

    def test_verify_batch_raises_on_length_mismatch(self):
        """verify_batch should raise on mismatched lengths."""
        outputs_a = ["a", "b"]
        outputs_b = ["x", "y", "z"]
        with pytest.raises(ValueError):
            verify_batch(outputs_a, outputs_b)

    def test_aggregate_scores_computes_statistics(self):
        """aggregate_scores should compute summary statistics."""
        outputs_a = ["hello", "world", "test"]
        outputs_b = ["hello", "earth", "exam"]
        scores = verify_batch(outputs_a, outputs_b)
        summary = aggregate_scores(scores)

        assert "count" in summary
        assert summary["count"] == 3
        assert "mean_drift" in summary
        assert "std_drift" in summary
        assert "min_drift" in summary
        assert "max_drift" in summary
        assert "drift_type_distribution" in summary

    def test_aggregate_scores_handles_empty_list(self):
        """aggregate_scores should handle empty list."""
        summary = aggregate_scores([])
        assert summary["count"] == 0


class TestPureFunctions:
    """Tests to ensure functions are pure (no side effects)."""

    def test_verify_is_deterministic(self):
        """Same inputs should always produce same output."""
        a, b = "hello world", "hello earth"
        score1 = verify(a, b)
        score2 = verify(a, b)
        assert score1.drift_score == score2.drift_score
        assert score1.confidence == score2.confidence

    def test_verify_does_not_modify_inputs(self):
        """verify should not modify input strings."""
        a = "original text"
        b = "other text"
        a_copy = a
        b_copy = b
        verify(a, b)
        assert a == a_copy
        assert b == b_copy

    def test_verify_embeddings_does_not_modify_arrays(self):
        """verify_embeddings should not modify input arrays."""
        emb_a = np.array([0.1, 0.2, 0.3])
        emb_b = np.array([0.4, 0.5, 0.6])
        original_a = emb_a.copy()
        original_b = emb_b.copy()
        verify_embeddings(emb_a, emb_b)
        np.testing.assert_array_equal(emb_a, original_a)
        np.testing.assert_array_equal(emb_b, original_b)
