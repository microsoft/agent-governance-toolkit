# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Test Layer 1: Primitives packages.
"""

import pytest


# Check if optional packages are installed
try:
    import agent_primitives
    HAS_PRIMITIVES = True
except ImportError:
    HAS_PRIMITIVES = False


@pytest.mark.skipif(not HAS_PRIMITIVES, reason="agent_primitives not installed")
class TestAgentPrimitives:
    """Test agent-primitives package."""
    
    def test_import_primitives(self):
        """Test basic import."""
        from agent_primitives import AgentFailure, FailureType, FailureSeverity
        assert FailureType is not None
        assert FailureSeverity is not None
    
    def test_failure_types(self):
        """Test failure type enum values."""
        from agent_primitives import FailureType
        assert hasattr(FailureType, 'TIMEOUT')
        assert hasattr(FailureType, 'INVALID_ACTION')
        assert hasattr(FailureType, 'RESOURCE_EXHAUSTED')
    
    def test_create_agent_failure(self):
        """Test creating an AgentFailure."""
        from agent_primitives import AgentFailure, FailureType, FailureSeverity
        from datetime import datetime, timezone
        
        failure = AgentFailure(
            agent_id="test-agent",
            failure_type=FailureType.TIMEOUT,
            error_message="Test timeout",
            context={"action": "test"},
            timestamp=datetime.now(timezone.utc),
        )
        
        assert failure.agent_id == "test-agent"
        assert failure.failure_type == FailureType.TIMEOUT


class TestCMVK:
    """Test verification-kernel package."""
    
    def test_import_cmvk(self):
        """Test basic import."""
        try:
            from cmvk import DriftDetector
            assert DriftDetector is not None
        except ImportError:
            pytest.skip("cmvk not installed with numpy")
    
    def test_drift_detection_stub(self):
        """Test drift detector can be instantiated."""
        try:
            from cmvk import DriftDetector
            detector = DriftDetector()
            assert detector is not None
        except ImportError:
            pytest.skip("cmvk not installed with numpy")


class TestCaaS:
    """Test context-as-a-service package."""
    
    def test_import_caas(self):
        """Test basic import."""
        try:
            from caas_core import ContextPipeline
            assert ContextPipeline is not None
        except ImportError:
            pytest.skip("caas not installed")


class TestEMK:
    """Test episodic-memory-kernel package."""
    
    def test_import_emk(self):
        """Test basic import."""
        try:
            from emk import EpisodicMemory, Episode
            assert EpisodicMemory is not None
            assert Episode is not None
        except ImportError:
            pytest.skip("emk not installed")


# =========================================================================
# DriftDetector (cmvk.verify) edge cases (#163)
# =========================================================================

try:
    from cmvk import verify, verify_embeddings, VerificationScore, DriftType
    import numpy as np
    HAS_CMVK = True
except ImportError:
    HAS_CMVK = False


@pytest.mark.skipif(not HAS_CMVK, reason="cmvk not installed with numpy")
class TestDriftDetectorEdgeCases:
    """Edge cases for cmvk drift verification functions."""

    def test_identical_outputs_no_drift(self):
        """Identical outputs should produce drift_score of 0.0."""
        score = verify("hello world", "hello world")
        assert score.drift_score == 0.0
        assert score.confidence > 0.0

    def test_completely_different_outputs_high_drift(self):
        """Completely different outputs should produce meaningful drift."""
        score = verify("alpha beta gamma", "12345 67890 !@#$%")
        assert score.drift_score > 0.3

    def test_both_empty_strings(self):
        """Two empty strings should yield zero drift."""
        score = verify("", "")
        assert score.drift_score == 0.0
        assert score.drift_type == DriftType.LEXICAL

    def test_one_empty_string(self):
        """One empty input yields maximum drift."""
        score = verify("some text", "")
        assert score.drift_score == 1.0

    def test_identical_embeddings_zero_drift(self):
        """Identical embedding vectors should produce zero drift."""
        vec = np.array([1.0, 2.0, 3.0])
        score = verify_embeddings(vec, vec)
        assert score.drift_score == pytest.approx(0.0, abs=1e-6)

    def test_opposite_embeddings_high_drift(self):
        """Opposite vectors should produce high drift (cosine)."""
        vec_a = np.array([1.0, 0.0, 0.0])
        vec_b = np.array([-1.0, 0.0, 0.0])
        score = verify_embeddings(vec_a, vec_b)
        assert score.drift_score > 0.9

    def test_zero_threshold_passes_only_identical(self):
        """With threshold 0, only identical outputs pass."""
        score_same = verify("abc", "abc")
        assert score_same.passed(threshold=0.0)

        score_diff = verify("abc", "xyz")
        assert not score_diff.passed(threshold=0.0)

    def test_verification_score_to_dict(self):
        """VerificationScore.to_dict returns expected keys."""
        score = verify("foo", "bar")
        d = score.to_dict()
        assert "drift_score" in d
        assert "confidence" in d
        assert "drift_type" in d
        assert "details" in d


# =========================================================================
# EpisodicMemory (emk) edge cases (#164)
# =========================================================================

try:
    from emk import Episode, FileAdapter
    HAS_EMK = True
except ImportError:
    HAS_EMK = False


@pytest.mark.skipif(not HAS_EMK, reason="emk not installed")
class TestEpisodicMemoryEdgeCases:
    """Edge cases for emk Episode and FileAdapter."""

    def test_empty_store_retrieve_returns_empty(self, tmp_path):
        """Retrieving from an empty store returns an empty list."""
        store = FileAdapter(str(tmp_path / "empty.jsonl"))
        results = store.retrieve()
        assert results == []

    def test_retrieve_no_matches_with_filter(self, tmp_path):
        """Retrieve with a non-matching filter returns empty."""
        store = FileAdapter(str(tmp_path / "filtered.jsonl"))
        ep = Episode(
            goal="test", action="act", result="ok", reflection="fine",
            metadata={"user_id": "abc"},
        )
        store.store(ep)
        results = store.retrieve(filters={"user_id": "nonexistent"})
        assert results == []

    def test_get_by_id_missing_returns_none(self, tmp_path):
        """get_by_id for non-existent ID returns None."""
        store = FileAdapter(str(tmp_path / "missing.jsonl"))
        assert store.get_by_id("does-not-exist") is None

    def test_store_and_retrieve_multiple(self, tmp_path):
        """Store multiple episodes and retrieve them all."""
        store = FileAdapter(str(tmp_path / "multi.jsonl"))
        for i in range(5):
            ep = Episode(
                goal=f"goal-{i}", action=f"act-{i}",
                result=f"res-{i}", reflection=f"ref-{i}",
            )
            store.store(ep)
        results = store.retrieve(limit=10)
        assert len(results) == 5

    def test_retrieve_respects_limit(self, tmp_path):
        """Retrieve with limit returns at most that many episodes."""
        store = FileAdapter(str(tmp_path / "limit.jsonl"))
        for i in range(10):
            ep = Episode(
                goal=f"g-{i}", action=f"a-{i}",
                result=f"r-{i}", reflection=f"ref-{i}",
            )
            store.store(ep)
        results = store.retrieve(limit=3)
        assert len(results) == 3

    def test_duplicate_episodes_stored_independently(self, tmp_path):
        """Storing the same episode content twice creates separate entries."""
        store = FileAdapter(str(tmp_path / "dupes.jsonl"))
        ep1 = Episode(goal="g", action="a", result="r", reflection="ref")
        ep2 = Episode(goal="g", action="a", result="r", reflection="ref")
        store.store(ep1)
        store.store(ep2)
        results = store.retrieve(limit=10)
        assert len(results) == 2

    def test_episode_is_mutable(self):
        """Public Preview: Episode model is mutable for flexibility."""
        ep = Episode(goal="g", action="a", result="r", reflection="ref")
        ep.goal = "new goal"
        assert ep.goal == "new goal"

    def test_episode_mark_as_failure(self):
        """mark_as_failure returns new episode with failure metadata."""
        ep = Episode(goal="g", action="a", result="fail", reflection="bad")
        failed = ep.mark_as_failure(reason="timeout")
        assert failed.is_failure()
        assert failed.metadata["failure_reason"] == "timeout"
        assert not ep.is_failure()  # original unchanged
