# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for AgentMesh Reward module."""

import pytest
from datetime import datetime, timedelta

from agentmesh.reward import (
    RewardEngine,
    TrustScore,
    RewardDimension,
    RewardSignal,
)
from agentmesh.reward.scoring import DimensionType


class TestRewardEngine:
    """Tests for RewardEngine."""
    
    def test_create_engine(self):
        """Test creating reward engine."""
        engine = RewardEngine()
        
        assert engine is not None
    
    def test_initial_score(self):
        """Test initial trust score."""
        engine = RewardEngine()
        
        score = engine.get_agent_score("did:mesh:test")
        
        assert isinstance(score, TrustScore)
        assert score.total_score >= 0
        assert score.total_score <= 1000
    
    def test_record_signal(self):
        """Test recording reward signals."""
        engine = RewardEngine()
        
        engine.record_signal(
            agent_did="did:mesh:test",
            dimension=DimensionType.POLICY_COMPLIANCE,
            value=1.0,
            source="test",
        )
        
        # Signal should be recorded
        state = engine._agents.get("did:mesh:test")
        assert state is not None
        assert len(state.recent_signals) == 1
    
    def test_policy_compliance_signal(self):
        """Test recording policy compliance."""
        engine = RewardEngine()
        
        engine.record_policy_compliance(
            agent_did="did:mesh:test",
            compliant=True,
            policy_name="test-policy",
        )
        
        state = engine._agents.get("did:mesh:test")
        signal = state.recent_signals[0]
        
        assert signal.dimension == DimensionType.POLICY_COMPLIANCE
        assert signal.value == 1.0
    
    def test_resource_usage_signal(self):
        """Test recording resource usage."""
        engine = RewardEngine()
        
        engine.record_resource_usage(
            agent_did="did:mesh:test",
            tokens_used=100,
            tokens_budget=200,
            compute_ms=50,
            compute_budget_ms=100,
        )
        
        state = engine._agents.get("did:mesh:test")
        signal = state.recent_signals[0]
        
        assert signal.dimension == DimensionType.RESOURCE_EFFICIENCY
        assert signal.value == 1.0  # Within budget
    
    def test_score_recalculation(self):
        """Test score recalculation."""
        engine = RewardEngine()
        
        # Add many positive signals
        for _ in range(10):
            engine.record_signal(
                agent_did="did:mesh:test",
                dimension=DimensionType.POLICY_COMPLIANCE,
                value=1.0,
                source="test",
            )
        
        score = engine._recalculate_score("did:mesh:test")
        
        # Score should be high
        assert score.total_score > 500
    
    def test_automatic_revocation(self):
        """Test automatic credential revocation on low score."""
        engine = RewardEngine()
        
        revoked_agents = []
        engine.on_revocation(lambda did, reason: revoked_agents.append(did))
        
        # Add many negative signals across all dimensions to drive score below 300
        for _ in range(100):
            for dim in DimensionType:
                engine.record_signal(
                    agent_did="did:mesh:test",
                    dimension=dim,
                    value=0.0,
                    source="test",
                )
        
        engine._recalculate_score("did:mesh:test")
        
        # Agent should be revoked (score will be 0)
        state = engine._agents.get("did:mesh:test")
        assert state.revoked or len(revoked_agents) > 0
    
    def test_score_explanation(self):
        """Test getting score explanation."""
        engine = RewardEngine()
        
        engine.record_signal(
            agent_did="did:mesh:test",
            dimension=DimensionType.POLICY_COMPLIANCE,
            value=0.8,
            source="test",
        )
        engine._recalculate_score("did:mesh:test")
        
        explanation = engine.get_score_explanation("did:mesh:test")
        
        assert "agent_did" in explanation
        assert "total_score" in explanation
        assert "dimensions" in explanation
        assert "trend" in explanation


class TestTrustScore:
    """Tests for TrustScore."""
    
    def test_create_score(self):
        """Test creating trust score."""
        score = TrustScore(agent_did="did:mesh:test")
        
        assert score.agent_did == "did:mesh:test"
        assert score.total_score == 500  # Default
    
    def test_tier_assignment(self):
        """Test tier assignment based on score."""
        score = TrustScore(agent_did="did:mesh:test", total_score=950)
        assert score.tier == "verified_partner"
        
        score = TrustScore(agent_did="did:mesh:test", total_score=750)
        assert score.tier == "trusted"
        
        score = TrustScore(agent_did="did:mesh:test", total_score=500)
        assert score.tier == "standard"
        
        score = TrustScore(agent_did="did:mesh:test", total_score=350)
        assert score.tier == "probationary"
        
        score = TrustScore(agent_did="did:mesh:test", total_score=100)
        assert score.tier == "untrusted"
    
    def test_threshold_check(self):
        """Test threshold checking."""
        score = TrustScore(agent_did="did:mesh:test", total_score=700)
        
        assert score.meets_threshold(500)
        assert score.meets_threshold(700)
        assert not score.meets_threshold(800)


