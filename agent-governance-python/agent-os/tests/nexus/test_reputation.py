# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for Nexus Reputation Engine
"""

import pytest
from datetime import datetime

from nexus.reputation import (
    ReputationEngine,
    ReputationHistory,
    TrustScore,
    TrustTier,
)


class TestTrustScore:
    """Tests for TrustScore class."""
    
    def test_tier_classification(self):
        """Test tier classification from score."""
        assert TrustScore.get_tier(950) == TrustTier.VERIFIED_PARTNER
        assert TrustScore.get_tier(750) == TrustTier.TRUSTED
        assert TrustScore.get_tier(550) == TrustTier.STANDARD
        assert TrustScore.get_tier(350) == TrustTier.PROBATIONARY
        assert TrustScore.get_tier(150) == TrustTier.UNTRUSTED
    
    def test_meets_threshold(self):
        """Test threshold checking."""
        score = TrustScore(
            agent_did="did:nexus:test",
            total_score=750,
            tier=TrustTier.TRUSTED,
            base_score=650,
            behavioral_modifier=50,
            capability_modifier=50,
        )
        
        assert score.meets_threshold(700) is True
        assert score.meets_threshold(800) is False


class TestReputationEngine:
    """Tests for ReputationEngine."""
    
    def test_base_score_calculation(self):
        """Test base score from verification level."""
        engine = ReputationEngine()
        history = ReputationHistory(agent_did="did:nexus:test")
        
        # Verified partner starts high
        score = engine.calculate_trust_score("verified_partner", history)
        assert score.base_score == 800
        
        # Registered starts lower
        score = engine.calculate_trust_score("registered", history)
        assert score.base_score == 400
    
    def test_behavioral_modifiers(self):
        """Test behavioral modifiers on score."""
        engine = ReputationEngine()
        
        # Successful tasks increase score
        history = ReputationHistory(
            agent_did="did:nexus:good-agent",
            successful_tasks=50,
            failed_tasks=0,
        )
        score = engine.calculate_trust_score("registered", history)
        assert score.behavioral_modifier > 0
        
        # Failed tasks decrease score
        history = ReputationHistory(
            agent_did="did:nexus:bad-agent",
            successful_tasks=0,
            failed_tasks=10,
        )
        score = engine.calculate_trust_score("registered", history)
        assert score.behavioral_modifier < 0
    
    def test_capability_modifiers(self):
        """Test capability modifiers on score."""
        engine = ReputationEngine()
        history = ReputationHistory(agent_did="did:nexus:test")
        
        # Full reversibility adds points
        capabilities = {"reversibility": "full"}
        privacy = {"retention_policy": "ephemeral", "training_consent": False}
        
        score = engine.calculate_trust_score(
            "registered", history, capabilities, privacy
        )
        assert score.capability_modifier > 0
    
    def test_record_task_outcome(self):
        """Test recording task outcomes."""
        engine = ReputationEngine()
        
        history = engine.record_task_outcome("did:nexus:test", "success")
        assert history.successful_tasks == 1
        
        history = engine.record_task_outcome("did:nexus:test", "failure")
        assert history.failed_tasks == 1
    
    def test_slash_reputation(self):
        """Test reputation slashing."""
        engine = ReputationEngine()
        
        slash = engine.slash_reputation(
            agent_did="did:nexus:bad-agent",
            reason="hallucination",
            severity="high",
            broadcast=False,
        )
        
        assert slash.score_reduction == 100  # High severity
        assert slash.reason == "hallucination"
    
    def test_trust_threshold_check(self):
        """Test trust threshold checking."""
        engine = ReputationEngine(trust_threshold=700)
        
        # Record some successful tasks to build reputation
        for _ in range(100):
            engine.record_task_outcome("did:nexus:trusted", "success")
        
        # Manually set cache for testing
        history = engine._get_or_create_history("did:nexus:trusted")
        score = engine.calculate_trust_score("verified", history)
        engine._score_cache["did:nexus:trusted"] = score
        
        meets, _ = engine.check_trust_threshold("did:nexus:trusted")
        assert meets is True
    
    def test_score_clamping(self):
        """Test score stays in 0-1000 range."""
        engine = ReputationEngine()
        
        # Even with extreme values, score should be clamped
        history = ReputationHistory(
            agent_did="did:nexus:extreme",
            successful_tasks=1000,  # Way too many
        )
        
        score = engine.calculate_trust_score("verified_partner", history)
        assert 0 <= score.total_score <= 1000


class TestReputationHistory:
    """Tests for ReputationHistory."""
    
    def test_success_rate(self):
        """Test success rate calculation."""
        history = ReputationHistory(
            agent_did="did:nexus:test",
            successful_tasks=80,
            failed_tasks=20,
            total_tasks=100,
        )
        
        assert history.success_rate == 0.8
    
    def test_dispute_win_rate(self):
        """Test dispute win rate calculation."""
        history = ReputationHistory(
            agent_did="did:nexus:test",
            disputes_won=7,
            disputes_lost=3,
        )
        
        assert history.dispute_win_rate == 0.7
    
    def test_empty_rates(self):
        """Test rates with no data."""
        history = ReputationHistory(agent_did="did:nexus:new")
        
        assert history.success_rate == 0.0
        assert history.dispute_win_rate == 0.5  # Neutral default
