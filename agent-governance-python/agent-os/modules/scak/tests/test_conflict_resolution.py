# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for conflict resolution mechanisms.
"""

import pytest
import asyncio
from src.agents.conflict_resolution import (
    ConflictResolver,
    AgentVote,
    ConflictType,
    VoteType
)


class TestConflictResolver:
    """Test conflict resolution algorithms."""
    
    @pytest.fixture
    def resolver(self):
        """Create resolver instance."""
        return ConflictResolver(
            default_vote_type=VoteType.MAJORITY,
            supervisor_agent_id="supervisor-001"
        )
    
    @pytest.mark.asyncio
    async def test_majority_vote_clear_winner(self, resolver):
        """Test majority vote with clear winner."""
        votes = [
            AgentVote(agent_id="agent-1", option="approve", confidence=0.9),
            AgentVote(agent_id="agent-2", option="approve", confidence=0.8),
            AgentVote(agent_id="agent-3", option="reject", confidence=0.7),
        ]
        
        resolution = await resolver.resolve_conflict(
            "conflict-001",
            ConflictType.DECISION,
            votes,
            VoteType.MAJORITY
        )
        
        assert resolution.winning_option == "approve"
        assert resolution.votes_for_winner == 2
        assert resolution.consensus_score == 2/3
        assert len(resolution.dissenting_agents) == 1
    
    @pytest.mark.asyncio
    async def test_majority_vote_tie(self, resolver):
        """Test majority vote with tie (uses confidence tiebreaker)."""
        votes = [
            AgentVote(agent_id="agent-1", option="option_a", confidence=0.9),
            AgentVote(agent_id="agent-2", option="option_b", confidence=0.6),
        ]
        
        resolution = await resolver.resolve_conflict(
            "conflict-002",
            ConflictType.DECISION,
            votes,
            VoteType.MAJORITY
        )
        
        # Should pick option_a due to higher confidence
        assert resolution.winning_option == "option_a"
        assert resolution.tiebreaker_used is True
    
    @pytest.mark.asyncio
    async def test_weighted_vote(self, resolver):
        """Test confidence-weighted voting."""
        votes = [
            AgentVote(
                agent_id="expert",
                option="option_a",
                confidence=0.95  # High expertise
            ),
            AgentVote(
                agent_id="novice-1",
                option="option_b",
                confidence=0.3  # Low confidence
            ),
            AgentVote(
                agent_id="novice-2",
                option="option_b",
                confidence=0.4
            ),
        ]
        
        resolution = await resolver.resolve_conflict(
            "conflict-003",
            ConflictType.INTERPRETATION,
            votes,
            VoteType.WEIGHTED
        )
        
        # Expert vote (0.95) should outweigh two novice votes (0.3 + 0.4 = 0.7)
        assert resolution.winning_option == "option_a"
    
    @pytest.mark.asyncio
    async def test_supermajority_met(self, resolver):
        """Test supermajority when threshold met."""
        votes = [
            AgentVote(agent_id=f"agent-{i}", option="approve", confidence=0.8)
            for i in range(7)
        ] + [
            AgentVote(agent_id=f"agent-{i}", option="reject", confidence=0.8)
            for i in range(7, 10)
        ]
        
        resolution = await resolver.resolve_conflict(
            "conflict-004",
            ConflictType.DECISION,
            votes,
            VoteType.SUPERMAJORITY
        )
        
        # 7/10 = 70% > 67% threshold
        assert resolution.winning_option == "approve"
        assert resolution.escalated_to_supervisor is False
    
    @pytest.mark.asyncio
    async def test_supermajority_not_met(self, resolver):
        """Test supermajority when threshold not met (escalates)."""
        votes = [
            AgentVote(agent_id="agent-1", option="option_a", confidence=0.8),
            AgentVote(agent_id="agent-2", option="option_b", confidence=0.8),
            AgentVote(agent_id="agent-3", option="option_c", confidence=0.8),
        ]
        
        resolution = await resolver.resolve_conflict(
            "conflict-005",
            ConflictType.DECISION,
            votes,
            VoteType.SUPERMAJORITY
        )
        
        # No supermajority, should escalate or use fallback
        # With supervisor configured, should escalate
        assert resolution.winning_option in ["option_a", "option_b", "option_c"]
    
    @pytest.mark.asyncio
    async def test_unanimous_success(self, resolver):
        """Test unanimous vote when all agree."""
        votes = [
            AgentVote(agent_id=f"agent-{i}", option="proceed", confidence=0.9)
            for i in range(5)
        ]
        
        resolution = await resolver.resolve_conflict(
            "conflict-006",
            ConflictType.DECISION,
            votes,
            VoteType.UNANIMOUS
        )
        
        assert resolution.winning_option == "proceed"
        assert resolution.consensus_score == 1.0
        assert len(resolution.dissenting_agents) == 0
    
    @pytest.mark.asyncio
    async def test_unanimous_failure(self, resolver):
        """Test unanimous vote when not all agree (escalates)."""
        votes = [
            AgentVote(agent_id="agent-1", option="proceed", confidence=0.9),
            AgentVote(agent_id="agent-2", option="proceed", confidence=0.9),
            AgentVote(agent_id="agent-3", option="abort", confidence=0.9),
        ]
        
        resolution = await resolver.resolve_conflict(
            "conflict-007",
            ConflictType.DECISION,
            votes,
            VoteType.UNANIMOUS
        )
        
        # Not unanimous, should escalate
        assert resolution.escalated_to_supervisor is True
    
    @pytest.mark.asyncio
    async def test_ranked_choice_immediate_majority(self, resolver):
        """Test ranked-choice with immediate majority."""
        votes = [
            AgentVote(
                agent_id="agent-1",
                option="option_a",
                ranked_preferences=["option_a", "option_b", "option_c"]
            ),
            AgentVote(
                agent_id="agent-2",
                option="option_a",
                ranked_preferences=["option_a", "option_c", "option_b"]
            ),
            AgentVote(
                agent_id="agent-3",
                option="option_b",
                ranked_preferences=["option_b", "option_a", "option_c"]
            ),
        ]
        
        resolution = await resolver.resolve_conflict(
            "conflict-008",
            ConflictType.PRIORITY,
            votes,
            VoteType.RANKED_CHOICE
        )
        
        # option_a has 2/3 votes (majority)
        assert resolution.winning_option == "option_a"
    
    @pytest.mark.asyncio
    async def test_resolution_history(self, resolver):
        """Test resolution history tracking."""
        votes = [
            AgentVote(agent_id="agent-1", option="yes", confidence=0.9),
            AgentVote(agent_id="agent-2", option="no", confidence=0.8),
        ]
        
        await resolver.resolve_conflict(
            "conflict-009",
            ConflictType.DECISION,
            votes
        )
        
        stats = resolver.get_resolution_stats()
        
        assert stats["total_resolutions"] == 1
        assert stats["avg_consensus_score"] > 0
        assert "by_method" in stats
    
    @pytest.mark.asyncio
    async def test_empty_votes_raises_error(self, resolver):
        """Test that empty votes list raises error."""
        with pytest.raises(ValueError, match="zero votes"):
            await resolver.resolve_conflict(
                "conflict-010",
                ConflictType.DECISION,
                []
            )


class TestVotingEdgeCases:
    """Test edge cases in voting."""
    
    @pytest.fixture
    def resolver(self):
        """Create resolver without supervisor."""
        return ConflictResolver(
            default_vote_type=VoteType.MAJORITY,
            supervisor_agent_id=None  # No supervisor
        )
    
    @pytest.mark.asyncio
    async def test_single_vote(self, resolver):
        """Test with single vote."""
        votes = [
            AgentVote(agent_id="agent-1", option="approve", confidence=0.9)
        ]
        
        resolution = await resolver.resolve_conflict(
            "conflict-single",
            ConflictType.DECISION,
            votes
        )
        
        assert resolution.winning_option == "approve"
        assert resolution.consensus_score == 1.0
    
    @pytest.mark.asyncio
    async def test_all_different_options(self, resolver):
        """Test when each agent votes for different option."""
        votes = [
            AgentVote(agent_id="agent-1", option="option_1", confidence=0.9),
            AgentVote(agent_id="agent-2", option="option_2", confidence=0.8),
            AgentVote(agent_id="agent-3", option="option_3", confidence=0.7),
        ]
        
        resolution = await resolver.resolve_conflict(
            "conflict-all-diff",
            ConflictType.DECISION,
            votes
        )
        
        # Should pick one (highest confidence in tie)
        assert resolution.winning_option == "option_1"
        assert resolution.tiebreaker_used is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
