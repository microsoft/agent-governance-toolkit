# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for pluggable reward distribution strategies."""

import pytest

from agentmesh.reward.distribution import (
    ContributionWeightedStrategy,
    DistributionResult,
    EqualSplitStrategy,
    HierarchicalStrategy,
    ParticipantInfo,
    RewardPool,
    TrustWeightedStrategy,
)
from agentmesh.reward.distributor import RewardDistributor


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pool(participants: list[ParticipantInfo], reward: float = 100.0) -> RewardPool:
    return RewardPool(total_reward=reward, task_id="task-1", participants=participants)


def _agents_3() -> list[ParticipantInfo]:
    return [
        ParticipantInfo(agent_did="did:mesh:a1", trust_score=800, delegation_depth=0),
        ParticipantInfo(agent_did="did:mesh:a2", trust_score=400, delegation_depth=1),
        ParticipantInfo(agent_did="did:mesh:a3", trust_score=200, delegation_depth=2),
    ]


# ---------------------------------------------------------------------------
# Equal split
# ---------------------------------------------------------------------------

class TestEqualSplitStrategy:
    def test_three_agents(self):
        result = EqualSplitStrategy().distribute(_pool(_agents_3()))
        assert len(result.allocations) == 3
        for a in result.allocations:
            assert pytest.approx(a.amount, abs=0.01) == 100.0 / 3
            assert a.strategy_used == "equal"
        assert pytest.approx(result.total_distributed) == 100.0

    def test_single_participant(self):
        pool = _pool([ParticipantInfo(agent_did="did:mesh:solo", trust_score=500, delegation_depth=0)])
        result = EqualSplitStrategy().distribute(pool)
        assert result.allocations[0].amount == pytest.approx(100.0)

    def test_zero_reward(self):
        result = EqualSplitStrategy().distribute(_pool(_agents_3(), reward=0.0))
        for a in result.allocations:
            assert a.amount == 0.0
        assert result.total_distributed == 0.0


# ---------------------------------------------------------------------------
# Trust-weighted
# ---------------------------------------------------------------------------

class TestTrustWeightedStrategy:
    def test_proportional_shares(self):
        result = TrustWeightedStrategy().distribute(_pool(_agents_3()))
        amounts = {a.agent_did: a.amount for a in result.allocations}
        # 800 / 1400, 400 / 1400, 200 / 1400
        assert amounts["did:mesh:a1"] == pytest.approx(800 / 1400 * 100)
        assert amounts["did:mesh:a2"] == pytest.approx(400 / 1400 * 100)
        assert amounts["did:mesh:a3"] == pytest.approx(200 / 1400 * 100)
        assert pytest.approx(result.total_distributed) == 100.0

    def test_all_same_trust(self):
        participants = [
            ParticipantInfo(agent_did=f"did:mesh:a{i}", trust_score=500, delegation_depth=0)
            for i in range(4)
        ]
        result = TrustWeightedStrategy().distribute(_pool(participants))
        for a in result.allocations:
            assert a.amount == pytest.approx(25.0)

    def test_zero_reward(self):
        result = TrustWeightedStrategy().distribute(_pool(_agents_3(), reward=0.0))
        assert result.total_distributed == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# Hierarchical
# ---------------------------------------------------------------------------

class TestHierarchicalStrategy:
    def test_root_gets_most(self):
        result = HierarchicalStrategy().distribute(_pool(_agents_3()))
        amounts = {a.agent_did: a.amount for a in result.allocations}
        assert amounts["did:mesh:a1"] > amounts["did:mesh:a2"]
        assert amounts["did:mesh:a2"] > amounts["did:mesh:a3"]
        assert pytest.approx(result.total_distributed) == 100.0

    def test_custom_decay(self):
        result = HierarchicalStrategy(decay_factor=0.5).distribute(_pool(_agents_3()))
        amounts = {a.agent_did: a.amount for a in result.allocations}
        # weights: 1.0, 0.5, 0.25 → total 1.75
        assert amounts["did:mesh:a1"] == pytest.approx(1.0 / 1.75 * 100)
        assert amounts["did:mesh:a2"] == pytest.approx(0.5 / 1.75 * 100)

    def test_single_participant(self):
        pool = _pool([ParticipantInfo(agent_did="did:mesh:solo", trust_score=500, delegation_depth=0)])
        result = HierarchicalStrategy().distribute(pool)
        assert result.allocations[0].amount == pytest.approx(100.0)


# ---------------------------------------------------------------------------
# Contribution-weighted
# ---------------------------------------------------------------------------

class TestContributionWeightedStrategy:
    def test_explicit_weights(self):
        participants = [
            ParticipantInfo(
                agent_did="did:mesh:a1", trust_score=500, delegation_depth=0,
                contribution_weight=0.5,
            ),
            ParticipantInfo(
                agent_did="did:mesh:a2", trust_score=500, delegation_depth=0,
                contribution_weight=0.3,
            ),
            ParticipantInfo(
                agent_did="did:mesh:a3", trust_score=500, delegation_depth=0,
                contribution_weight=0.2,
            ),
        ]
        result = ContributionWeightedStrategy().distribute(_pool(participants))
        amounts = {a.agent_did: a.amount for a in result.allocations}
        assert amounts["did:mesh:a1"] == pytest.approx(50.0)
        assert amounts["did:mesh:a2"] == pytest.approx(30.0)
        assert amounts["did:mesh:a3"] == pytest.approx(20.0)

    def test_missing_weights_get_zero(self):
        participants = [
            ParticipantInfo(
                agent_did="did:mesh:a1", trust_score=500, delegation_depth=0,
                contribution_weight=1.0,
            ),
            ParticipantInfo(
                agent_did="did:mesh:a2", trust_score=500, delegation_depth=0,
            ),
        ]
        result = ContributionWeightedStrategy().distribute(_pool(participants))
        amounts = {a.agent_did: a.amount for a in result.allocations}
        assert amounts["did:mesh:a1"] == pytest.approx(100.0)
        assert amounts["did:mesh:a2"] == pytest.approx(0.0)


# ---------------------------------------------------------------------------
# RewardDistributor
# ---------------------------------------------------------------------------

class TestRewardDistributor:
    def test_default_strategy(self):
        dist = RewardDistributor()
        result = dist.distribute(_pool(_agents_3()))
        assert result.strategy == "trust_weighted"

    def test_named_strategy(self):
        dist = RewardDistributor()
        result = dist.distribute(_pool(_agents_3()), strategy_name="equal")
        assert result.strategy == "equal"

    def test_unknown_strategy_raises(self):
        dist = RewardDistributor()
        with pytest.raises(ValueError, match="Unknown strategy"):
            dist.distribute(_pool(_agents_3()), strategy_name="nonexistent")

    def test_custom_strategy_registration(self):
        class FixedStrategy:
            """Gives everything to the first participant."""

            def distribute(self, pool: RewardPool) -> DistributionResult:
                from agentmesh.reward.distribution import RewardAllocation

                if not pool.participants:
                    return DistributionResult(
                        task_id=pool.task_id, strategy="fixed",
                        allocations=[], total_distributed=0.0,
                    )
                allocs = [
                    RewardAllocation(
                        agent_did=pool.participants[0].agent_did,
                        amount=pool.total_reward,
                        percentage=100.0,
                        strategy_used="fixed",
                    ),
                ] + [
                    RewardAllocation(
                        agent_did=p.agent_did, amount=0.0,
                        percentage=0.0, strategy_used="fixed",
                    )
                    for p in pool.participants[1:]
                ]
                return DistributionResult(
                    task_id=pool.task_id, strategy="fixed",
                    allocations=allocs,
                    total_distributed=pool.total_reward,
                )

        dist = RewardDistributor()
        dist.register_strategy("fixed", FixedStrategy())
        result = dist.distribute(_pool(_agents_3()), strategy_name="fixed")
        assert result.allocations[0].amount == pytest.approx(100.0)
        assert result.allocations[1].amount == 0.0

    def test_conservation_validation(self):
        """Distributor rejects results where total != pool reward."""

        class BrokenStrategy:
            def distribute(self, pool: RewardPool) -> DistributionResult:
                from agentmesh.reward.distribution import RewardAllocation

                return DistributionResult(
                    task_id=pool.task_id, strategy="broken",
                    allocations=[
                        RewardAllocation(
                            agent_did="did:mesh:x", amount=999.0,
                            percentage=100.0, strategy_used="broken",
                        ),
                    ],
                    total_distributed=999.0,
                )

        dist = RewardDistributor()
        dist.register_strategy("broken", BrokenStrategy())
        with pytest.raises(ValueError, match="Distribution mismatch"):
            dist.distribute(_pool(_agents_3()), strategy_name="broken")


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_no_participants(self):
        pool = _pool([], reward=100.0)
        for strategy_name in ("equal", "trust_weighted", "hierarchical", "contribution"):
            dist = RewardDistributor()
            result = dist.distribute(pool, strategy_name=strategy_name)
            assert result.allocations == []
            assert result.total_distributed == 0.0

    def test_zero_reward_all_strategies(self):
        pool = _pool(_agents_3(), reward=0.0)
        dist = RewardDistributor()
        for name in ("equal", "trust_weighted", "hierarchical", "contribution"):
            result = dist.distribute(pool, strategy_name=name)
            assert result.total_distributed == pytest.approx(0.0)
