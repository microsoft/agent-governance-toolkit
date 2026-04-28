# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Reward & Learning Engine (Layer 4)

Behavioral feedback loop that scores agent actions
against a governance rubric.
"""

from .engine import RewardEngine
from .scoring import TrustScore, RewardDimension, RewardSignal
from .trust_decay import NetworkTrustEngine, TrustEvent
from .distribution import (
    ContributionWeightedStrategy,
    DistributionResult,
    EqualSplitStrategy,
    HierarchicalStrategy,
    ParticipantInfo,
    RewardAllocation,
    RewardPool,
    RewardStrategy,
    TrustWeightedStrategy,
)
from .distributor import RewardDistributor

__all__ = [
    "RewardEngine",
    "TrustScore",
    "RewardDimension",
    "RewardSignal",
    "NetworkTrustEngine",
    "TrustEvent",
    "ContributionWeightedStrategy",
    "DistributionResult",
    "EqualSplitStrategy",
    "HierarchicalStrategy",
    "ParticipantInfo",
    "RewardAllocation",
    "RewardPool",
    "RewardStrategy",
    "TrustWeightedStrategy",
    "RewardDistributor",
]
