# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Shared trust and identity types for AgentMesh integrations.

These types provide the canonical interface for trust scoring,
agent identity, and verification across all governance integrations.
Import from here instead of duplicating in each integration package.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class TrustScore:
    """Trust score for an agent or interaction."""
    score: float  # 0.0 to 1.0
    confidence: float = 1.0
    source: str = ""
    timestamp: str = ""

    def __post_init__(self) -> None:
        self.score = max(0.0, min(1.0, self.score))
        self.confidence = max(0.0, min(1.0, self.confidence))

    @property
    def is_trusted(self) -> bool:
        return self.score >= 0.5

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "confidence": self.confidence,
            "source": self.source,
            "timestamp": self.timestamp,
        }


@dataclass
class AgentProfile:
    """Identity and capability profile for a governed agent."""
    agent_id: str
    did: str = ""
    role: str = ""
    capabilities: list[str] = field(default_factory=list)
    trust_score: float = 0.5
    organization: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def has_capability(self, capability: str) -> bool:
        return capability in self.capabilities or "*" in self.capabilities


@dataclass
class TrustRecord:
    """Record of a trust-relevant interaction."""
    agent_id: str
    peer_id: str
    action: str
    success: bool
    trust_delta: float = 0.0
    timestamp: str = ""
    details: str = ""


class TrustTracker:
    """Tracks trust scores and interaction history for agents.

    Provides the canonical implementation used across all integrations.
    Integration packages should import this rather than reimplementing.
    """

    def __init__(
        self,
        initial_score: float = 0.5,
        reward: float = 0.01,
        penalty: float = 0.05,
        min_score: float = 0.0,
        max_score: float = 1.0,
    ) -> None:
        self._scores: dict[str, float] = {}
        self._history: list[TrustRecord] = []
        self._initial = initial_score
        self._reward = reward
        self._penalty = penalty
        self._min = min_score
        self._max = max_score

    def get_score(self, agent_id: str) -> float:
        return self._scores.get(agent_id, self._initial)

    def record_interaction(
        self, agent_id: str, peer_id: str, action: str, success: bool,
    ) -> float:
        current = self.get_score(agent_id)
        delta = self._reward if success else -self._penalty
        new_score = max(self._min, min(self._max, current + delta))
        self._scores[agent_id] = new_score
        self._history.append(TrustRecord(
            agent_id=agent_id,
            peer_id=peer_id,
            action=action,
            success=success,
            trust_delta=delta,
        ))
        return new_score

    def get_history(self, agent_id: str | None = None) -> list[TrustRecord]:
        if agent_id is None:
            return list(self._history)
        return [r for r in self._history if r.agent_id == agent_id]

    def reset(self, agent_id: str) -> None:
        self._scores.pop(agent_id, None)
