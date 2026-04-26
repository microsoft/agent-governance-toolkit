# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Nexus Integration Stub — Trust Scoring for Ring Assignment.

Provides the interface for integrating an external trust/reputation
engine with the Hypervisor. Supply your own scorer implementation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol


class NexusTrustScorer(Protocol):
    """Protocol for a trust scoring backend."""

    def calculate_trust_score(
        self,
        verification_level: str,
        history: Any,
        capabilities: dict | None = None,
        privacy: dict | None = None,
    ) -> Any: ...

    def slash_reputation(
        self,
        agent_did: str,
        reason: str,
        severity: str,
        evidence_hash: str | None = None,
        trace_id: str | None = None,
        broadcast: bool = True,
    ) -> Any: ...

    def record_task_outcome(
        self,
        agent_did: str,
        outcome: str,
    ) -> Any: ...


@dataclass
class NexusScoreResult:
    """Result of a trust score lookup."""

    agent_did: str
    raw_nexus_score: int
    normalized_sigma: float
    tier: str
    resolved_at: datetime = field(default_factory=lambda: datetime.now(UTC))


class NexusAdapter:
    """Stub adapter for trust scoring integration.

    Provides a default sigma of 0.50 when no scorer is configured.
    """

    def __init__(
        self,
        scorer: NexusTrustScorer | None = None,
        cache_ttl_seconds: int = 300,
    ) -> None:
        self._scorer = scorer
        self._cache: dict[str, NexusScoreResult] = {}
        self._cache_ttl = cache_ttl_seconds

    def resolve_sigma(
        self,
        agent_did: str,
        verification_level: str = "standard",
        history: Any | None = None,
        capabilities: dict | None = None,
    ) -> float:
        """Resolve an agent's sigma. Returns 0.50 default when no scorer is configured."""
        if self._scorer is None:
            return 0.50
        score = self._scorer.calculate_trust_score(
            verification_level=verification_level,
            history=history,
            capabilities=capabilities,
        )
        raw_score = getattr(score, "total_score", 500)
        return raw_score / 1000.0

    def report_slash(
        self,
        agent_did: str,
        reason: str,
        severity: str = "medium",
        evidence_hash: str | None = None,
    ) -> None:
        """Report a penalty event to the trust backend."""
        if self._scorer:
            self._scorer.slash_reputation(
                agent_did=agent_did,
                reason=reason,
                severity=severity,
                evidence_hash=evidence_hash,
            )

    def report_task_outcome(self, agent_did: str, outcome: str) -> None:
        """Report a task outcome for reputation tracking."""
        if self._scorer:
            self._scorer.record_task_outcome(agent_did, outcome)
