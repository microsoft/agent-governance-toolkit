# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Verification Integration Stub — Behavioral Verification adapter.

Provides the interface for integrating a behavioral verification
system with the Hypervisor. Supply your own verifier implementation.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Protocol


class VerificationBackend(Protocol):
    """Protocol for a behavioral verification backend."""

    def verify_embeddings(
        self,
        embedding_a: Any,
        embedding_b: Any,
        metric: str = "cosine",
        weights: Any = None,
        threshold_profile: str | None = None,
        explain: bool = False,
    ) -> Any: ...


class DriftSeverity(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class DriftCheckResult:
    """Result of a behavioral verification check."""

    agent_did: str
    session_id: str
    drift_score: float
    severity: DriftSeverity
    passed: bool
    explanation: str | None = None
    action_id: str | None = None
    checked_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def should_slash(self) -> bool:
        return self.severity in (DriftSeverity.HIGH, DriftSeverity.CRITICAL)

    @property
    def should_demote(self) -> bool:
        return self.severity == DriftSeverity.MEDIUM


@dataclass
class DriftThresholds:
    low: float = 0.15
    medium: float = 0.30
    high: float = 0.50
    critical: float = 0.75


class VerificationAdapter:
    """Stub adapter for behavioral verification integration."""

    def __init__(
        self,
        verifier: VerificationBackend | None = None,
        thresholds: DriftThresholds | None = None,
        on_drift_detected: Callable[[DriftCheckResult], None] | None = None,
    ) -> None:
        self._verifier = verifier
        self.thresholds = thresholds or DriftThresholds()
        self._on_drift_detected = on_drift_detected
        self._check_history: list[DriftCheckResult] = []

    def check_behavioral_drift(
        self,
        agent_did: str,
        session_id: str,
        claimed_embedding: Any,
        observed_embedding: Any,
        action_id: str | None = None,
        metric: str = "cosine",
        threshold_profile: str | None = None,
    ) -> DriftCheckResult:
        """Check for behavioral drift. Returns a pass-through result when no verifier is configured."""
        result = DriftCheckResult(
            agent_did=agent_did,
            session_id=session_id,
            drift_score=0.0,
            severity=DriftSeverity.NONE,
            passed=True,
            action_id=action_id,
        )
        self._check_history.append(result)
        return result

    def get_agent_drift_history(self, agent_did: str, session_id: str | None = None) -> list[DriftCheckResult]:
        return [r for r in self._check_history if r.agent_did == agent_did and (session_id is None or r.session_id == session_id)]

    def get_drift_rate(self, agent_did: str, session_id: str | None = None) -> float:
        history = self.get_agent_drift_history(agent_did, session_id)
        if not history:
            return 0.0
        return sum(1 for r in history if not r.passed) / len(history)

    @property
    def total_checks(self) -> int:
        return len(self._check_history)

    @property
    def total_violations(self) -> int:
        return sum(1 for r in self._check_history if not r.passed)
