# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""
Fault Logging — stub implementation.

Public Preview: assigns full liability to the direct-cause agent.
No causal chain analysis.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class FaultAttribution:
    """Fault attribution for an agent."""

    agent_did: str
    liability_score: float
    causal_contribution: float
    is_direct_cause: bool = False
    reason: str = ""


@dataclass
class AttributionResult:
    """Attribution result for a saga failure."""

    attribution_id: str = field(default_factory=lambda: f"attr:{uuid.uuid4().hex[:8]}")
    saga_id: str = ""
    session_id: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    attributions: list[FaultAttribution] = field(default_factory=list)
    causal_chain_length: int = 0
    root_cause_agent: str | None = None

    @property
    def agents_involved(self) -> list[str]:
        return [a.agent_did for a in self.attributions]

    def get_liability(self, agent_did: str) -> float:
        for a in self.attributions:
            if a.agent_did == agent_did:
                return a.liability_score
        return 0.0


class CausalAttributor:
    """Simple fault attribution — assigns liability to the direct cause agent."""

    def __init__(self) -> None:
        self._history: list[AttributionResult] = []

    def attribute(
        self,
        saga_id: str,
        session_id: str,
        agent_actions: dict[str, list[dict]],
        failure_step_id: str,
        failure_agent_did: str,
        risk_weights: dict[str, float] | None = None,
    ) -> AttributionResult:
        """Assign full liability to the direct-cause agent."""
        attributions = []
        for agent_did in agent_actions:
            attributions.append(FaultAttribution(
                agent_did=agent_did,
                liability_score=1.0 if agent_did == failure_agent_did else 0.0,
                causal_contribution=1.0 if agent_did == failure_agent_did else 0.0,
                is_direct_cause=(agent_did == failure_agent_did),
                reason="Direct cause" if agent_did == failure_agent_did else "",
            ))
        result = AttributionResult(
            saga_id=saga_id, session_id=session_id,
            attributions=attributions, root_cause_agent=failure_agent_did,
        )
        self._history.append(result)
        return result

    @property
    def attribution_history(self) -> list[AttributionResult]:
        return list(self._history)
