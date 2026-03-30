# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""
Kill Switch — simple hard kill.

Public Preview: immediate agent termination, no task transfer.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum


class KillReason(str, Enum):
    """Why an agent was killed."""

    BEHAVIORAL_DRIFT = "behavioral_drift"
    RATE_LIMIT = "rate_limit"
    RING_BREACH = "ring_breach"
    MANUAL = "manual"
    QUARANTINE_TIMEOUT = "quarantine_timeout"
    SESSION_TIMEOUT = "session_timeout"


class HandoffStatus(str, Enum):
    """Status of a saga step handoff."""

    PENDING = "pending"
    HANDED_OFF = "handed_off"
    FAILED = "failed"
    COMPENSATED = "compensated"


@dataclass
class StepHandoff:
    """A saga step being handed off (Public Preview: always COMPENSATED)."""

    step_id: str
    saga_id: str
    from_agent: str
    to_agent: str | None = None
    status: HandoffStatus = HandoffStatus.COMPENSATED


@dataclass
class KillResult:
    """Result of a kill switch operation."""

    kill_id: str = field(default_factory=lambda: f"kill:{uuid.uuid4().hex[:8]}")
    agent_did: str = ""
    session_id: str = ""
    reason: KillReason = KillReason.MANUAL
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    handoffs: list[StepHandoff] = field(default_factory=list)
    handoff_success_count: int = 0
    compensation_triggered: bool = False
    details: str = ""


class KillSwitch:
    """
    Simple hard kill (Public Preview: no handoff, immediate termination).
    """

    def __init__(self) -> None:
        self._kill_history: list[KillResult] = []
        self._substitutes: dict[str, list[str]] = {}

    def register_substitute(
        self, session_id: str, agent_did: str
    ) -> None:
        """Register a substitute (Public Preview: no-op, handoff not supported)."""
        self._substitutes.setdefault(session_id, []).append(agent_did)

    def unregister_substitute(
        self, session_id: str, agent_did: str
    ) -> None:
        subs = self._substitutes.get(session_id, [])
        if agent_did in subs:
            subs.remove(agent_did)

    def kill(
        self,
        agent_did: str,
        session_id: str,
        reason: KillReason,
        in_flight_steps: list[dict] | None = None,
        details: str = "",
    ) -> KillResult:
        """Kill an agent immediately (Public Preview: no handoff)."""
        in_flight = in_flight_steps or []

        handoffs = [
            StepHandoff(
                step_id=step_info.get("step_id", ""),
                saga_id=step_info.get("saga_id", ""),
                from_agent=agent_did,
                status=HandoffStatus.COMPENSATED,
            )
            for step_info in in_flight
        ]

        result = KillResult(
            agent_did=agent_did,
            session_id=session_id,
            reason=reason,
            handoffs=handoffs,
            handoff_success_count=0,
            compensation_triggered=len(handoffs) > 0,
            details=details,
        )
        self._kill_history.append(result)
        self.unregister_substitute(session_id, agent_did)
        return result

    def _find_substitute(
        self, session_id: str, exclude_did: str
    ) -> str | None:
        return None

    @property
    def kill_history(self) -> list[KillResult]:
        return list(self._kill_history)

    @property
    def total_kills(self) -> int:
        return len(self._kill_history)

    @property
    def total_handoffs(self) -> int:
        return 0
