# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""
Liability Ledger — simple append-only fault log.

Public Preview: records fault events as (agent, type, timestamp, details).
No risk scoring, no admission decisions.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum


class LedgerEntryType(str, Enum):
    """Types of liability ledger entries."""

    VOUCH_GIVEN = "vouch_given"
    VOUCH_RECEIVED = "vouch_received"
    VOUCH_RELEASED = "vouch_released"
    SLASH_RECEIVED = "slash_received"
    SLASH_CASCADED = "slash_cascaded"
    QUARANTINE_ENTERED = "quarantine_entered"
    QUARANTINE_RELEASED = "quarantine_released"
    FAULT_ATTRIBUTED = "fault_attributed"
    CLEAN_SESSION = "clean_session"


@dataclass
class LedgerEntry:
    """A single entry in the liability ledger."""

    entry_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    agent_did: str = ""
    entry_type: LedgerEntryType = LedgerEntryType.CLEAN_SESSION
    session_id: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    severity: float = 0.0
    details: str = ""
    related_agent: str | None = None


@dataclass
class AgentRiskProfile:
    """Risk profile for an agent (Public Preview: always admits)."""

    agent_did: str
    total_entries: int = 0
    slash_count: int = 0
    quarantine_count: int = 0
    clean_session_count: int = 0
    fault_score_avg: float = 0.0
    risk_score: float = 0.0
    recommendation: str = "admit"


class LiabilityLedger:
    """
    Simple append-only fault log.

    Public Preview: records events for audit trail only.
    No risk scoring or admission logic.
    """

    PROBATION_THRESHOLD = 0.3
    DENY_THRESHOLD = 0.6

    def __init__(self) -> None:
        self._entries: list[LedgerEntry] = []
        self._by_agent: dict[str, list[LedgerEntry]] = {}

    def record(
        self,
        agent_did: str,
        entry_type: LedgerEntryType,
        session_id: str = "",
        severity: float = 0.0,
        details: str = "",
        related_agent: str | None = None,
    ) -> LedgerEntry:
        """Record a liability event."""
        entry = LedgerEntry(
            agent_did=agent_did,
            entry_type=entry_type,
            session_id=session_id,
            severity=severity,
            details=details,
            related_agent=related_agent,
        )
        self._entries.append(entry)
        self._by_agent.setdefault(agent_did, []).append(entry)
        return entry

    def get_agent_history(self, agent_did: str) -> list[LedgerEntry]:
        """Get all ledger entries for an agent."""
        return list(self._by_agent.get(agent_did, []))

    def compute_risk_profile(self, agent_did: str) -> AgentRiskProfile:
        """Return a basic risk profile (Public Preview: always admits)."""
        entries = self.get_agent_history(agent_did)
        return AgentRiskProfile(
            agent_did=agent_did,
            total_entries=len(entries),
            recommendation="admit",
        )

    def should_admit(self, agent_did: str) -> tuple[bool, str]:
        """Always admits in Public Preview."""
        return True, "admit"

    @property
    def total_entries(self) -> int:
        return len(self._entries)

    @property
    def tracked_agents(self) -> list[str]:
        return list(self._by_agent.keys())
