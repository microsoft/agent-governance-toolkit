# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Liability Ledger — append-only fault log with risk scoring and admission.

Records liability events per agent and derives a saturating risk score from the
severity of negative events (slashes, quarantines, faults), discounted by clean
sessions. The score drives an admission recommendation: admit / probation / deny.
"""

from __future__ import annotations

import math
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
    """Risk profile derived from an agent's liability history."""

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
    Append-only fault log with risk scoring and admission decisions.
    """

    PROBATION_THRESHOLD = 0.3
    DENY_THRESHOLD = 0.6

    # Negative event types and the severity assumed when an entry is recorded
    # without an explicit severity.
    _NEGATIVE_DEFAULT_SEVERITY = {
        LedgerEntryType.SLASH_RECEIVED: 0.6,
        LedgerEntryType.SLASH_CASCADED: 0.4,
        LedgerEntryType.QUARANTINE_ENTERED: 0.5,
        LedgerEntryType.FAULT_ATTRIBUTED: 0.5,
    }
    # Each clean session offsets this much accumulated negative severity.
    _REDEMPTION_PER_CLEAN = 0.1
    # Larger -> risk saturates more slowly with accumulated severity.
    _RISK_SCALE = 2.0

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
        """Derive a risk profile from the agent's recorded history.

        ``risk_score = 1 - exp(-raw / RISK_SCALE)`` where
        ``raw = max(0, Σ negative-severity - REDEMPTION_PER_CLEAN * clean_sessions)``.
        """
        entries = self.get_agent_history(agent_did)

        slash_count = 0
        quarantine_count = 0
        clean_count = 0
        neg_severities: list[float] = []

        for e in entries:
            if e.entry_type in (
                LedgerEntryType.SLASH_RECEIVED,
                LedgerEntryType.SLASH_CASCADED,
            ):
                slash_count += 1
            if e.entry_type == LedgerEntryType.QUARANTINE_ENTERED:
                quarantine_count += 1
            if e.entry_type == LedgerEntryType.CLEAN_SESSION:
                clean_count += 1
            if e.entry_type in self._NEGATIVE_DEFAULT_SEVERITY:
                default = self._NEGATIVE_DEFAULT_SEVERITY[e.entry_type]
                neg_severities.append(e.severity if e.severity > 0 else default)

        neg_sum = sum(neg_severities)
        fault_avg = (neg_sum / len(neg_severities)) if neg_severities else 0.0
        raw = max(0.0, neg_sum - self._REDEMPTION_PER_CLEAN * clean_count)
        risk_score = 1.0 - math.exp(-raw / self._RISK_SCALE)

        if risk_score >= self.DENY_THRESHOLD:
            recommendation = "deny"
        elif risk_score >= self.PROBATION_THRESHOLD:
            recommendation = "probation"
        else:
            recommendation = "admit"

        return AgentRiskProfile(
            agent_did=agent_did,
            total_entries=len(entries),
            slash_count=slash_count,
            quarantine_count=quarantine_count,
            clean_session_count=clean_count,
            fault_score_avg=fault_avg,
            risk_score=risk_score,
            recommendation=recommendation,
        )

    def should_admit(self, agent_did: str) -> tuple[bool, str]:
        """Admission decision. Denies only agents whose risk crosses DENY_THRESHOLD.

        Returns ``(admitted, reason)`` where reason is the recommendation:
        ``"admit"``, ``"probation"`` (admitted, flagged), or ``"deny"``.
        """
        profile = self.compute_risk_profile(agent_did)
        if profile.recommendation == "deny":
            return False, "deny"
        return True, profile.recommendation

    @property
    def total_entries(self) -> int:
        return len(self._entries)

    @property
    def tracked_agents(self) -> list[str]:
        return list(self._by_agent.keys())
