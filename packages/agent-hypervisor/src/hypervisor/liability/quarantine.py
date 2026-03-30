# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""
Quarantine Manager — stub implementation.

Public Preview: quarantine is not enforced. Calls return safe defaults.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum


class QuarantineReason(str, Enum):
    """Why an agent was quarantined."""

    BEHAVIORAL_DRIFT = "behavioral_drift"
    LIABILITY_VIOLATION = "liability_violation"
    RING_BREACH = "ring_breach"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    MANUAL = "manual"
    CASCADE_SLASH = "cascade_slash"


@dataclass
class QuarantineRecord:
    """Record of an agent in quarantine."""

    quarantine_id: str = field(default_factory=lambda: f"quar:{uuid.uuid4().hex[:8]}")
    agent_did: str = ""
    session_id: str = ""
    reason: QuarantineReason = QuarantineReason.MANUAL
    details: str = ""
    entered_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime | None = None
    released_at: datetime | None = None
    is_active: bool = True
    forensic_data: dict = field(default_factory=dict)

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.now(UTC) > self.expires_at

    @property
    def duration_seconds(self) -> float:
        end = self.released_at or datetime.now(UTC)
        return (end - self.entered_at).total_seconds()


class QuarantineManager:
    """
    Quarantine stub (Public Preview: no quarantine enforcement).
    """

    DEFAULT_QUARANTINE_SECONDS = 300

    def __init__(self) -> None:
        self._quarantines: dict[str, QuarantineRecord] = {}

    def quarantine(
        self,
        agent_did: str,
        session_id: str,
        reason: QuarantineReason,
        details: str = "",
        duration_seconds: int | None = None,
        forensic_data: dict | None = None,
    ) -> QuarantineRecord:
        """Log a quarantine request (Public Preview: no enforcement)."""
        record = QuarantineRecord(
            agent_did=agent_did,
            session_id=session_id,
            reason=reason,
            details=details,
            is_active=False,
        )
        self._quarantines[record.quarantine_id] = record
        return record

    def release(self, agent_did: str, session_id: str) -> QuarantineRecord | None:
        """No-op in Public Preview."""
        return None

    def is_quarantined(self, agent_did: str, session_id: str) -> bool:
        """Always False in Public Preview."""
        return False

    def get_active_quarantine(
        self, agent_did: str, session_id: str
    ) -> QuarantineRecord | None:
        return None

    def tick(self) -> list[QuarantineRecord]:
        return []

    def get_history(
        self, agent_did: str | None = None, session_id: str | None = None
    ) -> list[QuarantineRecord]:
        """Get quarantine history, optionally filtered."""
        records = list(self._quarantines.values())
        if agent_did:
            records = [r for r in records if r.agent_did == agent_did]
        if session_id:
            records = [r for r in records if r.session_id == session_id]
        return records

    @property
    def active_quarantines(self) -> list[QuarantineRecord]:
        return []

    @property
    def quarantine_count(self) -> int:
        return 0
