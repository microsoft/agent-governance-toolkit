# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Quarantine Manager — isolates agents for a bounded duration.

A quarantine is an active, time-bounded record. ``is_quarantined`` and
``get_active_quarantine`` honour expiry, ``release`` lifts it early, and
``tick`` expires lapsed records. Re-quarantining an already-isolated agent
supersedes the prior record (escalation).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
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
    Enforces time-bounded agent quarantine within sessions.
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
        """Quarantine an agent for ``duration_seconds`` (default 300s).

        If the agent already has an active quarantine in this session, that
        record is released first so only the newest (escalated) record is active.
        """
        existing = self.get_active_quarantine(agent_did, session_id)
        if existing is not None:
            existing.is_active = False
            existing.released_at = datetime.now(UTC)

        now = datetime.now(UTC)
        seconds = self.DEFAULT_QUARANTINE_SECONDS if duration_seconds is None else duration_seconds
        record = QuarantineRecord(
            agent_did=agent_did,
            session_id=session_id,
            reason=reason,
            details=details,
            entered_at=now,
            expires_at=now + timedelta(seconds=seconds),
            is_active=True,
            forensic_data=forensic_data or {},
        )
        self._quarantines[record.quarantine_id] = record
        return record

    def release(self, agent_did: str, session_id: str) -> QuarantineRecord | None:
        """Release an agent's active quarantine early. Returns the record, or None."""
        record = self.get_active_quarantine(agent_did, session_id)
        if record is None:
            return None
        record.is_active = False
        record.released_at = datetime.now(UTC)
        return record

    def is_quarantined(self, agent_did: str, session_id: str) -> bool:
        """True if the agent has an active, unexpired quarantine in the session."""
        return self.get_active_quarantine(agent_did, session_id) is not None

    def get_active_quarantine(self, agent_did: str, session_id: str) -> QuarantineRecord | None:
        """Return the agent's active, unexpired quarantine, expiring lapsed ones lazily."""
        for record in self._quarantines.values():
            if record.agent_did != agent_did or record.session_id != session_id:
                continue
            if not record.is_active:
                continue
            if record.is_expired:
                record.is_active = False
                record.released_at = record.expires_at
                continue
            return record
        return None

    def tick(self) -> list[QuarantineRecord]:
        """Expire all lapsed active quarantines. Returns the records just expired."""
        expired: list[QuarantineRecord] = []
        for record in self._quarantines.values():
            if record.is_active and record.is_expired:
                record.is_active = False
                record.released_at = record.expires_at
                expired.append(record)
        return expired

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
        return [r for r in self._quarantines.values() if r.is_active and not r.is_expired]

    @property
    def quarantine_count(self) -> int:
        return len(self.active_quarantines)
