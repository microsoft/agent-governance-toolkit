# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""
Quarantine Manager.

Records quarantined agents in-memory, enforces them via ``is_quarantined``,
expires them based on ``expires_at``, and supports manual release. State is
process-local (not persisted across restarts).
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
    Records and enforces agent quarantines (process-local, in-memory).
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
        """Quarantine an agent for ``duration_seconds`` (default
        ``DEFAULT_QUARANTINE_SECONDS``). The record is active and enforced until
        it expires or is released. Any prior active record for the same
        ``(agent_did, session_id)`` is superseded, so an agent has at most one
        active quarantine per session (history is retained)."""
        now = datetime.now(UTC)
        prior = self._find_active(agent_did, session_id)
        if prior is not None:
            prior.is_active = False
            prior.released_at = now
        dur = duration_seconds if duration_seconds is not None else self.DEFAULT_QUARANTINE_SECONDS
        record = QuarantineRecord(
            agent_did=agent_did,
            session_id=session_id,
            reason=reason,
            details=details,
            entered_at=now,
            expires_at=now + timedelta(seconds=dur),
            is_active=True,
            forensic_data=forensic_data or {},
        )
        self._quarantines[record.quarantine_id] = record
        return record

    def release(self, agent_did: str, session_id: str) -> QuarantineRecord | None:
        """Release the agent's active quarantine(s) early. Clears EVERY active,
        unexpired record for (agent_did, session_id) so ``is_quarantined`` is
        False afterward even if the agent was quarantined more than once. Already
        expired records are left for ``tick`` (releasing them here would stamp a
        late ``released_at`` and overstate ``duration_seconds``). Returns the most
        recently entered released record, or None if none were active."""
        now = datetime.now(UTC)
        released = [
            record
            for record in self._quarantines.values()
            if record.agent_did == agent_did
            and record.session_id == session_id
            and record.is_active
            and not record.is_expired
        ]
        if not released:
            return None
        for record in released:
            record.is_active = False
            record.released_at = now
        return max(released, key=lambda r: r.entered_at)

    def is_quarantined(self, agent_did: str, session_id: str) -> bool:
        """True if the agent has an active, unexpired quarantine for the session."""
        return self._find_active(agent_did, session_id) is not None

    def get_active_quarantine(self, agent_did: str, session_id: str) -> QuarantineRecord | None:
        return self._find_active(agent_did, session_id)

    def tick(self) -> list[QuarantineRecord]:
        """Expire any active records whose ``expires_at`` has passed. Returns
        the records that were expired by this call."""
        expired: list[QuarantineRecord] = []
        now = datetime.now(UTC)
        for record in self._quarantines.values():
            if record.is_active and record.is_expired:
                record.is_active = False
                if record.released_at is None:
                    record.released_at = record.expires_at or now
                expired.append(record)
        return expired

    def _find_active(self, agent_did: str, session_id: str) -> QuarantineRecord | None:
        for record in self._quarantines.values():
            if (
                record.agent_did == agent_did
                and record.session_id == session_id
                and record.is_active
                and not record.is_expired
            ):
                return record
        return None

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
