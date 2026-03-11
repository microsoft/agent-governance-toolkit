"""Tamper-evident audit logging with hash chain."""

from __future__ import annotations

import hashlib
import json
import time
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class AuditEntry:
    """An immutable audit log entry."""

    timestamp: float
    agent_id: str
    action: str
    decision: str  # "allow", "deny", "warn"
    details: dict = field(default_factory=dict)
    previous_hash: str = ""
    entry_hash: str = ""

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "agent_id": self.agent_id,
            "action": self.action,
            "decision": self.decision,
            "details": self.details,
            "previous_hash": self.previous_hash,
            "entry_hash": self.entry_hash,
        }


class AuditLog:
    """Tamper-evident audit log using hash chain hashing."""

    def __init__(self):
        self._entries: List[AuditEntry] = []
        self._lock = threading.Lock()

    def _compute_hash(self, entry_data: dict, previous_hash: str) -> str:
        payload = json.dumps(entry_data, sort_keys=True) + previous_hash
        return hashlib.sha256(payload.encode()).hexdigest()

    def record(
        self,
        agent_id: str,
        action: str,
        decision: str,
        details: Optional[dict] = None,
    ) -> AuditEntry:
        """Record a new audit entry with hash chain hash."""
        with self._lock:
            previous_hash = self._entries[-1].entry_hash if self._entries else ""
            entry_data = {
                "timestamp": time.time(),
                "agent_id": agent_id,
                "action": action,
                "decision": decision,
                "details": details or {},
            }
            entry_hash = self._compute_hash(entry_data, previous_hash)
            entry = AuditEntry(
                timestamp=entry_data["timestamp"],
                agent_id=agent_id,
                action=action,
                decision=decision,
                details=details or {},
                previous_hash=previous_hash,
                entry_hash=entry_hash,
            )
            self._entries.append(entry)
            return entry

    def verify_chain(self) -> bool:
        """Verify the integrity of the entire audit chain."""
        with self._lock:
            for i, entry in enumerate(self._entries):
                previous_hash = self._entries[i - 1].entry_hash if i > 0 else ""
                if entry.previous_hash != previous_hash:
                    return False
                entry_data = {
                    "timestamp": entry.timestamp,
                    "agent_id": entry.agent_id,
                    "action": entry.action,
                    "decision": entry.decision,
                    "details": entry.details,
                }
                expected = self._compute_hash(entry_data, previous_hash)
                if entry.entry_hash != expected:
                    return False
            return True

    def get_entries(
        self,
        agent_id: Optional[str] = None,
        decision: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[AuditEntry]:
        """Query audit entries with optional filters."""
        with self._lock:
            entries = list(self._entries)

        if agent_id:
            entries = [e for e in entries if e.agent_id == agent_id]
        if decision:
            entries = [e for e in entries if e.decision == decision]
        if limit:
            entries = entries[-limit:]
        return entries

    def __len__(self) -> int:
        return len(self._entries)
