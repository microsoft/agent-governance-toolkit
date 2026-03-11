"""Audit trail component with SHA-256 hash chain.

Captures agent actions, governance decisions, and context in a
tamper-evident chain. Supports JSONL export for compliance.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


GENESIS_HASH = "0" * 64


@dataclass
class AuditEntry:
    """Single audit record in the hash chain."""

    agent_id: str
    action: str
    decision: str
    timestamp: float
    context: Dict[str, Any] = field(default_factory=dict)
    entry_hash: str = ""
    previous_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "agent_id": self.agent_id,
            "action": self.action,
            "decision": self.decision,
            "timestamp": self.timestamp,
            "context": self.context,
            "entry_hash": self.entry_hash,
            "previous_hash": self.previous_hash,
        }

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), sort_keys=True)


class AuditLogger:
    """Append-only audit logger with SHA-256 hash chain.

    Each entry's hash includes the previous entry's hash, creating
    a tamper-evident chain. If any entry is modified, all subsequent
    hashes become invalid.

    Langflow component metadata:
    - display_name: "Audit Logger"
    - description: "Records governance decisions in a tamper-evident chain"
    - icon: "file-text"
    """

    display_name = "Audit Logger"
    description = "Records governance decisions in a tamper-evident chain"
    icon = "file-text"

    def __init__(self) -> None:
        self._entries: List[AuditEntry] = []
        self._last_hash: str = GENESIS_HASH

    @staticmethod
    def _compute_hash(
        agent_id: str,
        action: str,
        decision: str,
        timestamp: float,
        context: Dict[str, Any],
        previous_hash: str,
    ) -> str:
        """Compute SHA-256 hash for an entry."""
        payload = json.dumps(
            {
                "agent_id": agent_id,
                "action": action,
                "decision": decision,
                "timestamp": timestamp,
                "context": context,
                "previous_hash": previous_hash,
            },
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def log(
        self,
        agent_id: str,
        action: str,
        decision: str,
        context: Optional[Dict[str, Any]] = None,
        timestamp: Optional[float] = None,
    ) -> AuditEntry:
        """Append an entry to the audit chain."""
        ts = timestamp if timestamp is not None else time.time()
        ctx = context or {}

        entry_hash = self._compute_hash(
            agent_id=agent_id,
            action=action,
            decision=decision,
            timestamp=ts,
            context=ctx,
            previous_hash=self._last_hash,
        )

        entry = AuditEntry(
            agent_id=agent_id,
            action=action,
            decision=decision,
            timestamp=ts,
            context=ctx,
            entry_hash=entry_hash,
            previous_hash=self._last_hash,
        )

        self._entries.append(entry)
        self._last_hash = entry_hash
        return entry

    @property
    def entries(self) -> List[AuditEntry]:
        """Get all audit entries."""
        return list(self._entries)

    @property
    def chain_length(self) -> int:
        """Number of entries in the chain."""
        return len(self._entries)

    def verify_chain(self) -> bool:
        """Verify the integrity of the entire hash chain.

        Returns True if all hashes are valid and properly linked.
        """
        if not self._entries:
            return True

        expected_prev = GENESIS_HASH
        for entry in self._entries:
            if entry.previous_hash != expected_prev:
                return False

            expected_hash = self._compute_hash(
                agent_id=entry.agent_id,
                action=entry.action,
                decision=entry.decision,
                timestamp=entry.timestamp,
                context=entry.context,
                previous_hash=entry.previous_hash,
            )
            if entry.entry_hash != expected_hash:
                return False

            expected_prev = entry.entry_hash

        return True

    def export_jsonl(self) -> str:
        """Export all entries as JSONL for compliance."""
        lines = [entry.to_json() for entry in self._entries]
        return "\n".join(lines)

    def export_jsonl_to_file(self, path: str) -> int:
        """Export entries to a JSONL file. Returns number of entries written."""
        content = self.export_jsonl()
        with open(path, "w") as f:
            f.write(content)
            if content:
                f.write("\n")
        return len(self._entries)

    def summary(self) -> Dict[str, Any]:
        """Get summary statistics."""
        decisions: Dict[str, int] = {}
        agents: set = set()
        for entry in self._entries:
            decisions[entry.decision] = decisions.get(entry.decision, 0) + 1
            agents.add(entry.agent_id)

        return {
            "total_entries": len(self._entries),
            "unique_agents": len(agents),
            "decisions": decisions,
            "chain_valid": self.verify_chain(),
        }
