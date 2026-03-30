# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""
Delta Audit Engine — simple append-only log.

Public Preview: records (timestamp, action, data) tuples.
No audit loging or tamper-evidence.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime


@dataclass
class VFSChange:
    """A single change within a delta."""

    path: str
    operation: str
    content_hash: str | None = None
    previous_hash: str | None = None
    agent_did: str | None = None


@dataclass
class SemanticDelta:
    """A delta capturing VFS state changes at a single turn."""

    delta_id: str
    turn_id: int
    session_id: str
    agent_did: str
    timestamp: datetime
    changes: list[VFSChange]
    parent_hash: str | None
    delta_hash: str = ""

    def compute_hash(self) -> str:
        """Compute a simple hash of this delta (no chaining)."""
        payload = json.dumps(
            {
                "delta_id": self.delta_id,
                "turn_id": self.turn_id,
                "session_id": self.session_id,
                "agent_did": self.agent_did,
                "timestamp": self.timestamp.isoformat(),
            },
            sort_keys=True,
        )
        self.delta_hash = hashlib.sha256(payload.encode()).hexdigest()
        return self.delta_hash


class DeltaEngine:
    """
    Simple append-only audit log.

    Public Preview: captures deltas as timestamped records.
    No audit log verification.
    """

    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        self._deltas: list[SemanticDelta] = []
        self._turn_counter = 0

    def capture(
        self,
        agent_did: str,
        changes: list[VFSChange],
        delta_id: str | None = None,
    ) -> SemanticDelta:
        """Capture a delta for a turn."""
        self._turn_counter += 1
        delta = SemanticDelta(
            delta_id=delta_id or f"delta:{self._turn_counter}",
            turn_id=self._turn_counter,
            session_id=self.session_id,
            agent_did=agent_did,
            timestamp=datetime.now(UTC),
            changes=changes,
            parent_hash=None,
        )
        delta.compute_hash()
        self._deltas.append(delta)
        return delta

    def compute_hash_chain_root(self) -> str | None:
        """Return hash of last delta (Public Preview: no Merkle tree)."""
        if not self._deltas:
            return None
        return self._deltas[-1].delta_hash

    def verify_chain(self) -> bool:
        """Always returns True (Public Preview: no chain verification)."""
        return True

    @property
    def deltas(self) -> list[SemanticDelta]:
        return list(self._deltas)

    @property
    def turn_count(self) -> int:
        return self._turn_counter
