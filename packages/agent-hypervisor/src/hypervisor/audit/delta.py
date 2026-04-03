# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Delta Audit Engine — tamper-evident append-only audit log.

Records VFS state changes as a SHA-256 hash chain where each entry
links to its predecessor, providing cryptographic tamper evidence.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Optional


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

    def _build_hash_input(self) -> str:
        changes_data = [
            {
                "path": c.path,
                "operation": c.operation,
                "content_hash": c.content_hash,
                "previous_hash": c.previous_hash,
                "agent_did": c.agent_did,
            }
            for c in self.changes
        ]
        return json.dumps(
            {
                "delta_id": self.delta_id,
                "turn_id": self.turn_id,
                "session_id": self.session_id,
                "agent_did": self.agent_did,
                "timestamp": self.timestamp.isoformat(),
                "parent_hash": self.parent_hash or "",
                "changes": changes_data,
            },
            sort_keys=True,
        )

    def compute_hash(self) -> str:
        """Compute SHA-256 hash covering all fields including changes and parent linkage."""
        self.delta_hash = hashlib.sha256(self._build_hash_input().encode()).hexdigest()
        return self.delta_hash

    def verify_hash(self) -> bool:
        """Recompute hash and compare to stored value without mutation."""
        expected = hashlib.sha256(self._build_hash_input().encode()).hexdigest()
        return expected == self.delta_hash


class DeltaEngine:
    """Tamper-evident append-only audit log with SHA-256 hash chain verification."""

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
        """Capture a delta for a turn, chaining to previous entry."""
        self._turn_counter += 1
        parent_hash = self._deltas[-1].delta_hash if self._deltas else None
        delta = SemanticDelta(
            delta_id=delta_id or f"delta:{self._turn_counter}",
            turn_id=self._turn_counter,
            session_id=self.session_id,
            agent_did=agent_did,
            timestamp=datetime.now(UTC),
            changes=changes,
            parent_hash=parent_hash,
        )
        delta.compute_hash()
        self._deltas.append(delta)
        return delta

    def compute_hash_chain_root(self) -> str | None:
        """Return hash of last delta in the chain."""
        if not self._deltas:
            return None
        return self._deltas[-1].delta_hash

    def verify_chain(self) -> tuple[bool, Optional[str]]:
        """Verify full chain integrity: hash correctness and parent linkage."""
        if not self._deltas:
            return True, None

        previous_hash = None
        for i, delta in enumerate(self._deltas):
            if not delta.verify_hash():
                return False, f"Entry {i} hash mismatch"
            if delta.parent_hash != previous_hash:
                return False, f"Entry {i} chain broken"
            previous_hash = delta.delta_hash

        return True, None

    @property
    def deltas(self) -> list[SemanticDelta]:
        return list(self._deltas)

    @property
    def turn_count(self) -> int:
        return self._turn_counter
