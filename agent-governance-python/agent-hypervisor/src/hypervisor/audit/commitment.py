# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""
Hash Commitment — stub implementation.

Public Preview: stores commitments in-memory only.
No blockchain anchoring.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class CommitmentRecord:
    """Record of a Summary Hash commitment."""

    session_id: str
    hash_chain_root: str
    participant_dids: list[str]
    delta_count: int
    committed_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    blockchain_tx_id: str | None = None
    committed_to: str = "local"


class CommitmentEngine:
    """
    Simple in-memory commitment store.

    Public Preview: stores commitments locally, no external anchoring.
    """

    def __init__(self) -> None:
        self._commitments: dict[str, CommitmentRecord] = {}
        self._batch_queue: list[CommitmentRecord] = []

    def commit(
        self,
        session_id: str,
        hash_chain_root: str,
        participant_dids: list[str],
        delta_count: int,
    ) -> CommitmentRecord:
        """Commit a session's Summary Hash."""
        record = CommitmentRecord(
            session_id=session_id,
            hash_chain_root=hash_chain_root,
            participant_dids=participant_dids,
            delta_count=delta_count,
        )
        self._commitments[session_id] = record
        return record

    def verify(self, session_id: str, expected_root: str) -> bool:
        """Verify a session's audit log root."""
        record = self._commitments.get(session_id)
        if not record:
            return False
        return record.hash_chain_root == expected_root

    def queue_for_batch(self, record: CommitmentRecord) -> None:
        """Queue a commitment (Public Preview: no-op)."""
        self._batch_queue.append(record)

    def flush_batch(self) -> list[CommitmentRecord]:
        """Flush the batch queue."""
        batch = list(self._batch_queue)
        self._batch_queue.clear()
        return batch

    def get_commitment(self, session_id: str) -> CommitmentRecord | None:
        return self._commitments.get(session_id)
