# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Hash Commitment — local commitment store with optional external anchoring.

Stores each session's audit hash-chain root as a verifiable commitment. By
default commitments are anchored locally (in-memory). Supplying an
``anchor_backend`` (any object exposing ``anchor(record) -> str``) records an
external anchor reference (e.g. a transaction id) for each commitment.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Protocol


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


class AnchorBackend(Protocol):
    """External anchoring backend (e.g. a ledger or notary service)."""

    def anchor(self, record: CommitmentRecord) -> str: ...


class CommitmentEngine:
    """
    Verifiable commitment store for session audit roots.

    Without an anchor backend this is a real local commitment ledger:
    ``commit`` stores a root and ``verify`` checks a presented root against it.
    With an anchor backend, each commitment also carries an external anchor
    reference.
    """

    def __init__(self, anchor_backend: AnchorBackend | None = None) -> None:
        self._commitments: dict[str, CommitmentRecord] = {}
        self._batch_queue: list[CommitmentRecord] = []
        self._anchor_backend = anchor_backend

    def commit(
        self,
        session_id: str,
        hash_chain_root: str,
        participant_dids: list[str],
        delta_count: int,
    ) -> CommitmentRecord:
        """Commit a session's Summary Hash, anchoring externally if configured."""
        record = CommitmentRecord(
            session_id=session_id,
            hash_chain_root=hash_chain_root,
            participant_dids=participant_dids,
            delta_count=delta_count,
        )
        if self._anchor_backend is not None:
            record.blockchain_tx_id = self._anchor_backend.anchor(record)
            record.committed_to = "external"
        self._commitments[session_id] = record
        return record

    def verify(self, session_id: str, expected_root: str) -> bool:
        """Verify a session's audit log root."""
        record = self._commitments.get(session_id)
        if not record:
            return False
        return record.hash_chain_root == expected_root

    def queue_for_batch(self, record: CommitmentRecord) -> None:
        """Queue a commitment for deferred (batched) anchoring."""
        self._batch_queue.append(record)

    def flush_batch(self) -> list[CommitmentRecord]:
        """Flush the batch queue, anchoring each queued record if a backend is set."""
        batch = list(self._batch_queue)
        if self._anchor_backend is not None:
            for record in batch:
                if record.blockchain_tx_id is None:
                    record.blockchain_tx_id = self._anchor_backend.anchor(record)
                    record.committed_to = "external"
        self._batch_queue.clear()
        return batch

    def get_commitment(self, session_id: str) -> CommitmentRecord | None:
        return self._commitments.get(session_id)
