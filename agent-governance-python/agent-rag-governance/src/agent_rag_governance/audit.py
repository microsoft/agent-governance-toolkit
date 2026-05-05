# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Structured audit logging for RAG retrieval calls.

Emits JSON-lines entries to a file or stdout. Each entry records the
agent identity, target collection, a privacy-safe query hash, chunk
counts, and the governance decision — enabling EU AI Act traceability
requirements without exposing raw query text.
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


@dataclass
class RAGAuditEntry:
    """A single audit record for one retrieval call.

    Attributes:
        timestamp: ISO 8601 UTC timestamp of the call.
        agent_id: Identifier of the agent that made the retrieval.
        collection: Name of the target collection.
        query_hash: SHA-256 hex digest of the raw query string. The raw
            query is never logged to avoid leaking sensitive search terms.
        num_chunks_retrieved: Number of chunks returned by the retriever
            before content scanning.
        num_chunks_blocked: Number of chunks withheld after content scanning.
        decision: Governance outcome — ``"allowed"``, ``"denied"``, or
            ``"rate_limited"``.
        policy_triggered: Name of the specific policy that caused a non-
            ``"allowed"`` decision, or ``None`` for clean passes.
    """

    timestamp: str
    agent_id: str
    collection: str
    query_hash: str
    num_chunks_retrieved: int
    num_chunks_blocked: int
    decision: str
    policy_triggered: Optional[str]

    @staticmethod
    def hash_query(query: str) -> str:
        """Return a SHA-256 hex digest of *query*."""
        return hashlib.sha256(query.encode("utf-8")).hexdigest()

    def to_json(self) -> str:
        """Serialize to a single-line JSON string."""
        return json.dumps(asdict(self))


class AuditLogger:
    """Emits :class:`RAGAuditEntry` records to a file or stdout.

    Args:
        log_path: Path to the JSON-lines log file. ``None`` writes to
            stdout.

    Example::

        logger = AuditLogger(log_path="/var/log/rag-audit.jsonl")
        logger.emit(entry)
    """

    def __init__(self, log_path: Optional[str] = None) -> None:
        self._path = Path(log_path) if log_path else None

    def emit(self, entry: RAGAuditEntry) -> None:
        """Write *entry* as a JSON line."""
        line = entry.to_json() + "\n"
        if self._path is None:
            sys.stdout.write(line)
            sys.stdout.flush()
        else:
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(line)


def make_entry(
    *,
    agent_id: str,
    collection: str,
    query: str,
    num_chunks_retrieved: int,
    num_chunks_blocked: int,
    decision: str,
    policy_triggered: Optional[str] = None,
) -> RAGAuditEntry:
    """Convenience factory for :class:`RAGAuditEntry`.

    Args:
        agent_id: Agent identifier.
        collection: Target collection name.
        query: Raw query string — hashed before storage.
        num_chunks_retrieved: Chunk count before scanning.
        num_chunks_blocked: Chunk count withheld by scanner.
        decision: ``"allowed"``, ``"denied"``, or ``"rate_limited"``.
        policy_triggered: Policy name that caused non-allowed decision.

    Returns:
        A populated :class:`RAGAuditEntry`.
    """
    return RAGAuditEntry(
        timestamp=datetime.now(timezone.utc).isoformat(),
        agent_id=agent_id,
        collection=collection,
        query_hash=RAGAuditEntry.hash_query(query),
        num_chunks_retrieved=num_chunks_retrieved,
        num_chunks_blocked=num_chunks_blocked,
        decision=decision,
        policy_triggered=policy_triggered,
    )
