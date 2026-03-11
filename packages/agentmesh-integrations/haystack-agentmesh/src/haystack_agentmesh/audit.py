"""AuditLogger component for Haystack pipelines.

Append-only audit log with SHA-256 hash chain hashing and JSONL export.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

try:
    from haystack import component
except ImportError:  # pragma: no cover
    class _ComponentShim:
        def __call__(self, cls):
            return cls

        @staticmethod
        def input_types(**kwargs):
            def decorator(func):
                return func
            return decorator

        @staticmethod
        def output_types(**kwargs):
            def decorator(func):
                return func
            return decorator

    component = _ComponentShim()  # type: ignore[assignment]


@dataclass
class AuditEntry:
    """A single immutable audit record."""

    entry_id: str
    timestamp: float
    action: str
    agent_id: str
    decision: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    prev_hash: str = ""
    chain_hash: str = ""


def _hash_entry(entry: AuditEntry) -> str:
    """Compute SHA-256 hash chaining this entry to the previous one."""
    payload = (
        f"{entry.entry_id}|{entry.timestamp}|{entry.action}|"
        f"{entry.agent_id}|{entry.decision}|"
        f"{json.dumps(entry.metadata, sort_keys=True)}|{entry.prev_hash}"
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@component
class AuditLogger:
    """Append-only audit logger with SHA-256 hash chain integrity.

    Each entry is chained to the previous entry's hash, making the
    log tamper-evident.  Supports JSONL export for offline analysis.
    """

    def __init__(self) -> None:
        self._entries: List[AuditEntry] = []
        self._last_hash: str = "genesis"

    # ── Component interface ───────────────────────────────────────

    @component.input_types(
        action=str,
        agent_id=str,
        decision=str,
        metadata=Optional[Dict[str, Any]],
    )
    @component.output_types(entry_id=str, chain_hash=str)
    def run(
        self,
        action: str,
        agent_id: str,
        decision: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Record an audit entry and return ``entry_id`` and ``chain_hash``."""
        entry = AuditEntry(
            entry_id=uuid.uuid4().hex[:16],
            timestamp=time.time(),
            action=action,
            agent_id=agent_id,
            decision=decision,
            metadata=metadata or {},
            prev_hash=self._last_hash,
        )
        entry.chain_hash = _hash_entry(entry)
        self._last_hash = entry.chain_hash
        self._entries.append(entry)
        return {"entry_id": entry.entry_id, "chain_hash": entry.chain_hash}

    # ── Query helpers ─────────────────────────────────────────────

    @property
    def entries(self) -> List[AuditEntry]:
        """Return a copy of all audit entries."""
        return list(self._entries)

    def verify_chain(self) -> bool:
        """Verify the integrity of the full hash chain.

        Returns ``True`` if every entry's ``chain_hash`` matches its
        recomputed value and the ``prev_hash`` links are consistent.
        """
        prev = "genesis"
        for entry in self._entries:
            if entry.prev_hash != prev:
                return False
            if _hash_entry(entry) != entry.chain_hash:
                return False
            prev = entry.chain_hash
        return True

    def export_jsonl(self, path: str) -> int:
        """Export audit entries to a JSONL file. Returns entry count."""
        with open(path, "w") as fh:
            for entry in self._entries:
                fh.write(json.dumps(asdict(entry), default=str) + "\n")
        return len(self._entries)

    def to_jsonl_string(self) -> str:
        """Serialize all entries to a JSONL string."""
        lines = [json.dumps(asdict(e), default=str) for e in self._entries]
        return "\n".join(lines) + ("\n" if lines else "")
