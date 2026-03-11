"""Audit logging node with hash chain tamper evidence for Flowise flows."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class AuditEntry:
    """A single audit log entry in the hash chain."""

    index: int
    timestamp: float
    data: dict[str, Any]
    previous_hash: str
    hash: str


class AuditNode:
    """Logs all inputs to a hash chain audit trail with SHA-256 hash chaining.

    Provides tamper-evident logging for governance decisions in Flowise flows.
    """

    def __init__(
        self,
        storage: str = "memory",
        file_path: str | None = None,
        export_format: str = "json",
    ) -> None:
        if storage not in ("memory", "file"):
            raise ValueError(f"Unsupported storage type: {storage}")
        if export_format not in ("json", "jsonl"):
            raise ValueError(f"Unsupported export format: {export_format}")
        if storage == "file" and not file_path:
            raise ValueError("file_path is required when storage='file'")

        self.storage = storage
        self.file_path = Path(file_path) if file_path else None
        self.export_format = export_format
        self._chain: list[AuditEntry] = []

    @staticmethod
    def _compute_hash(index: int, timestamp: float, data: dict, previous_hash: str) -> str:
        """Compute SHA-256 hash for a chain entry."""
        payload = json.dumps(
            {"index": index, "timestamp": timestamp, "data": data, "previous_hash": previous_hash},
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def log(self, data: dict[str, Any], timestamp: float | None = None) -> AuditEntry:
        """Append an entry to the audit chain."""
        index = len(self._chain)
        ts = timestamp if timestamp is not None else time.time()
        previous_hash = self._chain[-1].hash if self._chain else "0" * 64

        entry_hash = self._compute_hash(index, ts, data, previous_hash)
        entry = AuditEntry(
            index=index,
            timestamp=ts,
            data=data,
            previous_hash=previous_hash,
            hash=entry_hash,
        )
        self._chain.append(entry)

        if self.storage == "file" and self.file_path:
            self._write_to_file(entry)

        return entry

    def _write_to_file(self, entry: AuditEntry) -> None:
        """Persist an entry to file."""
        record = {
            "index": entry.index,
            "timestamp": entry.timestamp,
            "data": entry.data,
            "previous_hash": entry.previous_hash,
            "hash": entry.hash,
        }
        with open(self.file_path, "a", encoding="utf-8") as f:  # type: ignore[arg-type]
            if self.export_format == "jsonl":
                f.write(json.dumps(record, default=str) + "\n")
            else:
                # For JSON format, append as JSONL and export() returns valid JSON array
                f.write(json.dumps(record, default=str) + "\n")

    def verify_chain(self) -> bool:
        """Verify the integrity of the entire audit chain."""
        for i, entry in enumerate(self._chain):
            expected_prev = self._chain[i - 1].hash if i > 0 else "0" * 64
            if entry.previous_hash != expected_prev:
                return False
            expected_hash = self._compute_hash(entry.index, entry.timestamp, entry.data, entry.previous_hash)
            if entry.hash != expected_hash:
                return False
        return True

    def export(self) -> str:
        """Export the audit chain."""
        records = [
            {
                "index": e.index,
                "timestamp": e.timestamp,
                "data": e.data,
                "previous_hash": e.previous_hash,
                "hash": e.hash,
            }
            for e in self._chain
        ]
        if self.export_format == "jsonl":
            return "\n".join(json.dumps(r, default=str) for r in records)
        return json.dumps(records, indent=2, default=str)

    @property
    def chain(self) -> list[AuditEntry]:
        """Return the current chain."""
        return list(self._chain)

    def __len__(self) -> int:
        return len(self._chain)

    def run(self, input_data: dict[str, Any]) -> dict[str, Any]:
        """Flowise-compatible run method. Logs input and passes through."""
        entry = self.log(input_data)
        return {
            "audit_index": entry.index,
            "audit_hash": entry.hash,
            "chain_valid": self.verify_chain(),
            "output": input_data,
        }
