# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
CMVK Audit Trail Module

Provides immutable audit logging for verification operations.
All verifications can be logged with timestamps, inputs, and results
for compliance and forensic analysis.
"""

from __future__ import annotations

import hashlib
import json
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np


@dataclass(frozen=True)
class AuditEntry:
    """
    Immutable audit record for a single verification.

    All fields are frozen to ensure auditability.

    Attributes:
        id: Unique identifier for this verification
        timestamp: UTC timestamp of verification
        operation: Type of verification operation
        inputs_hash: SHA-256 hash of input data (for privacy)
        result_summary: Summary of verification result
        drift_score: The drift score from verification
        confidence: The confidence score
        metric_used: Distance metric used
        profile_used: Threshold profile applied (if any)
        passed: Whether verification passed thresholds
        metadata: Additional context (user, session, etc.)
        checksum: Integrity checksum for this entry
    """

    id: str
    timestamp: str
    operation: str
    inputs_hash: str
    result_summary: dict
    drift_score: float
    confidence: float
    metric_used: str
    profile_used: str | None
    passed: bool
    metadata: dict
    checksum: str

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return asdict(self)

    def verify_integrity(self) -> bool:
        """Verify the entry's checksum is valid."""
        computed = _compute_checksum(
            self.id,
            self.timestamp,
            self.operation,
            self.inputs_hash,
            self.drift_score,
            self.confidence,
        )
        return computed == self.checksum


@dataclass
class AuditTrail:
    """
    Audit trail manager for verification operations.

    Maintains an immutable log of all verifications with optional
    persistence to file.

    Thread-safe for concurrent verifications.
    """

    entries: list[AuditEntry] = field(default_factory=list)
    persist_path: Path | None = None
    auto_persist: bool = False
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        """Load existing entries if persist path exists."""
        if self.persist_path and self.persist_path.exists():
            self._load_from_file()

    def log(
        self,
        operation: str,
        inputs: dict[str, Any],
        drift_score: float,
        confidence: float,
        metric_used: str = "cosine",
        profile_used: str | None = None,
        passed: bool = True,
        result_details: dict | None = None,
        metadata: dict | None = None,
    ) -> AuditEntry:
        """
        Log a verification operation.

        Args:
            operation: Type of operation (e.g., "verify_embeddings")
            inputs: Input data (will be hashed, not stored directly)
            drift_score: Drift score from verification
            confidence: Confidence score
            metric_used: Distance metric used
            profile_used: Threshold profile applied
            passed: Whether verification passed
            result_details: Additional result information
            metadata: Additional context (user, session, etc.)

        Returns:
            The created AuditEntry
        """
        entry_id = str(uuid.uuid4())
        timestamp = datetime.now(UTC).isoformat()
        inputs_hash = _hash_inputs(inputs)

        checksum = _compute_checksum(
            entry_id,
            timestamp,
            operation,
            inputs_hash,
            drift_score,
            confidence,
        )

        entry = AuditEntry(
            id=entry_id,
            timestamp=timestamp,
            operation=operation,
            inputs_hash=inputs_hash,
            result_summary=result_details or {},
            drift_score=drift_score,
            confidence=confidence,
            metric_used=metric_used,
            profile_used=profile_used,
            passed=passed,
            metadata=metadata or {},
            checksum=checksum,
        )

        with self._lock:
            self.entries.append(entry)
            if self.auto_persist and self.persist_path:
                self._persist_entry(entry)

        return entry

    def get_entries(
        self,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        operation: str | None = None,
        passed_only: bool | None = None,
    ) -> list[AuditEntry]:
        """
        Query audit entries with optional filters.

        Args:
            start_time: Filter entries after this time
            end_time: Filter entries before this time
            operation: Filter by operation type
            passed_only: If True, only passed; if False, only failed; if None, all

        Returns:
            List of matching AuditEntry records
        """
        with self._lock:
            results = list(self.entries)

        if start_time:
            start_iso = start_time.isoformat()
            results = [e for e in results if e.timestamp >= start_iso]

        if end_time:
            end_iso = end_time.isoformat()
            results = [e for e in results if e.timestamp <= end_iso]

        if operation:
            results = [e for e in results if e.operation == operation]

        if passed_only is not None:
            results = [e for e in results if e.passed == passed_only]

        return results

    def get_statistics(self) -> dict:
        """
        Calculate summary statistics for the audit trail.

        Returns:
            Dictionary with counts, pass rates, and drift statistics
        """
        with self._lock:
            entries = list(self.entries)

        if not entries:
            return {"total_entries": 0}

        drift_scores = [e.drift_score for e in entries]
        passed_count = sum(1 for e in entries if e.passed)

        # Group by operation
        by_operation: dict[str, list[AuditEntry]] = {}
        for e in entries:
            by_operation.setdefault(e.operation, []).append(e)

        operation_stats = {
            op: {
                "count": len(ops),
                "pass_rate": sum(1 for e in ops if e.passed) / len(ops),
                "mean_drift": float(np.mean([e.drift_score for e in ops])),
            }
            for op, ops in by_operation.items()
        }

        return {
            "total_entries": len(entries),
            "passed_count": passed_count,
            "failed_count": len(entries) - passed_count,
            "pass_rate": passed_count / len(entries),
            "mean_drift": float(np.mean(drift_scores)),
            "std_drift": float(np.std(drift_scores)),
            "min_drift": float(np.min(drift_scores)),
            "max_drift": float(np.max(drift_scores)),
            "by_operation": operation_stats,
        }

    def verify_integrity(self) -> tuple[bool, list[str]]:
        """
        Verify integrity of all audit entries.

        Returns:
            Tuple of (all_valid, list of invalid entry IDs)
        """
        invalid_ids = []
        with self._lock:
            for entry in self.entries:
                if not entry.verify_integrity():
                    invalid_ids.append(entry.id)

        return len(invalid_ids) == 0, invalid_ids

    def export_json(self, path: Path | str) -> None:
        """Export audit trail to JSON file."""
        path = Path(path)
        with self._lock:
            data = {
                "exported_at": datetime.now(UTC).isoformat(),
                "entry_count": len(self.entries),
                "entries": [e.to_dict() for e in self.entries],
            }

        path.write_text(json.dumps(data, indent=2))

    def export_csv(self, path: Path | str) -> None:
        """Export audit trail to CSV file."""
        import csv

        path = Path(path)
        with self._lock:
            entries = list(self.entries)

        if not entries:
            path.write_text("")
            return

        fieldnames = [
            "id",
            "timestamp",
            "operation",
            "drift_score",
            "confidence",
            "metric_used",
            "profile_used",
            "passed",
            "inputs_hash",
        ]

        with path.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for entry in entries:
                writer.writerow({k: getattr(entry, k) for k in fieldnames})

    def _load_from_file(self) -> None:
        """Load entries from persist file."""
        if not self.persist_path or not self.persist_path.exists():
            return

        try:
            data = json.loads(self.persist_path.read_text())
            for entry_dict in data.get("entries", []):
                self.entries.append(AuditEntry(**entry_dict))
        except (json.JSONDecodeError, TypeError) as e:
            # Log warning but don't fail
            print(f"Warning: Could not load audit trail from {self.persist_path}: {e}")

    def _persist_entry(self, entry: AuditEntry) -> None:
        """Append entry to persist file."""
        if not self.persist_path:
            return

        # Read existing or create new
        if self.persist_path.exists():
            try:
                data = json.loads(self.persist_path.read_text())
            except json.JSONDecodeError:
                data = {"entries": []}
        else:
            data = {"entries": []}

        data["entries"].append(entry.to_dict())
        data["updated_at"] = datetime.now(UTC).isoformat()
        data["entry_count"] = len(data["entries"])

        self.persist_path.write_text(json.dumps(data, indent=2))

    def clear(self) -> None:
        """Clear all entries (use with caution)."""
        with self._lock:
            self.entries.clear()


# ============================================================================
# Helper Functions
# ============================================================================


def _hash_inputs(inputs: dict[str, Any]) -> str:
    """Create SHA-256 hash of inputs for privacy-preserving audit."""

    def serialize(obj: Any) -> Any:
        """Convert objects to JSON-serializable format."""
        if isinstance(obj, np.ndarray) or hasattr(obj, "tolist"):
            return obj.tolist()
        elif hasattr(obj, "__dict__"):
            return str(type(obj).__name__)
        return obj

    # Create deterministic JSON representation
    serialized = json.dumps(
        {k: serialize(v) for k, v in sorted(inputs.items())},
        sort_keys=True,
    )
    return hashlib.sha256(serialized.encode()).hexdigest()


def _compute_checksum(*values: Any) -> str:
    """Compute checksum for audit entry integrity."""
    content = "|".join(str(v) for v in values)
    return hashlib.sha256(content.encode()).hexdigest()[:16]


# ============================================================================
# Global Audit Trail Instance
# ============================================================================

_global_audit_trail: AuditTrail | None = None


def get_audit_trail() -> AuditTrail:
    """Get or create the global audit trail instance."""
    global _global_audit_trail
    if _global_audit_trail is None:
        _global_audit_trail = AuditTrail()
    return _global_audit_trail


def configure_audit_trail(
    persist_path: Path | str | None = None,
    auto_persist: bool = False,
) -> AuditTrail:
    """
    Configure the global audit trail.

    Args:
        persist_path: Path to persist audit entries
        auto_persist: Whether to automatically persist each entry

    Returns:
        The configured AuditTrail instance
    """
    global _global_audit_trail
    _global_audit_trail = AuditTrail(
        persist_path=Path(persist_path) if persist_path else None,
        auto_persist=auto_persist,
    )
    return _global_audit_trail
