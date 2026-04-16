# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""
Ephemeral Session Data Garbage Collection — stub implementation.

Public Preview: GC is a no-op. Data is retained in-memory for
session lifetime only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class GCResult:
    """Result of a garbage collection run."""

    session_id: str
    retained_deltas: int
    retained_hash: bool
    purged_vfs_files: int
    purged_caches: int
    storage_before_bytes: int
    storage_after_bytes: int
    gc_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def storage_saved_bytes(self) -> int:
        return self.storage_before_bytes - self.storage_after_bytes

    @property
    def savings_pct(self) -> float:
        if self.storage_before_bytes == 0:
            return 0.0
        return (self.storage_saved_bytes / self.storage_before_bytes) * 100


@dataclass
class RetentionPolicy:
    """Configuration for what to retain after GC."""

    delta_retention_days: int = 180
    hash_retention: str = "permanent"
    liability_snapshot: bool = True


class EphemeralGC:
    """
    GC stub (Public Preview: logs collection requests, no actual purge).
    """

    def __init__(self, policy: RetentionPolicy | None = None) -> None:
        self.policy = policy or RetentionPolicy()
        self._gc_history: list[GCResult] = []
        self._purged_sessions: set[str] = set()

    def collect(
        self,
        session_id: str,
        vfs: Any = None,
        delta_engine: Any = None,
        vfs_file_count: int = 0,
        cache_count: int = 0,
        delta_count: int = 0,
        estimated_vfs_bytes: int = 0,
        estimated_cache_bytes: int = 0,
        estimated_delta_bytes: int = 0,
    ) -> GCResult:
        """Log a GC request (Public Preview: no actual purge)."""
        result = GCResult(
            session_id=session_id,
            retained_deltas=delta_count,
            retained_hash=True,
            purged_vfs_files=0,
            purged_caches=0,
            storage_before_bytes=estimated_vfs_bytes + estimated_cache_bytes + estimated_delta_bytes,
            storage_after_bytes=estimated_vfs_bytes + estimated_cache_bytes + estimated_delta_bytes,
        )
        self._gc_history.append(result)
        self._purged_sessions.add(session_id)
        return result

    def is_purged(self, session_id: str) -> bool:
        return session_id in self._purged_sessions

    def should_expire_deltas(self, delta_timestamp: datetime) -> bool:
        return False

    @property
    def history(self) -> list[GCResult]:
        return list(self._gc_history)

    @property
    def purged_session_count(self) -> int:
        return len(self._purged_sessions)
