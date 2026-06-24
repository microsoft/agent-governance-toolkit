# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Ephemeral Session Data Garbage Collection.

At session teardown the GC purges sensitive ephemeral state (VFS file contents,
snapshots, caches) so it is not retained in memory, while preserving the
tamper-evident delta hash chain required for audit. Delta retention is governed
by :class:`RetentionPolicy`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
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
    Purges ephemeral session data while retaining the audit hash chain.
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
        """Purge the session's ephemeral data; retain the delta hash chain.

        When a ``vfs`` object is supplied its contents/snapshots/permissions are
        irreversibly cleared (see :meth:`SessionVFS.purge`) and the purged counts
        reflect what was actually dropped. The ``*_count``/``*_bytes`` arguments
        are storage-accounting estimates used only for reporting savings.
        """
        purged_files = vfs_file_count
        purged_caches = cache_count
        if vfs is not None and hasattr(vfs, "purge"):
            purged_files, purged_caches = vfs.purge()

        retained_delta_count = delta_count
        if delta_engine is not None and hasattr(delta_engine, "turn_count"):
            retained_delta_count = delta_engine.turn_count

        storage_before = estimated_vfs_bytes + estimated_cache_bytes + estimated_delta_bytes
        # Only the retained delta hash chain survives; VFS + caches are purged.
        storage_after = estimated_delta_bytes

        result = GCResult(
            session_id=session_id,
            retained_deltas=retained_delta_count,
            retained_hash=True,
            purged_vfs_files=purged_files,
            purged_caches=purged_caches,
            storage_before_bytes=storage_before,
            storage_after_bytes=storage_after,
        )
        self._gc_history.append(result)
        self._purged_sessions.add(session_id)
        return result

    def is_purged(self, session_id: str) -> bool:
        return session_id in self._purged_sessions

    def should_expire_deltas(self, delta_timestamp: datetime) -> bool:
        """True if a delta is older than the policy's delta retention window."""
        cutoff = datetime.now(UTC) - timedelta(days=self.policy.delta_retention_days)
        return delta_timestamp < cutoff

    @property
    def history(self) -> list[GCResult]:
        return list(self._gc_history)

    @property
    def purged_session_count(self) -> int:
        return len(self._purged_sessions)
