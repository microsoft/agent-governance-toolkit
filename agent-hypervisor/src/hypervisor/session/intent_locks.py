# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""
Resource Locks — stub implementation.

Public Preview: locks are not enforced. All acquire calls succeed.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum


class LockIntent(str, Enum):
    """Types of lock intent."""

    READ = "read"
    WRITE = "write"
    EXCLUSIVE = "exclusive"


@dataclass
class IntentLock:
    """A declared resource lock on a resource."""

    lock_id: str = field(default_factory=lambda: f"lock:{uuid.uuid4().hex[:8]}")
    agent_did: str = ""
    session_id: str = ""
    resource_path: str = ""
    intent: LockIntent = LockIntent.READ
    acquired_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    is_active: bool = True
    saga_step_id: str | None = None


class LockContentionError(Exception):
    """Raised when lock contention is detected."""


class DeadlockError(Exception):
    """Raised when a deadlock is detected."""


class IntentLockManager:
    """
    Resource lock stub (Public Preview: all locks succeed, no contention).
    """

    def __init__(self) -> None:
        self._locks: dict[str, IntentLock] = {}

    def acquire(
        self,
        agent_did: str,
        session_id: str,
        resource_path: str,
        intent: LockIntent,
        saga_step_id: str | None = None,
    ) -> IntentLock:
        """Acquire a lock (Public Preview: always succeeds)."""
        lock = IntentLock(
            agent_did=agent_did,
            session_id=session_id,
            resource_path=resource_path,
            intent=intent,
            saga_step_id=saga_step_id,
        )
        self._locks[lock.lock_id] = lock
        return lock

    def release(self, lock_id: str) -> None:
        """Release a lock."""
        lock = self._locks.get(lock_id)
        if lock:
            lock.is_active = False

    def release_agent_locks(self, agent_did: str, session_id: str) -> int:
        count = 0
        for lock in list(self._locks.values()):
            if lock.agent_did == agent_did and lock.session_id == session_id and lock.is_active:
                lock.is_active = False
                count += 1
        return count

    def release_session_locks(self, session_id: str) -> int:
        count = 0
        for lock in list(self._locks.values()):
            if lock.session_id == session_id and lock.is_active:
                lock.is_active = False
                count += 1
        return count

    def get_agent_locks(self, agent_did: str, session_id: str) -> list[IntentLock]:
        return [
            lock for lock in self._locks.values()
            if lock.agent_did == agent_did
            and lock.session_id == session_id
            and lock.is_active
        ]

    def get_resource_locks(self, resource_path: str) -> list[IntentLock]:
        return [
            lock for lock in self._locks.values()
            if lock.resource_path == resource_path
            and lock.is_active
        ]

    @property
    def active_lock_count(self) -> int:
        return sum(1 for lock in self._locks.values() if lock.is_active)

    @property
    def contention_points(self) -> list[str]:
        return []
