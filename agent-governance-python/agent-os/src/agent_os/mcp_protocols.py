# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Persistence protocols and in-memory defaults for MCP governance components."""

from __future__ import annotations

import threading
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Callable, Protocol


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class MCPSessionStore(Protocol):
    """Persistence contract for authenticated MCP sessions."""

    def get(self, session_id: str) -> Any | None:
        """Return the stored session for *session_id*, if present."""

    def set(self, session: Any) -> None:
        """Persist *session* keyed by its session identifier."""

    def delete(self, session_id: str) -> bool:
        """Delete *session_id* and return ``True`` when it existed."""


class MCPNonceStore(Protocol):
    """Persistence contract for replay-protection nonces."""

    def has(self, nonce: str) -> bool:
        """Return ``True`` when *nonce* is still tracked."""

    def add(self, nonce: str, expires_at: datetime) -> None:
        """Track *nonce* until *expires_at*."""

    def cleanup(self) -> int:
        """Remove expired entries and return the number removed."""


class MCPRateLimitStore(Protocol):
    """Persistence contract for per-agent rate-limit buckets."""

    def get_bucket(self, agent_id: str) -> Any | None:
        """Return the bucket state stored for *agent_id*, if present."""

    def set_bucket(self, agent_id: str, bucket: Any) -> None:
        """Persist *bucket* for *agent_id*."""


class MCPAuditSink(Protocol):
    """Persistence contract for structured audit records."""

    def record(self, entry: dict[str, Any]) -> None:
        """Persist a structured audit *entry*."""


class InMemorySessionStore:
    """Thread-safe in-memory session storage."""

    def __init__(self) -> None:
        self._sessions: dict[str, Any] = {}
        self._lock = threading.Lock()

    def get(self, session_id: str) -> Any | None:
        with self._lock:
            return self._sessions.get(session_id)

    def set(self, session: Any) -> None:
        session_id = getattr(session, "token", None)
        if not isinstance(session_id, str) or not session_id:
            raise ValueError("session must provide a non-empty string token")
        with self._lock:
            self._sessions[session_id] = session

    def delete(self, session_id: str) -> bool:
        with self._lock:
            return self._sessions.pop(session_id, None) is not None


class InMemoryNonceStore:
    """Thread-safe in-memory nonce storage with TTL cleanup and eviction."""

    def __init__(
        self,
        *,
        clock: Callable[[], datetime] = _utcnow,
        max_entries: int = 10_000,
    ) -> None:
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        self._clock = clock
        self._max_entries = max_entries
        self._nonces: OrderedDict[str, datetime] = OrderedDict()
        self._lock = threading.Lock()

    def has(self, nonce: str) -> bool:
        with self._lock:
            expires_at = self._nonces.get(nonce)
            if expires_at is None:
                return False
            if expires_at <= self._clock():
                self._nonces.pop(nonce, None)
                return False
            self._nonces.move_to_end(nonce)
            return True

    def add(self, nonce: str, expires_at: datetime) -> None:
        with self._lock:
            self._nonces[nonce] = expires_at
            self._nonces.move_to_end(nonce)
            while len(self._nonces) > self._max_entries:
                self._nonces.popitem(last=False)

    def cleanup(self) -> int:
        removed = 0
        now = self._clock()
        with self._lock:
            expired = [nonce for nonce, expires_at in self._nonces.items() if expires_at <= now]
            for nonce in expired:
                self._nonces.pop(nonce, None)
            removed = len(expired)
        return removed

    def count(self) -> int:
        with self._lock:
            return len(self._nonces)


class InMemoryRateLimitStore:
    """Thread-safe in-memory rate-limit bucket storage."""

    def __init__(self) -> None:
        self._buckets: dict[str, Any] = {}
        self._lock = threading.Lock()

    def get_bucket(self, agent_id: str) -> Any | None:
        with self._lock:
            return self._buckets.get(agent_id)

    def set_bucket(self, agent_id: str, bucket: Any) -> None:
        with self._lock:
            self._buckets[agent_id] = bucket


class InMemoryAuditSink:
    """Thread-safe in-memory audit sink for structured records."""

    def __init__(self) -> None:
        self._entries: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def record(self, entry: dict[str, Any]) -> None:
        with self._lock:
            self._entries.append(dict(entry))

    def entries(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(entry) for entry in self._entries]
