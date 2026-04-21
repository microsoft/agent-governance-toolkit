# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Registry storage protocols and in-memory defaults.

Spec: docs/specs/AGENTMESH-WIRE-1.0.md Section 11
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class AgentRecord:
    """A registered agent's metadata and pre-key bundle."""

    did: str
    public_key: bytes
    capabilities: list[str] = field(default_factory=list)
    metadata: dict[str, str] = field(default_factory=dict)
    registered_at: datetime = field(default_factory=_utcnow)
    last_seen: datetime = field(default_factory=_utcnow)

    # Pre-key bundle
    identity_key: bytes | None = None
    signed_pre_key: bytes | None = None
    signed_pre_key_signature: bytes | None = None
    signed_pre_key_id: int | None = None
    one_time_pre_keys: list[dict[str, Any]] = field(default_factory=list)

    # Reputation
    reputation_score: float = 0.5


class RegistryStore(Protocol):
    """Protocol for registry persistence backends."""

    def get_agent(self, did: str) -> AgentRecord | None: ...
    def put_agent(self, record: AgentRecord) -> None: ...
    def delete_agent(self, did: str) -> bool: ...
    def search_by_capability(self, capability: str, limit: int) -> list[AgentRecord]: ...
    def consume_one_time_key(self, did: str) -> dict[str, Any] | None: ...
    def update_last_seen(self, did: str) -> None: ...


class InMemoryRegistryStore:
    """Thread-safe in-memory registry store for development."""

    def __init__(self) -> None:
        self._agents: dict[str, AgentRecord] = {}
        self._lock = threading.Lock()

    def get_agent(self, did: str) -> AgentRecord | None:
        with self._lock:
            return self._agents.get(did)

    def put_agent(self, record: AgentRecord) -> None:
        with self._lock:
            self._agents[record.did] = record

    def delete_agent(self, did: str) -> bool:
        with self._lock:
            return self._agents.pop(did, None) is not None

    def search_by_capability(self, capability: str, limit: int = 50) -> list[AgentRecord]:
        with self._lock:
            results = []
            for agent in self._agents.values():
                if capability in agent.capabilities:
                    results.append(agent)
                    if len(results) >= limit:
                        break
            return results

    def consume_one_time_key(self, did: str) -> dict[str, Any] | None:
        with self._lock:
            agent = self._agents.get(did)
            if not agent or not agent.one_time_pre_keys:
                return None
            return agent.one_time_pre_keys.pop(0)

    def update_last_seen(self, did: str) -> None:
        with self._lock:
            agent = self._agents.get(did)
            if agent:
                agent.last_seen = _utcnow()
