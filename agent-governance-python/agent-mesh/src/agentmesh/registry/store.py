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
    identity_key: bytes | None = None  # X25519 long-term key (32 bytes)
    identity_key_ed: bytes | None = None  # Ed25519 signing key (32 bytes) — required to verify signed_pre_key signature
    signed_pre_key: bytes | None = None
    signed_pre_key_signature: bytes | None = None
    signed_pre_key_id: int | None = None
    one_time_pre_keys: list[dict[str, Any]] = field(default_factory=list)

    # Reputation
    reputation_score: float = 0.5

    # Session counters (Phase 6.c follow-up). The EMA above is a
    # rolling average — operators also want to see how many sessions
    # contributed to it. Counters are bumped exclusively by
    # `submit_session_reputation` (POST /v1/registry/reputation/session).
    # Resetting requires `delete_agent` followed by re-registration —
    # this is intentional so a buggy peer can't roll back its own
    # history.
    total_sessions: int = 0
    successful_sessions: int = 0
    failed_sessions: int = 0
    timeout_sessions: int = 0
    # ISO-8601 timestamp of the most recent session that scored this
    # agent (initiator OR receiver). `None` until the first session.
    last_session_at: datetime | None = None

    # Entra Agent ID verification (Phase 6.c). Set by
    # `POST /v1/registry/verify` after the verifier confirms an Entra
    # JWT against tenant JWKS. `verified_app_id` is the Entra `appid`
    # claim from the verified token; `tier` is bumped to "verified"
    # so trust-scoring downstream can prefer cryptographically
    # identified peers over anonymous ones. Both stay `None` for
    # anonymous-tier agents and for clusters that haven't opted in.
    verified_app_id: str | None = None
    verified_tenant_id: str | None = None
    verified_at: datetime | None = None
    tier: str = "anonymous"


class RegistryStore(Protocol):
    """Protocol for registry persistence backends."""

    def get_agent(self, did: str) -> AgentRecord | None: ...
    def put_agent(self, record: AgentRecord) -> None: ...
    def delete_agent(self, did: str) -> bool: ...
    def search_by_capability(self, capability: str, limit: int) -> list[AgentRecord]: ...
    def consume_one_time_key(self, did: str) -> dict[str, Any] | None: ...
    def update_last_seen(self, did: str) -> None: ...
    def try_update_last_seen(self, did: str, min_interval_seconds: float = 10.0) -> bool:
        """Atomically update last_seen only if at least min_interval_seconds
        have elapsed since the last update. Returns True if updated, False
        if throttled. Implementations MUST be atomic."""
        ...


class InMemoryRegistryStore:
    """Thread-safe in-memory registry store for development."""

    def __init__(self) -> None:
        self._agents: dict[str, AgentRecord] = {}
        self._last_heartbeat: dict[str, datetime] = {}
        self._lock = threading.Lock()

    def get_agent(self, did: str) -> AgentRecord | None:
        with self._lock:
            return self._agents.get(did)

    def put_agent(self, record: AgentRecord) -> None:
        with self._lock:
            self._agents[record.did] = record

    def delete_agent(self, did: str) -> bool:
        with self._lock:
            self._last_heartbeat.pop(did, None)
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

    def try_update_last_seen(self, did: str, min_interval_seconds: float = 10.0) -> bool:
        """Atomically update last_seen only if enough time has elapsed
        since the last heartbeat call (not since last_seen, which is set
        at registration)."""
        with self._lock:
            agent = self._agents.get(did)
            if not agent:
                return False
            now = _utcnow()
            last_hb = self._last_heartbeat.get(did)
            if last_hb is not None:
                elapsed = (now - last_hb).total_seconds()
                if elapsed < min_interval_seconds:
                    return False
            agent.last_seen = now
            self._last_heartbeat[did] = now
            return True
