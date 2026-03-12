# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Redis Trust Store Backend.

Provides a Redis-backed distributed trust store with pub/sub support
for real-time synchronization across mesh proxies.
"""

from __future__ import annotations

import json
import threading
from typing import Any, Callable

try:
    import redis

    _REDIS_AVAILABLE = True
except ImportError:
    _REDIS_AVAILABLE = False


def _require_redis() -> None:
    """Raise ImportError if redis package is not installed."""
    if not _REDIS_AVAILABLE:
        raise ImportError(
            "redis package is required for RedisTrustStore. "
            "Install with: pip install agentmesh-platform[storage] "
            "or pip install redis>=4.0"
        )


class RedisTrustStore:
    """
    Redis-backed distributed trust store.

    Stores agent trust scores and identity data in Redis with optional TTL
    and pub/sub for real-time updates across distributed mesh proxies.

    Args:
        redis_url: Redis connection URL.
        prefix: Key prefix for all stored data.
        ttl: Optional TTL in seconds for stored data.
    """

    TRUST_SCORE_SUFFIX = "trust"
    IDENTITY_SUFFIX = "identity"
    AGENTS_SET_KEY = "agents"
    PUBSUB_CHANNEL = "trust_updates"

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379",
        prefix: str = "agentmesh:",
        ttl: int | None = None,
    ) -> None:
        _require_redis()
        self._prefix = prefix
        self._ttl = ttl
        self._client: redis.Redis = redis.Redis.from_url(  # type: ignore[union-attr]
            redis_url, decode_responses=True
        )
        self._subscriber_thread: threading.Thread | None = None

    # -- Key helpers ----------------------------------------------------------

    def _key(self, agent_did: str, suffix: str) -> str:
        """Build a prefixed key for an agent."""
        return f"{self._prefix}{suffix}:{agent_did}"

    def _agents_key(self) -> str:
        """Key for the set tracking all known agent DIDs."""
        return f"{self._prefix}{self.AGENTS_SET_KEY}"

    def _channel(self) -> str:
        """Pub/sub channel name."""
        return f"{self._prefix}{self.PUBSUB_CHANNEL}"

    # -- Trust score operations -----------------------------------------------

    def store_trust_score(self, agent_did: str, score: dict[str, Any]) -> None:
        """Store trust score data for an agent.

        Args:
            agent_did: The agent's DID identifier.
            score: Trust score dictionary (e.g. competence, integrity, …).
        """
        key = self._key(agent_did, self.TRUST_SCORE_SUFFIX)
        self._client.set(key, json.dumps(score))
        if self._ttl is not None:
            self._client.expire(key, self._ttl)
        self._client.sadd(self._agents_key(), agent_did)

    def get_trust_score(self, agent_did: str) -> dict[str, Any] | None:
        """Retrieve trust score for an agent.

        Args:
            agent_did: The agent's DID identifier.

        Returns:
            Trust score dict or None if not found.
        """
        raw = self._client.get(self._key(agent_did, self.TRUST_SCORE_SUFFIX))
        if raw is None:
            return None
        return json.loads(raw)

    # -- Identity operations --------------------------------------------------

    def store_identity(self, agent_did: str, identity_data: dict[str, Any]) -> None:
        """Store agent identity data.

        Args:
            agent_did: The agent's DID identifier.
            identity_data: Identity information dict.
        """
        key = self._key(agent_did, self.IDENTITY_SUFFIX)
        self._client.set(key, json.dumps(identity_data))
        if self._ttl is not None:
            self._client.expire(key, self._ttl)
        self._client.sadd(self._agents_key(), agent_did)

    def get_identity(self, agent_did: str) -> dict[str, Any] | None:
        """Retrieve identity data for an agent.

        Args:
            agent_did: The agent's DID identifier.

        Returns:
            Identity dict or None if not found.
        """
        raw = self._client.get(self._key(agent_did, self.IDENTITY_SUFFIX))
        if raw is None:
            return None
        return json.loads(raw)

    # -- Management operations ------------------------------------------------

    def delete(self, agent_did: str) -> None:
        """Remove all data for an agent.

        Args:
            agent_did: The agent's DID identifier.
        """
        self._client.delete(
            self._key(agent_did, self.TRUST_SCORE_SUFFIX),
            self._key(agent_did, self.IDENTITY_SUFFIX),
        )
        self._client.srem(self._agents_key(), agent_did)

    def list_agents(self) -> list[str]:
        """List all known agent DIDs.

        Returns:
            Sorted list of agent DID strings.
        """
        members = self._client.smembers(self._agents_key())
        return sorted(members)

    # -- Pub/sub --------------------------------------------------------------

    def publish_update(
        self, agent_did: str, update_type: str, data: dict[str, Any]
    ) -> None:
        """Publish a trust update event.

        Args:
            agent_did: The agent's DID identifier.
            update_type: Type of update (e.g. ``"score_changed"``).
            data: Arbitrary event payload.
        """
        message = json.dumps(
            {"agent_did": agent_did, "update_type": update_type, "data": data}
        )
        self._client.publish(self._channel(), message)

    def subscribe_updates(self, callback: Callable[[dict[str, Any]], None]) -> None:
        """Subscribe to trust score updates via pub/sub.

        Starts a background thread that listens for messages on the trust
        updates channel and invokes *callback* for each received message.

        Args:
            callback: Function called with the parsed message dict.
        """
        pubsub = self._client.pubsub()
        pubsub.subscribe(self._channel())

        def _listener() -> None:
            for message in pubsub.listen():
                if message["type"] == "message":
                    parsed = json.loads(message["data"])
                    callback(parsed)

        self._subscriber_thread = threading.Thread(target=_listener, daemon=True)
        self._subscriber_thread.start()
