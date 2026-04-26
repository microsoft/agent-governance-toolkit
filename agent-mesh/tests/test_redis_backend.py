# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for RedisTrustStore.

Uses fakeredis for in-memory Redis emulation — no live Redis server required.
"""

import json
import time
import threading

import pytest

try:
    import fakeredis
except ImportError:
    pytest.skip("fakeredis not installed", allow_module_level=True)

from agentmesh.storage.redis_backend import RedisTrustStore, _REDIS_AVAILABLE


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_store(
    prefix: str = "agentmesh:", ttl: int | None = None
) -> RedisTrustStore:
    """Create a RedisTrustStore backed by fakeredis."""
    store = RedisTrustStore.__new__(RedisTrustStore)
    store._prefix = prefix
    store._ttl = ttl
    store._client = fakeredis.FakeRedis(decode_responses=True)
    store._subscriber_thread = None
    return store


SAMPLE_SCORE = {
    "competence": 0.9,
    "integrity": 0.85,
    "availability": 0.95,
    "predictability": 0.8,
    "transparency": 0.88,
}

SAMPLE_IDENTITY = {
    "did": "did:mesh:abc123",
    "public_key": "ed25519:deadbeef",
    "name": "TestAgent",
}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestStoreTrustScore:
    """Store and retrieve trust scores."""

    def test_store_and_get(self) -> None:
        store = _make_store()
        store.store_trust_score("did:mesh:abc123", SAMPLE_SCORE)
        result = store.get_trust_score("did:mesh:abc123")
        assert result == SAMPLE_SCORE

    def test_get_missing_returns_none(self) -> None:
        store = _make_store()
        assert store.get_trust_score("did:mesh:missing") is None


class TestStoreIdentity:
    """Store and retrieve identities."""

    def test_store_and_get(self) -> None:
        store = _make_store()
        store.store_identity("did:mesh:abc123", SAMPLE_IDENTITY)
        result = store.get_identity("did:mesh:abc123")
        assert result == SAMPLE_IDENTITY

    def test_get_missing_returns_none(self) -> None:
        store = _make_store()
        assert store.get_identity("did:mesh:missing") is None


class TestDelete:
    """Delete agent data."""

    def test_delete_removes_trust_and_identity(self) -> None:
        store = _make_store()
        store.store_trust_score("did:mesh:abc123", SAMPLE_SCORE)
        store.store_identity("did:mesh:abc123", SAMPLE_IDENTITY)

        store.delete("did:mesh:abc123")

        assert store.get_trust_score("did:mesh:abc123") is None
        assert store.get_identity("did:mesh:abc123") is None
        assert "did:mesh:abc123" not in store.list_agents()


class TestListAgents:
    """List known agents."""

    def test_list_agents(self) -> None:
        store = _make_store()
        store.store_trust_score("did:mesh:aaa", SAMPLE_SCORE)
        store.store_identity("did:mesh:bbb", SAMPLE_IDENTITY)
        agents = store.list_agents()
        assert agents == ["did:mesh:aaa", "did:mesh:bbb"]

    def test_list_empty(self) -> None:
        store = _make_store()
        assert store.list_agents() == []


class TestKeyPrefixing:
    """Key prefixing works correctly."""

    def test_custom_prefix(self) -> None:
        store = _make_store(prefix="custom:")
        store.store_trust_score("did:mesh:abc123", SAMPLE_SCORE)

        # Verify the key in Redis uses the custom prefix
        keys = store._client.keys("custom:*")
        assert any("custom:" in k for k in keys)
        assert not any(k.startswith("agentmesh:") for k in keys)

    def test_default_prefix(self) -> None:
        store = _make_store()
        store.store_trust_score("did:mesh:abc123", SAMPLE_SCORE)
        keys = store._client.keys("agentmesh:*")
        assert len(keys) >= 1


class TestTTL:
    """TTL is set when configured."""

    def test_ttl_applied(self) -> None:
        store = _make_store(ttl=300)
        store.store_trust_score("did:mesh:abc123", SAMPLE_SCORE)

        trust_key = store._key("did:mesh:abc123", store.TRUST_SCORE_SUFFIX)
        remaining = store._client.ttl(trust_key)
        assert 0 < remaining <= 300

    def test_ttl_on_identity(self) -> None:
        store = _make_store(ttl=600)
        store.store_identity("did:mesh:abc123", SAMPLE_IDENTITY)

        identity_key = store._key("did:mesh:abc123", store.IDENTITY_SUFFIX)
        remaining = store._client.ttl(identity_key)
        assert 0 < remaining <= 600

    def test_no_ttl_by_default(self) -> None:
        store = _make_store()
        store.store_trust_score("did:mesh:abc123", SAMPLE_SCORE)

        trust_key = store._key("did:mesh:abc123", store.TRUST_SCORE_SUFFIX)
        # -1 means no expiry in Redis
        assert store._client.ttl(trust_key) == -1


class TestPubSub:
    """Pub/sub publish and subscribe."""

    def test_publish_update(self) -> None:
        store = _make_store()
        # Use a separate fakeredis pubsub client to verify the message
        pubsub = store._client.pubsub()
        pubsub.subscribe(store._channel())
        # Consume the subscription confirmation message
        pubsub.get_message()

        store.publish_update("did:mesh:abc123", "score_changed", {"score": 0.95})

        msg = pubsub.get_message()
        assert msg is not None
        assert msg["type"] == "message"
        parsed = json.loads(msg["data"])
        assert parsed["agent_did"] == "did:mesh:abc123"
        assert parsed["update_type"] == "score_changed"
        assert parsed["data"] == {"score": 0.95}

    def test_subscribe_updates(self) -> None:
        """subscribe_updates receives published messages via callback."""
        # fakeredis requires shared server state for cross-client pubsub
        server = fakeredis.FakeServer()
        store = _make_store()
        store._client = fakeredis.FakeRedis(server=server, decode_responses=True)

        received: list[dict] = []
        event = threading.Event()

        def _cb(msg: dict) -> None:
            received.append(msg)
            event.set()

        store.subscribe_updates(_cb)

        # Publish from a second client sharing the same server
        pub_client = fakeredis.FakeRedis(server=server, decode_responses=True)
        payload = json.dumps(
            {
                "agent_did": "did:mesh:xyz",
                "update_type": "identity_updated",
                "data": {"name": "NewAgent"},
            }
        )
        pub_client.publish(store._channel(), payload)

        assert event.wait(timeout=5), "Callback was not invoked within timeout"
        assert len(received) == 1
        assert received[0]["agent_did"] == "did:mesh:xyz"


class TestMissingRedisPackage:
    """Handle missing redis package gracefully."""

    def test_import_error_when_redis_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import agentmesh.storage.redis_backend as mod

        monkeypatch.setattr(mod, "_REDIS_AVAILABLE", False)
        with pytest.raises(ImportError, match="redis package is required"):
            mod.RedisTrustStore()
