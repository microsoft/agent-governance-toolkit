# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for AgentMesh Registry service."""

import base64

import pytest
from fastapi.testclient import TestClient

from agentmesh.registry.app import RegistryServer
from agentmesh.registry.store import AgentRecord, InMemoryRegistryStore


@pytest.fixture
def client():
    server = RegistryServer()
    return TestClient(server.app)


@pytest.fixture
def store():
    return InMemoryRegistryStore()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


class TestRegistryStore:
    def test_put_and_get(self, store):
        record = AgentRecord(did="did:agentmesh:test1", public_key=b"\x01" * 32)
        store.put_agent(record)
        result = store.get_agent("did:agentmesh:test1")
        assert result is not None
        assert result.did == "did:agentmesh:test1"

    def test_get_missing(self, store):
        assert store.get_agent("did:agentmesh:missing") is None

    def test_delete(self, store):
        record = AgentRecord(did="did:agentmesh:test2", public_key=b"\x02" * 32)
        store.put_agent(record)
        assert store.delete_agent("did:agentmesh:test2") is True
        assert store.get_agent("did:agentmesh:test2") is None

    def test_delete_missing(self, store):
        assert store.delete_agent("did:agentmesh:missing") is False

    def test_search_by_capability(self, store):
        store.put_agent(AgentRecord(
            did="did:agentmesh:a1", public_key=b"\x01" * 32,
            capabilities=["data:read", "data:write"],
        ))
        store.put_agent(AgentRecord(
            did="did:agentmesh:a2", public_key=b"\x02" * 32,
            capabilities=["data:read"],
        ))
        store.put_agent(AgentRecord(
            did="did:agentmesh:a3", public_key=b"\x03" * 32,
            capabilities=["compute:run"],
        ))
        results = store.search_by_capability("data:read")
        assert len(results) == 2

    def test_consume_otk(self, store):
        record = AgentRecord(
            did="did:agentmesh:otk1", public_key=b"\x01" * 32,
            one_time_pre_keys=[
                {"key_id": 0, "public_key": _b64(b"\xaa" * 32)},
                {"key_id": 1, "public_key": _b64(b"\xbb" * 32)},
            ],
        )
        store.put_agent(record)

        otk1 = store.consume_one_time_key("did:agentmesh:otk1")
        assert otk1 is not None
        assert otk1["key_id"] == 0

        otk2 = store.consume_one_time_key("did:agentmesh:otk1")
        assert otk2 is not None
        assert otk2["key_id"] == 1

        otk3 = store.consume_one_time_key("did:agentmesh:otk1")
        assert otk3 is None

    def test_update_last_seen(self, store):
        record = AgentRecord(did="did:agentmesh:ls1", public_key=b"\x01" * 32)
        store.put_agent(record)
        old_ts = record.last_seen
        import time
        time.sleep(0.01)
        store.update_last_seen("did:agentmesh:ls1")
        updated = store.get_agent("did:agentmesh:ls1")
        assert updated.last_seen >= old_ts


class TestRegistryAPI:
    def test_health(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"

    def test_register_agent(self, client):
        resp = client.post("/v1/agents", json={
            "did": "did:agentmesh:api-test",
            "public_key": _b64(b"\x01" * 32),
            "capabilities": ["data:read"],
            "metadata": {"name": "test-agent"},
        })
        assert resp.status_code == 201
        assert resp.json()["did"] == "did:agentmesh:api-test"

    def test_register_duplicate(self, client):
        body = {
            "did": "did:agentmesh:dup",
            "public_key": _b64(b"\x01" * 32),
        }
        client.post("/v1/agents", json=body)
        resp = client.post("/v1/agents", json=body)
        assert resp.status_code == 409

    def test_get_agent(self, client):
        client.post("/v1/agents", json={
            "did": "did:agentmesh:get1",
            "public_key": _b64(b"\x01" * 32),
            "capabilities": ["search"],
        })
        resp = client.get("/v1/agents/did:agentmesh:get1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["did"] == "did:agentmesh:get1"
        assert "search" in data["capabilities"]

    def test_get_agent_not_found(self, client):
        resp = client.get("/v1/agents/did:agentmesh:missing")
        assert resp.status_code == 404

    def test_delete_agent(self, client):
        client.post("/v1/agents", json={
            "did": "did:agentmesh:del1",
            "public_key": _b64(b"\x01" * 32),
        })
        resp = client.delete("/v1/agents/did:agentmesh:del1")
        assert resp.status_code == 204

    def test_upload_and_fetch_prekeys(self, client):
        client.post("/v1/agents", json={
            "did": "did:agentmesh:pk1",
            "public_key": _b64(b"\x01" * 32),
        })
        client.put("/v1/agents/did:agentmesh:pk1/prekeys", json={
            "identity_key": _b64(b"\x11" * 32),
            "identity_key_ed": _b64(b"\x77" * 32),
            "signed_pre_key": {
                "key_id": 42,
                "public_key": _b64(b"\x22" * 32),
                "signature": _b64(b"\x33" * 64),
            },
            "one_time_pre_keys": [
                {"key_id": 100, "public_key": _b64(b"\x44" * 32)},
                {"key_id": 101, "public_key": _b64(b"\x55" * 32)},
            ],
        })

        resp = client.get("/v1/agents/did:agentmesh:pk1/prekeys")
        assert resp.status_code == 200
        data = resp.json()
        assert data["signed_pre_key"]["key_id"] == 42
        assert data["identity_key_ed"] == _b64(b"\x77" * 32)
        assert data["one_time_pre_key"] is not None
        assert data["one_time_pre_key"]["key_id"] == 100

        # Second fetch gets next OPK
        resp2 = client.get("/v1/agents/did:agentmesh:pk1/prekeys")
        assert resp2.json()["one_time_pre_key"]["key_id"] == 101

        # Third fetch — no OPKs left
        resp3 = client.get("/v1/agents/did:agentmesh:pk1/prekeys")
        assert resp3.json()["one_time_pre_key"] is None

    def test_presence(self, client):
        client.post("/v1/agents", json={
            "did": "did:agentmesh:pres1",
            "public_key": _b64(b"\x01" * 32),
        })
        resp = client.get("/v1/agents/did:agentmesh:pres1/presence")
        assert resp.status_code == 200
        assert resp.json()["online"] is True

    def test_reputation(self, client):
        client.post("/v1/agents", json={
            "did": "did:agentmesh:rep1",
            "public_key": _b64(b"\x01" * 32),
        })
        resp = client.post("/v1/agents/did:agentmesh:rep1/reputation", json={
            "score": 0.9,
            "reason": "reliable execution",
        })
        assert resp.status_code == 200
        assert resp.json()["reputation_score"] > 0.5

    def test_discover(self, client):
        for i in range(3):
            client.post("/v1/agents", json={
                "did": f"did:agentmesh:disc{i}",
                "public_key": _b64(bytes([i]) * 32),
                "capabilities": ["data:read"] if i < 2 else ["compute:run"],
            })
        resp = client.get("/v1/discover?capability=data:read")
        assert resp.status_code == 200
        assert resp.json()["total"] == 2

    def test_heartbeat_updates_last_seen(self, client):
        client.post("/v1/agents", json={
            "did": "did:agentmesh:hb1",
            "public_key": _b64(b"\x01" * 32),
        })
        resp = client.post("/v1/agents/did:agentmesh:hb1/heartbeat")
        assert resp.status_code == 200
        assert resp.json()["did"] == "did:agentmesh:hb1"
        assert resp.json()["last_seen"] is not None

    def test_heartbeat_not_found(self, client):
        resp = client.post("/v1/agents/did:agentmesh:missing/heartbeat")
        assert resp.status_code == 404

    def test_heartbeat_throttled(self, client):
        client.post("/v1/agents", json={
            "did": "did:agentmesh:hb2",
            "public_key": _b64(b"\x01" * 32),
        })
        # First heartbeat succeeds
        resp1 = client.post("/v1/agents/did:agentmesh:hb2/heartbeat")
        assert resp1.status_code == 200
        first_ts = resp1.json()["last_seen"]

        # Immediate second heartbeat is throttled
        resp2 = client.post("/v1/agents/did:agentmesh:hb2/heartbeat")
        assert resp2.status_code == 429

        # Verify last_seen was NOT updated on throttled request
        presence = client.get("/v1/agents/did:agentmesh:hb2/presence")
        assert presence.json()["last_seen"] == first_ts

    def test_identity_key_ed_validation_rejects_wrong_length(self, client):
        client.post("/v1/agents", json={
            "did": "did:agentmesh:edval",
            "public_key": _b64(b"\x01" * 32),
        })
        resp = client.put("/v1/agents/did:agentmesh:edval/prekeys", json={
            "identity_key": _b64(b"\x11" * 32),
            "identity_key_ed": _b64(b"\x77" * 16),  # Wrong: 16 bytes instead of 32
            "signed_pre_key": {
                "key_id": 1,
                "public_key": _b64(b"\x22" * 32),
                "signature": _b64(b"\x33" * 64),
            },
        })
        assert resp.status_code == 400
        assert "32 bytes" in resp.json()["detail"]

    def test_session_reputation_requires_participant(self, client):
        for did in ("did:agentmesh:sr-init", "did:agentmesh:sr-recv"):
            client.post("/v1/agents", json={
                "did": did, "public_key": _b64(b"\x01" * 32),
            })
        # Reporter is not a participant
        resp = client.post("/v1/registry/reputation/session", json={
            "session_id": "sess-1",
            "initiator_amid": "did:agentmesh:sr-init",
            "receiver_amid": "did:agentmesh:sr-recv",
            "outcome": "success",
            "reporter_amid": "did:agentmesh:outsider",
        })
        assert resp.status_code == 403


class TestRegistryStoreRateLimiting:
    def test_try_update_last_seen_first_call_succeeds(self, store):
        record = AgentRecord(did="did:agentmesh:rl1", public_key=b"\x01" * 32)
        store.put_agent(record)
        assert store.try_update_last_seen("did:agentmesh:rl1", min_interval_seconds=10.0) is True

    def test_try_update_last_seen_immediate_retry_throttled(self, store):
        record = AgentRecord(did="did:agentmesh:rl2", public_key=b"\x01" * 32)
        store.put_agent(record)
        assert store.try_update_last_seen("did:agentmesh:rl2") is True
        assert store.try_update_last_seen("did:agentmesh:rl2") is False

    def test_try_update_last_seen_missing_agent(self, store):
        assert store.try_update_last_seen("did:agentmesh:missing") is False
