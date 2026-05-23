# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for AgentMesh Registry service."""

import base64
import hashlib
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from nacl.signing import SigningKey

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


def _make_registration_body(capabilities=None, metadata=None):
    """Generate a valid registration request with proof-of-possession.

    Returns (body_dict, signing_key, derived_did).
    """
    sk = SigningKey.generate()
    pub = sk.verify_key.encode()
    pub_b64 = _b64(pub)
    ts = datetime.now(timezone.utc).isoformat()
    message = pub_b64.encode() + ts.encode()
    sig = sk.sign(message).signature
    proof_b64 = _b64(sig)

    key_hash = hashlib.sha256(pub).hexdigest()[:32]
    did = f"did:mesh:{key_hash}"

    body = {
        "public_key": pub_b64,
        "proof": proof_b64,
        "proof_timestamp": ts,
    }
    if capabilities:
        body["capabilities"] = capabilities
    if metadata:
        body["metadata"] = metadata
    return body, sk, did


def _make_auth_header(sk: SigningKey, did: str) -> str:
    """Create Ed25519-Timestamp auth header for prekey upload."""
    ts = datetime.now(timezone.utc).isoformat()
    sig = sk.sign(ts.encode()).signature
    return f"Ed25519-Timestamp {did} {ts} {_b64(sig)}"


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
        dids = {r.did for r in results}
        assert "did:agentmesh:a1" in dids
        assert "did:agentmesh:a2" in dids


class TestRegistryAPI:
    def test_health(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"

    def test_register_agent(self, client):
        body, _, did = _make_registration_body(
            capabilities=["data:read"],
            metadata={"name": "test-agent"},
        )
        resp = client.post("/v1/agents", json=body)
        assert resp.status_code == 201
        assert resp.json()["did"] == did

    def test_register_duplicate(self, client):
        body, _, _ = _make_registration_body()
        client.post("/v1/agents", json=body)
        resp = client.post("/v1/agents", json=body)
        assert resp.status_code == 409

    def test_register_rejects_bad_proof(self, client):
        body, _, _ = _make_registration_body()
        body["proof"] = _b64(b"\x00" * 64)  # invalid signature
        resp = client.post("/v1/agents", json=body)
        assert resp.status_code == 401

    def test_register_rejects_missing_proof(self, client):
        sk = SigningKey.generate()
        pub = sk.verify_key.encode()
        body = {"public_key": _b64(pub)}
        resp = client.post("/v1/agents", json=body)
        assert resp.status_code == 422  # missing required fields

    def test_get_agent(self, client):
        body, _, did = _make_registration_body(capabilities=["search"])
        client.post("/v1/agents", json=body)
        resp = client.get(f"/v1/agents/{did}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["did"] == did
        assert "search" in data["capabilities"]

    def test_get_agent_not_found(self, client):
        resp = client.get("/v1/agents/did:mesh:missing")
        assert resp.status_code == 404

    def test_delete_agent(self, client):
        body, _, did = _make_registration_body()
        client.post("/v1/agents", json=body)
        resp = client.delete(f"/v1/agents/{did}")
        assert resp.status_code == 204

    def test_upload_and_fetch_prekeys(self, client):
        body, sk, did = _make_registration_body()
        client.post("/v1/agents", json=body)
        auth = _make_auth_header(sk, did)
        resp = client.put(
            f"/v1/agents/{did}/prekeys",
            json={
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
            },
            headers={"Authorization": auth},
        )
        assert resp.status_code == 200

        resp = client.get(f"/v1/agents/{did}/prekeys")
        assert resp.status_code == 200
        data = resp.json()
        assert data["signed_pre_key"]["key_id"] == 42
        assert data["identity_key_ed"] == _b64(b"\x77" * 32)
        assert data["one_time_pre_key"] is not None
        assert data["one_time_pre_key"]["key_id"] == 100

        # Second fetch gets next OPK
        resp2 = client.get(f"/v1/agents/{did}/prekeys")
        assert resp2.json()["one_time_pre_key"]["key_id"] == 101

        # Third fetch - no OPKs left
        resp3 = client.get(f"/v1/agents/{did}/prekeys")
        assert resp3.json()["one_time_pre_key"] is None

    def test_prekey_upload_requires_auth(self, client):
        body, _, did = _make_registration_body()
        client.post("/v1/agents", json=body)
        resp = client.put(
            f"/v1/agents/{did}/prekeys",
            json={
                "identity_key": _b64(b"\x11" * 32),
                "signed_pre_key": {
                    "key_id": 1,
                    "public_key": _b64(b"\x22" * 32),
                    "signature": _b64(b"\x33" * 64),
                },
            },
        )
        assert resp.status_code == 422  # missing auth header

    def test_presence(self, client):
        body, _, did = _make_registration_body()
        client.post("/v1/agents", json=body)
        resp = client.get(f"/v1/agents/{did}/presence")
        assert resp.status_code == 200
        assert resp.json()["online"] is True

    def test_reputation(self, client):
        body, _, did = _make_registration_body()
        client.post("/v1/agents", json=body)
        resp = client.post(f"/v1/agents/{did}/reputation", json={
            "score": 0.9,
            "reason": "reliable execution",
        })
        assert resp.status_code == 200
        assert resp.json()["reputation_score"] > 0.5

    def test_discover(self, client):
        for i in range(3):
            cap = ["data:read"] if i < 2 else ["compute:run"]
            body, _, _ = _make_registration_body(capabilities=cap)
            client.post("/v1/agents", json=body)
        resp = client.get("/v1/discover?capability=data:read")
        assert resp.status_code == 200
        assert resp.json()["total"] == 2

    def test_heartbeat_updates_last_seen(self, client):
        body, _, did = _make_registration_body()
        client.post("/v1/agents", json=body)
        resp = client.post(f"/v1/agents/{did}/heartbeat")
        assert resp.status_code == 200
        assert resp.json()["did"] == did
        assert resp.json()["last_seen"] is not None

    def test_heartbeat_not_found(self, client):
        resp = client.post("/v1/agents/did:mesh:missing/heartbeat")
        assert resp.status_code == 404

    def test_heartbeat_throttled(self, client):
        body, _, did = _make_registration_body()
        client.post("/v1/agents", json=body)
        resp1 = client.post(f"/v1/agents/{did}/heartbeat")
        assert resp1.status_code == 200
        first_ts = resp1.json()["last_seen"]

        # Immediate second heartbeat is throttled
        resp2 = client.post(f"/v1/agents/{did}/heartbeat")
        assert resp2.status_code == 429

        # Verify last_seen was NOT updated on throttled request
        presence = client.get(f"/v1/agents/{did}/presence")
        assert presence.json()["last_seen"] == first_ts

    def test_identity_key_ed_validation_rejects_wrong_length(self, client):
        body, sk, did = _make_registration_body()
        client.post("/v1/agents", json=body)
        auth = _make_auth_header(sk, did)
        resp = client.put(
            f"/v1/agents/{did}/prekeys",
            json={
                "identity_key": _b64(b"\x11" * 32),
                "identity_key_ed": _b64(b"\x77" * 16),  # Wrong: 16 bytes instead of 32
                "signed_pre_key": {
                    "key_id": 1,
                    "public_key": _b64(b"\x22" * 32),
                    "signature": _b64(b"\x33" * 64),
                },
            },
            headers={"Authorization": auth},
        )
        assert resp.status_code == 400
        assert "32 bytes" in resp.json()["detail"]
