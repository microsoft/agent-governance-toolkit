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
        body, sk, did = _make_registration_body()
        client.post("/v1/agents", json=body)
        auth = _make_auth_header(sk, did)
        resp = client.delete(f"/v1/agents/{did}", headers={"Authorization": auth})
        assert resp.status_code == 204

    def test_delete_agent_requires_auth(self, client):
        """Deregistration must reject unauthenticated callers."""
        body, _sk, did = _make_registration_body()
        client.post("/v1/agents", json=body)
        # No Authorization header
        resp = client.delete(f"/v1/agents/{did}")
        assert resp.status_code == 422  # FastAPI: missing required header

    def test_delete_agent_rejects_other_did(self, client):
        """Auth header for one DID cannot be used to delete another."""
        # Register two agents
        body_a, sk_a, did_a = _make_registration_body()
        body_b, _sk_b, did_b = _make_registration_body()
        client.post("/v1/agents", json=body_a)
        client.post("/v1/agents", json=body_b)
        # Sign with A's key but try to delete B
        auth = _make_auth_header(sk_a, did_a)
        resp = client.delete(f"/v1/agents/{did_b}", headers={"Authorization": auth})
        assert resp.status_code == 403

    def test_delete_agent_rejects_forged_signature(self, client):
        body, _sk, did = _make_registration_body()
        client.post("/v1/agents", json=body)
        # Use a fresh (unregistered) key claiming to be the registered DID
        forged_sk = SigningKey.generate()
        ts = datetime.now(timezone.utc).isoformat()
        sig = forged_sk.sign(ts.encode()).signature
        auth = f"Ed25519-Timestamp {did} {ts} {_b64(sig)}"
        resp = client.delete(f"/v1/agents/{did}", headers={"Authorization": auth})
        assert resp.status_code == 401

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
        # Reporter (different agent) submits reputation on the target.
        target_body, _, target_did = _make_registration_body()
        client.post("/v1/agents", json=target_body)
        reporter_body, reporter_sk, reporter_did = _make_registration_body()
        client.post("/v1/agents", json=reporter_body)
        resp = client.post(
            f"/v1/agents/{target_did}/reputation",
            json={"score": 0.9, "reason": "reliable execution"},
            headers={"Authorization": _make_auth_header(reporter_sk, reporter_did)},
        )
        assert resp.status_code == 200
        assert resp.json()["reputation_score"] > 0.5

    def test_reputation_requires_auth(self, client):
        body, _, did = _make_registration_body()
        client.post("/v1/agents", json=body)
        resp = client.post(f"/v1/agents/{did}/reputation", json={"score": 0.9})
        assert resp.status_code == 401

    def test_reputation_rejects_self_reporting(self, client):
        body, sk, did = _make_registration_body()
        client.post("/v1/agents", json=body)
        resp = client.post(
            f"/v1/agents/{did}/reputation",
            json={"score": 1.0, "reason": "i am great"},
            headers={"Authorization": _make_auth_header(sk, did)},
        )
        assert resp.status_code == 403
        assert "themselves" in resp.json()["detail"].lower()

    def test_discover(self, client):
        for i in range(3):
            cap = ["data:read"] if i < 2 else ["compute:run"]
            body, _, _ = _make_registration_body(capabilities=cap)
            client.post("/v1/agents", json=body)
        resp = client.get("/v1/discover?capability=data:read")
        assert resp.status_code == 200
        assert resp.json()["total"] == 2

    def test_heartbeat_updates_last_seen(self, client):
        body, sk, did = _make_registration_body()
        client.post("/v1/agents", json=body)
        resp = client.post(
            f"/v1/agents/{did}/heartbeat",
            headers={"Authorization": _make_auth_header(sk, did)},
        )
        assert resp.status_code == 200
        assert resp.json()["did"] == did
        assert resp.json()["last_seen"] is not None

    def test_heartbeat_requires_auth(self, client):
        body, _, did = _make_registration_body()
        client.post("/v1/agents", json=body)
        resp = client.post(f"/v1/agents/{did}/heartbeat")
        assert resp.status_code == 401

    def test_heartbeat_rejects_other_did(self, client):
        body_a, _, did_a = _make_registration_body()
        body_b, sk_b, did_b = _make_registration_body()
        client.post("/v1/agents", json=body_a)
        client.post("/v1/agents", json=body_b)
        # B tries to heartbeat A.
        resp = client.post(
            f"/v1/agents/{did_a}/heartbeat",
            headers={"Authorization": _make_auth_header(sk_b, did_b)},
        )
        assert resp.status_code == 403

    def test_heartbeat_not_found(self, client):
        # An unregistered DID can never auth; the auth helper short-circuits
        # before the 404 path is even reachable.
        sk = SigningKey.generate()
        ghost_did = "did:mesh:" + "0" * 32
        ts = datetime.now(timezone.utc).isoformat()
        sig = sk.sign(ts.encode()).signature
        resp = client.post(
            f"/v1/agents/{ghost_did}/heartbeat",
            headers={
                "Authorization": f"Ed25519-Timestamp {ghost_did} {ts} {_b64(sig)}",
            },
        )
        assert resp.status_code == 401

    def test_heartbeat_throttled(self, client):
        body, sk, did = _make_registration_body()
        client.post("/v1/agents", json=body)
        auth = _make_auth_header(sk, did)
        resp1 = client.post(f"/v1/agents/{did}/heartbeat", headers={"Authorization": auth})
        assert resp1.status_code == 200
        first_ts = resp1.json()["last_seen"]

        # Immediate second heartbeat is throttled (use a fresh signed
        # timestamp so we know we hit the throttle, not the replay window).
        resp2 = client.post(
            f"/v1/agents/{did}/heartbeat",
            headers={"Authorization": _make_auth_header(sk, did)},
        )
        assert resp2.status_code == 429

        # Verify last_seen was NOT updated on throttled request
        presence = client.get(f"/v1/agents/{did}/presence")
        assert presence.json()["last_seen"] == first_ts

    # ── Session reputation auth ─────────────────────────────────

    def test_session_reputation_requires_auth(self, client):
        body_i, _, did_i = _make_registration_body()
        body_r, _, did_r = _make_registration_body()
        client.post("/v1/agents", json=body_i)
        client.post("/v1/agents", json=body_r)
        resp = client.post(
            "/v1/registry/reputation/session",
            json={
                "session_id": "s-1",
                "initiator_amid": did_i,
                "receiver_amid": did_r,
                "outcome": "success",
                "reporter_amid": did_i,
            },
        )
        assert resp.status_code == 401

    def test_session_reputation_rejects_spoofed_reporter(self, client):
        # Caller authenticates as did_i but claims did_r is the reporter.
        body_i, sk_i, did_i = _make_registration_body()
        body_r, _, did_r = _make_registration_body()
        client.post("/v1/agents", json=body_i)
        client.post("/v1/agents", json=body_r)
        resp = client.post(
            "/v1/registry/reputation/session",
            json={
                "session_id": "s-2",
                "initiator_amid": did_i,
                "receiver_amid": did_r,
                "outcome": "success",
                "reporter_amid": did_r,  # spoofed
            },
            headers={"Authorization": _make_auth_header(sk_i, did_i)},
        )
        assert resp.status_code == 403
        assert "reporter_amid" in resp.json()["detail"].lower()

    def test_session_reputation_succeeds_with_matching_reporter(self, client):
        body_i, sk_i, did_i = _make_registration_body()
        body_r, _, did_r = _make_registration_body()
        client.post("/v1/agents", json=body_i)
        client.post("/v1/agents", json=body_r)
        resp = client.post(
            "/v1/registry/reputation/session",
            json={
                "session_id": "s-3",
                "initiator_amid": did_i,
                "receiver_amid": did_r,
                "outcome": "success",
                "reporter_amid": did_i,
            },
            headers={"Authorization": _make_auth_header(sk_i, did_i)},
        )
        assert resp.status_code == 200
        assert resp.json()["outcome"] == "success"

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

    def test_session_reputation_requires_participant(self, client):
        body_i, sk_i, did_i = _make_registration_body()
        body_r, _, did_r = _make_registration_body()
        body_out, sk_out, did_out = _make_registration_body()
        for b in (body_i, body_r, body_out):
            client.post("/v1/agents", json=b)
        # Reporter is authenticated but not a session participant
        resp = client.post(
            "/v1/registry/reputation/session",
            json={
                "session_id": "sess-1",
                "initiator_amid": did_i,
                "receiver_amid": did_r,
                "outcome": "success",
                "reporter_amid": did_out,
            },
            headers={"Authorization": _make_auth_header(sk_out, did_out)},
        )
        assert resp.status_code == 403

    def test_session_counters_initialize_to_zero(self, client):
        """Freshly-registered agent must expose all counters at zero
        + completion_rate sentinel so consumers can distinguish
        'no history' from '0 of N succeeded'."""
        body, _, did = _make_registration_body()
        client.post("/v1/agents", json=body)
        result = client.get(f"/v1/agents/{did}").json()
        assert result["total_sessions"] == 0
        assert result["successful_sessions"] == 0
        assert result["failed_sessions"] == 0
        assert result["timeout_sessions"] == 0
        assert result["completion_rate"] == -1.0
        assert result["last_session_at"] is None

    def test_session_counters_bump_on_success(self, client):
        """Success increments BOTH endpoints' total + successful (the
        EMA already applies to both; counters mirror that exactly)."""
        body_i, sk_i, did_i = _make_registration_body()
        body_r, _, did_r = _make_registration_body()
        client.post("/v1/agents", json=body_i)
        client.post("/v1/agents", json=body_r)
        client.post(
            "/v1/registry/reputation/session",
            json={
                "session_id": "s1",
                "initiator_amid": did_i,
                "receiver_amid": did_r,
                "outcome": "success",
                "reporter_amid": did_i,
            },
            headers={"Authorization": _make_auth_header(sk_i, did_i)},
        )
        for did in (did_i, did_r):
            result = client.get(f"/v1/agents/{did}").json()
            assert result["total_sessions"] == 1
            assert result["successful_sessions"] == 1
            assert result["failed_sessions"] == 0
            assert result["timeout_sessions"] == 0
            assert result["completion_rate"] == 1.0
            assert result["last_session_at"] is not None

    def test_session_counters_bump_only_receiver_on_failure(self, client):
        """Failed outcome scores only the receiver (matches the EMA
        semantics) — and only the receiver's counters bump. The
        initiator stays untouched so a flaky receiver can't drag
        down its caller."""
        body_i, sk_i, did_i = _make_registration_body()
        body_r, _, did_r = _make_registration_body()
        client.post("/v1/agents", json=body_i)
        client.post("/v1/agents", json=body_r)
        client.post(
            "/v1/registry/reputation/session",
            json={
                "session_id": "s2",
                "initiator_amid": did_i,
                "receiver_amid": did_r,
                "outcome": "failed",
                "reporter_amid": did_i,
            },
            headers={"Authorization": _make_auth_header(sk_i, did_i)},
        )
        recv = client.get(f"/v1/agents/{did_r}").json()
        init = client.get(f"/v1/agents/{did_i}").json()
        assert recv["total_sessions"] == 1
        assert recv["failed_sessions"] == 1
        assert recv["successful_sessions"] == 0
        assert recv["completion_rate"] == 0.0
        # initiator counters MUST stay at zero — failure is the
        # receiver's fault, not the initiator's
        assert init["total_sessions"] == 0
        assert init["completion_rate"] == -1.0

    def test_session_counters_bump_only_receiver_on_timeout(self, client):
        """Timeout is partial blame on the receiver only."""
        body_i, _, did_i = _make_registration_body()
        body_r, sk_r, did_r = _make_registration_body()
        client.post("/v1/agents", json=body_i)
        client.post("/v1/agents", json=body_r)
        client.post(
            "/v1/registry/reputation/session",
            json={
                "session_id": "s3",
                "initiator_amid": did_i,
                "receiver_amid": did_r,
                "outcome": "timeout",
                "reporter_amid": did_r,
            },
            headers={"Authorization": _make_auth_header(sk_r, did_r)},
        )
        recv = client.get(f"/v1/agents/{did_r}").json()
        assert recv["total_sessions"] == 1
        assert recv["timeout_sessions"] == 1
        assert recv["successful_sessions"] == 0
        assert recv["failed_sessions"] == 0

    def test_session_counters_completion_rate_after_mixed_outcomes(self, client):
        """3 success + 1 failed → 0.75 completion."""
        body_i, sk_i, did_i = _make_registration_body()
        body_r, _, did_r = _make_registration_body()
        client.post("/v1/agents", json=body_i)
        client.post("/v1/agents", json=body_r)
        for i, outcome in enumerate(["success", "success", "success", "failed"]):
            client.post(
                "/v1/registry/reputation/session",
                json={
                    "session_id": f"mix-{i}",
                    "initiator_amid": did_i,
                    "receiver_amid": did_r,
                    "outcome": outcome,
                    "reporter_amid": did_i,
                },
                headers={"Authorization": _make_auth_header(sk_i, did_i)},
            )
        recv = client.get(f"/v1/agents/{did_r}").json()
        assert recv["total_sessions"] == 4
        assert recv["successful_sessions"] == 3
        assert recv["failed_sessions"] == 1
        assert recv["completion_rate"] == 0.75

    def test_simple_reputation_endpoint_bumps_counters(self, client):
        """POST /v1/agents/{did}/reputation is what AGT mesh peers
        actually use (the session endpoint is reserved for explicit
        initiator/receiver outcome reporting). Without bumping counters
        here, total_sessions would stay at 0 even after hundreds of
        peer-replies that successfully drift reputation_score.
        Pins score → bucket mapping: ≥0.7 success, <0.3 failed,
        else timeout.

        Upstream auth: the caller must authenticate as a DIFFERENT
        agent (no self-reporting), so we register two agents and have
        the second one rate the first."""
        body_tgt, _, did_tgt = _make_registration_body()
        body_rep, sk_rep, did_rep = _make_registration_body()
        client.post("/v1/agents", json=body_tgt)
        client.post("/v1/agents", json=body_rep)
        auth = {"Authorization": _make_auth_header(sk_rep, did_rep)}
        # 0.9 → success
        client.post(f"/v1/agents/{did_tgt}/reputation",
                    json={"score": 0.9, "reason": "fast"}, headers=auth)
        result = client.get(f"/v1/agents/{did_tgt}").json()
        assert result["total_sessions"] == 1
        assert result["successful_sessions"] == 1
        # 0.1 → failed
        client.post(f"/v1/agents/{did_tgt}/reputation",
                    json={"score": 0.1, "reason": "broken"}, headers=auth)
        result = client.get(f"/v1/agents/{did_tgt}").json()
        assert result["total_sessions"] == 2
        assert result["failed_sessions"] == 1
        # 0.5 → timeout (mid-band)
        client.post(f"/v1/agents/{did_tgt}/reputation",
                    json={"score": 0.5, "reason": "slow"}, headers=auth)
        result = client.get(f"/v1/agents/{did_tgt}").json()
        assert result["total_sessions"] == 3
        assert result["timeout_sessions"] == 1
        # Buckets must sum to total
        assert (result["successful_sessions"] + result["failed_sessions"] +
                result["timeout_sessions"]) == result["total_sessions"]
        assert result["last_session_at"] is not None


class TestIdentityVerify:
    """Phase 6.c — POST /v1/registry/verify upgrades anonymous → verified.

    Tests use a stub PyJWKClient and explicit env so we don't need a
    live Entra tenant. The real verifier is exercised via the
    test_entra_verifier.py suite.
    """

    @pytest.fixture(autouse=True)
    def _reset_verifier(self, monkeypatch):
        # Stub the verifier so the test client can call verify()
        # without needing real JWKS / real tokens. The contract we
        # care about for the *route* is the agent-record stamping
        # behavior — that the route does the right thing when given
        # a valid claims dict. The verifier itself is tested
        # elsewhere.
        from agentmesh.identity import entra_verifier
        entra_verifier.reset_verifier_for_tests()
        monkeypatch.setenv("AGENTMESH_ENTRA_AUDIENCE", "api://test-mesh")
        monkeypatch.setenv("AGENTMESH_ENTRA_TENANT_ID",
                           "11111111-2222-3333-4444-555555555555")
        yield
        entra_verifier.reset_verifier_for_tests()

    def _stub_verifier(self, monkeypatch, *, raises=None, claims=None):
        """Install a stub verifier that either raises EntraTokenError
        or returns the supplied claims dict."""
        from agentmesh.identity import entra_verifier

        class _StubVerifier:
            async def verify(self, _token):
                if raises is not None:
                    raise raises
                return claims or {}
        async def _get():
            return _StubVerifier()
        monkeypatch.setattr(entra_verifier, "get_verifier", _get)

    def test_verify_unregistered_agent_returns_404(self, client, monkeypatch):
        self._stub_verifier(monkeypatch, claims={
            "appid": "00000000-1111-2222-3333-444444444444",
            "tid": "11111111-2222-3333-4444-555555555555",
        })
        resp = client.post("/v1/registry/verify", json={
            "amid": "did:mesh:" + "00" * 16,
            "verification_token": "stub-token",
        })
        assert resp.status_code == 404

    def test_verify_disabled_returns_503(self, client, monkeypatch):
        # Simulate operator NOT opting in by making get_verifier return None
        from agentmesh.identity import entra_verifier
        async def _none():
            return None
        monkeypatch.setattr(entra_verifier, "get_verifier", _none)
        body, _, did = _make_registration_body()
        client.post("/v1/agents", json=body)
        resp = client.post("/v1/registry/verify", json={
            "amid": did,
            "verification_token": "anything",
        })
        assert resp.status_code == 503
        assert "not configured" in resp.json()["detail"].lower()

    def test_verify_rejects_bad_token(self, client, monkeypatch):
        from agentmesh.identity.entra_verifier import EntraTokenError
        self._stub_verifier(monkeypatch, raises=EntraTokenError("wrong tenant"))
        body, _, did = _make_registration_body()
        client.post("/v1/agents", json=body)
        resp = client.post("/v1/registry/verify", json={
            "amid": did,
            "verification_token": "junk",
        })
        assert resp.status_code == 401
        # Agent tier must stay anonymous on failure (no stamping)
        result = client.get(f"/v1/agents/{did}").json()
        assert result["tier"] == "anonymous"
        assert result["verified_app_id"] is None

    def test_verify_rejects_token_missing_appid(self, client, monkeypatch):
        """A verified token without appid/azp must NOT promote to
        verified — we need the principal claim to stamp the record."""
        self._stub_verifier(monkeypatch, claims={
            "tid": "11111111-2222-3333-4444-555555555555",
            # no appid, no azp
        })
        body, _, did = _make_registration_body()
        client.post("/v1/agents", json=body)
        resp = client.post("/v1/registry/verify", json={
            "amid": did,
            "verification_token": "missing-claim",
        })
        assert resp.status_code == 401
        assert "appid" in resp.json()["detail"].lower()

    def test_verify_success_stamps_record(self, client, monkeypatch):
        self._stub_verifier(monkeypatch, claims={
            "appid": "abcdef01-2345-6789-abcd-ef0123456789",
            "tid": "11111111-2222-3333-4444-555555555555",
        })
        body, _, did = _make_registration_body()
        client.post("/v1/agents", json=body)
        resp = client.post("/v1/registry/verify", json={
            "amid": did,
            "verification_token": "good",
        })
        assert resp.status_code == 200
        out = resp.json()
        assert out["tier"] == "verified"
        assert out["verified_app_id"] == "abcdef01-2345-6789-abcd-ef0123456789"
        # GET /v1/agents/{did} reflects the verified fields
        result = client.get(f"/v1/agents/{did}").json()
        assert result["tier"] == "verified"
        assert result["verified_app_id"] == "abcdef01-2345-6789-abcd-ef0123456789"
        assert result["verified_tenant_id"] == "11111111-2222-3333-4444-555555555555"
        assert result["verified_at"] is not None

    def test_verify_falls_back_to_azp_when_appid_missing(self, client, monkeypatch):
        """v2.0 Entra tokens use `azp` instead of `appid` — the route
        must accept either."""
        self._stub_verifier(monkeypatch, claims={
            "azp": "00000000-1111-2222-3333-444444444444",
            "tid": "11111111-2222-3333-4444-555555555555",
        })
        body, _, did = _make_registration_body()
        client.post("/v1/agents", json=body)
        resp = client.post("/v1/registry/verify", json={
            "amid": did,
            "verification_token": "v2-token",
        })
        assert resp.status_code == 200
        assert resp.json()["verified_app_id"] == "00000000-1111-2222-3333-444444444444"


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
