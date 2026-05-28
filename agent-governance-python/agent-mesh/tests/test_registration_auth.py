"""Negative auth tests for registration endpoints.

Every endpoint that accepts a public key MUST reject requests without
valid proof-of-possession. These tests serve as a regression gate:
if someone adds a new registration endpoint and forgets auth, these
fail and CI blocks the merge.
"""
import base64

import pytest

from nacl.signing import SigningKey


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


# ── Registry /v1/agents ──────────────────────────────────────────────


class TestRegistryRejectsUnauthenticated:
    """POST /v1/agents must reject registration without valid proof."""

    @pytest.fixture(autouse=True)
    def setup(self):
        from agentmesh.registry.app import RegistryServer
        from fastapi.testclient import TestClient

        server = RegistryServer()
        self.client = TestClient(server.app)

    def test_rejects_no_proof_fields(self):
        sk = SigningKey.generate()
        pub = sk.verify_key.encode()
        resp = self.client.post("/v1/agents", json={
            "public_key": _b64(pub),
        })
        assert resp.status_code == 422, "Must reject when proof fields are missing"

    def test_rejects_wrong_signature(self):
        sk = SigningKey.generate()
        wrong_sk = SigningKey.generate()
        pub = sk.verify_key.encode()
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).isoformat()
        message = _b64(pub).encode() + ts.encode()
        bad_sig = wrong_sk.sign(message).signature
        resp = self.client.post("/v1/agents", json={
            "public_key": _b64(pub),
            "proof": _b64(bad_sig),
            "proof_timestamp": ts,
        })
        assert resp.status_code == 401, "Must reject proof signed by wrong key"

    def test_rejects_expired_proof(self):
        sk = SigningKey.generate()
        pub = sk.verify_key.encode()
        pub_b64 = _b64(pub)
        from datetime import datetime, timezone, timedelta
        old_ts = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        message = pub_b64.encode() + old_ts.encode()
        sig = sk.sign(message).signature
        resp = self.client.post("/v1/agents", json={
            "public_key": pub_b64,
            "proof": _b64(sig),
            "proof_timestamp": old_ts,
        })
        assert resp.status_code == 401, "Must reject expired proof timestamp"

    def test_rejects_client_supplied_did(self):
        """Clients cannot choose their own DID; it must be server-derived."""
        sk = SigningKey.generate()
        pub = sk.verify_key.encode()
        pub_b64 = _b64(pub)
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).isoformat()
        message = pub_b64.encode() + ts.encode()
        sig = sk.sign(message).signature
        resp = self.client.post("/v1/agents", json={
            "did": "did:mesh:attacker-chosen-did",
            "public_key": pub_b64,
            "proof": _b64(sig),
            "proof_timestamp": ts,
        })
        if resp.status_code == 201:
            data = resp.json()
            assert data["did"] != "did:mesh:attacker-chosen-did", \
                "Server must derive DID from key hash, not accept client-supplied DID"


# ── Trust Engine /api/v1/agents/register ─────────────────────────────


class TestTrustEngineRejectsUnauthenticated:
    """POST /api/v1/agents/register must reject registration without proof."""

    @pytest.fixture(autouse=True)
    def setup(self):
        from agentmesh.server.trust_engine import app, registry, _pending_challenges
        from fastapi.testclient import TestClient

        _pending_challenges.clear()
        registry._identities.clear()
        registry._by_sponsor.clear()
        self.client = TestClient(app)

    def test_rejects_no_proof_fields(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = Ed25519PrivateKey.generate()
        pub_b64 = base64.b64encode(key.public_key().public_bytes_raw()).decode()
        resp = self.client.post("/api/v1/agents/register", json={
            "name": "test-agent",
            "public_key": pub_b64,
            "sponsor_email": "test@example.com",
        })
        assert resp.status_code == 422, "Must reject when proof fields are missing"

    def test_rejects_wrong_signature(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = Ed25519PrivateKey.generate()
        wrong_key = Ed25519PrivateKey.generate()
        pub_b64 = base64.b64encode(key.public_key().public_bytes_raw()).decode()
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).isoformat()
        message = pub_b64.encode() + ts.encode()
        bad_sig = wrong_key.sign(message)
        resp = self.client.post("/api/v1/agents/register", json={
            "name": "test-agent",
            "public_key": pub_b64,
            "proof": base64.b64encode(bad_sig).decode(),
            "proof_timestamp": ts,
            "sponsor_email": "test@example.com",
        })
        assert resp.status_code == 401, "Must reject proof signed by wrong key"

    def test_rejects_name_squatting(self):
        """DID must be derived from key hash, not from the name field."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = Ed25519PrivateKey.generate()
        pub_b64 = base64.b64encode(key.public_key().public_bytes_raw()).decode()
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).isoformat()
        message = pub_b64.encode() + ts.encode()
        sig = key.sign(message)
        resp = self.client.post("/api/v1/agents/register", json={
            "name": "microsoft-payments",
            "public_key": pub_b64,
            "proof": base64.b64encode(sig).decode(),
            "proof_timestamp": ts,
            "sponsor_email": "attacker@example.com",
        })
        if resp.status_code == 200:
            import hashlib
            expected_hash = hashlib.sha256(key.public_key().public_bytes_raw()).hexdigest()[:32]
            data = resp.json()
            assert expected_hash in data["agent_did"], \
                "DID must be derived from public key hash, not from name"


# ── Prekey Upload Auth ───────────────────────────────────────────────


class TestPrekeyUploadRejectsUnauthenticated:
    """PUT /v1/agents/{did}/prekeys must reject unauthenticated uploads."""

    @pytest.fixture(autouse=True)
    def setup(self):
        from agentmesh.registry.app import RegistryServer
        from fastapi.testclient import TestClient

        server = RegistryServer()
        self.client = TestClient(server.app)

    def _register_agent(self):
        from datetime import datetime, timezone
        sk = SigningKey.generate()
        pub = sk.verify_key.encode()
        pub_b64 = _b64(pub)
        ts = datetime.now(timezone.utc).isoformat()
        message = pub_b64.encode() + ts.encode()
        sig = sk.sign(message).signature
        resp = self.client.post("/v1/agents", json={
            "public_key": pub_b64,
            "proof": _b64(sig),
            "proof_timestamp": ts,
        })
        assert resp.status_code == 201
        did = resp.json()["did"]
        return sk, did

    def test_rejects_no_auth_header(self):
        _, did = self._register_agent()
        resp = self.client.put(f"/v1/agents/{did}/prekeys", json={
            "identity_key": _b64(b"\x11" * 32),
            "signed_pre_key": {
                "key_id": 1,
                "public_key": _b64(b"\x22" * 32),
                "signature": _b64(b"\x33" * 64),
            },
        })
        assert resp.status_code == 422, "Must reject prekey upload without auth header"

    def test_rejects_wrong_key_auth(self):
        sk, did = self._register_agent()
        wrong_sk = SigningKey.generate()
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).isoformat()
        sig = wrong_sk.sign(ts.encode()).signature
        auth = f"Ed25519-Timestamp {did} {ts} {_b64(sig)}"
        resp = self.client.put(
            f"/v1/agents/{did}/prekeys",
            json={
                "identity_key": _b64(b"\x11" * 32),
                "signed_pre_key": {
                    "key_id": 1,
                    "public_key": _b64(b"\x22" * 32),
                    "signature": _b64(b"\x33" * 64),
                },
            },
            headers={"Authorization": auth},
        )
        assert resp.status_code == 401, "Must reject prekey upload with wrong key"


# ── Capability Grant Auth (security regression) ──────────────────────


class TestCapabilityGrantRejectsUnauthenticated:
    """POST /api/v1/capabilities/grant must require Ed25519-Timestamp
    auth tying the grantor to the caller, AND the grantor must already
    hold the capability being delegated."""

    @pytest.fixture(autouse=True)
    def setup(self):
        from agentmesh.server.trust_engine import (
            app, registry, capability_registry, _pending_challenges,
        )
        from fastapi.testclient import TestClient
        _pending_challenges.clear()
        registry._identities.clear()
        registry._by_sponsor.clear()
        capability_registry._scopes.clear()
        capability_registry._grants_by_grantor.clear()
        self.client = TestClient(app)
        self.registry = registry
        self.capability_registry = capability_registry

    def _register(self, name: str = "alice"):
        """Register an agent through the public API; returns (sk, did)."""
        from datetime import datetime, timezone
        import hashlib
        sk = SigningKey.generate()
        pub = sk.verify_key.encode()
        pub_b64 = base64.b64encode(pub).decode()
        ts = datetime.now(timezone.utc).isoformat()
        message = pub_b64.encode() + ts.encode()
        sig = sk.sign(message).signature
        resp = self.client.post("/api/v1/agents/register", json={
            "name": name,
            "public_key": pub_b64,
            "proof": base64.b64encode(sig).decode(),
            "proof_timestamp": ts,
            "sponsor_email": f"{name}@test.example.com",
        })
        assert resp.status_code == 200
        did = f"did:mesh:{hashlib.sha256(pub).hexdigest()[:32]}"
        assert resp.json()["agent_did"] == did
        return sk, did

    def _auth(self, sk: SigningKey, did: str) -> dict:
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).isoformat()
        sig = sk.sign(ts.encode()).signature
        token = f"Ed25519-Timestamp {did} {ts} {base64.b64encode(sig).decode()}"
        return {"Authorization": token}

    def test_rejects_no_auth_header(self):
        _, did_b = self._register("bob")
        resp = self.client.post("/api/v1/capabilities/grant", json={
            "capability": "read:data",
            "to_agent": did_b,
        })
        assert resp.status_code == 422  # missing required header

    def test_rejects_caller_does_not_hold_capability(self):
        """Caller authenticates but has no grants — cannot delegate."""
        sk_a, did_a = self._register("alice")
        _, did_b = self._register("bob")
        resp = self.client.post(
            "/api/v1/capabilities/grant",
            json={"capability": "read:data", "to_agent": did_b},
            headers=self._auth(sk_a, did_a),
        )
        assert resp.status_code == 403
        assert "does not hold" in resp.json()["detail"]

    def test_grantor_holding_capability_can_delegate(self):
        """Authenticated caller that holds the cap may delegate it."""
        sk_a, did_a = self._register("alice")
        _, did_b = self._register("bob")
        # Bootstrap: directly seed alice's scope with the capability she
        # is about to delegate (simulates a prior admin/bootstrap grant).
        self.capability_registry.grant(
            capability="read:data",
            to_agent=did_a,
            from_agent="did:mesh:bootstrap",
        )
        resp = self.client.post(
            "/api/v1/capabilities/grant",
            json={"capability": "read:data", "to_agent": did_b},
            headers=self._auth(sk_a, did_a),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["granted_by"] == did_a
        assert self.capability_registry.check(did_b, "read:data")

    def test_grantor_identity_is_authenticated_caller_not_body(self):
        """Even if the body sets ``from_agent``, the grantor is always
        the authenticated DID; spoofed body values are ignored."""
        sk_a, did_a = self._register("alice")
        _, did_b = self._register("bob")
        self.capability_registry.grant(
            capability="read:data",
            to_agent=did_a,
            from_agent="did:mesh:bootstrap",
        )
        resp = self.client.post(
            "/api/v1/capabilities/grant",
            json={
                "capability": "read:data",
                "to_agent": did_b,
                "from_agent": "did:mesh:somebody-else",
            },
            headers=self._auth(sk_a, did_a),
        )
        # Either the model rejects the extra field (422) or it ignores it
        # and the grantor is bound to the authenticated DID. Both are safe.
        assert resp.status_code in (200, 422)
        if resp.status_code == 200:
            assert resp.json()["granted_by"] == did_a


