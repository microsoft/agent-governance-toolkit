# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for AgentMesh component server endpoints.

Uses FastAPI TestClient for synchronous HTTP testing of all four servers.
"""

import pytest

fastapi = pytest.importorskip("fastapi", reason="fastapi not installed (optional [server] extra)")
from fastapi.testclient import TestClient  # noqa: E402


# ── Trust Engine Tests ───────────────────────────────────────────────


class TestTrustEngineServer:
    """Tests for the trust-engine HTTP server."""

    @pytest.fixture(autouse=True)
    def setup(self):
        from agentmesh.server.trust_engine import app, registry, _pending_challenges

        _pending_challenges.clear()
        # Clear registry between tests
        registry._identities.clear()
        registry._by_sponsor.clear()
        self.client = TestClient(app)

    def test_healthz(self):
        resp = self.client.get("/healthz")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["component"] == "trust-engine"

    def test_readyz(self):
        resp = self.client.get("/readyz")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ready"

    def test_metrics(self):
        resp = self.client.get("/metrics")
        assert resp.status_code == 200
        data = resp.json()
        assert "uptime_seconds" in data
        assert data["component"] == "trust-engine"

    def test_register_agent(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        import base64

        key = Ed25519PrivateKey.generate()
        pub_bytes = key.public_key().public_bytes_raw()
        pub_b64 = base64.b64encode(pub_bytes).decode()

        resp = self.client.post("/api/v1/agents/register", json={
            "name": "test-agent",
            "public_key": pub_b64,
            "sponsor_email": "test@example.com",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "registered"
        assert data["agent_did"].startswith("did:mesh:")

    def test_challenge_unregistered_agent(self):
        resp = self.client.post("/api/v1/handshake/challenge", json={
            "agent_did": "did:mesh:nonexistent",
        })
        assert resp.status_code == 404

    def test_challenge_registered_agent(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        import base64

        key = Ed25519PrivateKey.generate()
        pub_b64 = base64.b64encode(key.public_key().public_bytes_raw()).decode()

        # Register first
        reg_resp = self.client.post("/api/v1/agents/register", json={
            "name": "challenge-agent",
            "public_key": pub_b64,
            "sponsor_email": "test@example.com",
        })
        agent_did = reg_resp.json()["agent_did"]

        # Issue challenge
        resp = self.client.post("/api/v1/handshake/challenge", json={
            "agent_did": agent_did,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "challenge_id" in data
        assert "nonce" in data
        assert data["expires_in_seconds"] > 0

    def test_verify_unknown_challenge(self):
        resp = self.client.post("/api/v1/handshake/verify", json={
            "challenge_id": "nonexistent",
            "agent_did": "did:mesh:test",
            "response_nonce": "abc",
            "signature": "deadbeef",
            "public_key": "AAAA",
        })
        assert resp.status_code == 404

    def _register_and_challenge(self):
        """Register a fresh agent and issue a challenge.

        Returns ``(private_key, public_key_b64, agent_did, challenge_id, nonce)``
        ready for signing a valid handshake response.
        """
        import base64

        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        key = Ed25519PrivateKey.generate()
        pub_b64 = base64.b64encode(key.public_key().public_bytes_raw()).decode()

        reg = self.client.post("/api/v1/agents/register", json={
            "name": "verify-agent",
            "public_key": pub_b64,
            "sponsor_email": "verify@example.com",
        })
        assert reg.status_code == 200
        agent_did = reg.json()["agent_did"]

        ch = self.client.post("/api/v1/handshake/challenge", json={
            "agent_did": agent_did,
        })
        assert ch.status_code == 200
        ch_data = ch.json()
        return key, pub_b64, agent_did, ch_data["challenge_id"], ch_data["nonce"]

    def test_verify_valid_signed_response(self):
        """A correctly signed challenge response is reported as verified.

        Regression test for the dict-key mismatch where _verify_response
        returned ``{"valid": True, ...}`` but the endpoint read keys named
        ``verified`` / ``trust_score`` / ``trust_level`` — causing every
        successful verification to be reported as ``verified=False``.
        """
        import base64
        import secrets

        key, _pub_b64, agent_did, challenge_id, challenge_nonce = self._register_and_challenge()

        response_nonce = secrets.token_hex(16)
        payload = f"{challenge_id}:{challenge_nonce}:{response_nonce}:{agent_did}"
        signature_b64 = base64.b64encode(key.sign(payload.encode())).decode()

        resp = self.client.post("/api/v1/handshake/verify", json={
            "challenge_id": challenge_id,
            "agent_did": agent_did,
            "response_nonce": response_nonce,
            "signature": signature_b64,
            "public_key": base64.b64encode(key.public_key().public_bytes_raw()).decode(),
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["verified"] is True, f"expected verified=True, got {data}"
        assert data["trust_score"] >= 0
        # trust_level must be one of the canonical labels emitted by
        # agentmesh.trust.levels.trust_level_for_score; it must not be the
        # legacy empty-string default that masked the dict-key bug.
        assert data["trust_level"] in {
            "verified_partner", "trusted", "standard", "probationary", "untrusted",
        }
        assert data["peer_did"] == agent_did
        assert data["rejection_reason"] is None

    def test_verify_invalid_signature(self):
        """A response with a tampered signature is reported as not verified
        with a populated rejection_reason."""
        import base64
        import secrets

        key, _pub_b64, agent_did, challenge_id, challenge_nonce = self._register_and_challenge()

        response_nonce = secrets.token_hex(16)
        payload = f"{challenge_id}:{challenge_nonce}:{response_nonce}:{agent_did}"
        sig = bytearray(key.sign(payload.encode()))
        sig[0] ^= 0xFF  # tamper the first byte
        bad_sig_b64 = base64.b64encode(bytes(sig)).decode()

        resp = self.client.post("/api/v1/handshake/verify", json={
            "challenge_id": challenge_id,
            "agent_did": agent_did,
            "response_nonce": response_nonce,
            "signature": bad_sig_b64,
            "public_key": base64.b64encode(key.public_key().public_bytes_raw()).decode(),
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["verified"] is False
        assert data["trust_score"] == 0
        assert data["trust_level"] == ""
        assert data["rejection_reason"] is not None
        assert "signature" in data["rejection_reason"].lower()

    def test_capabilities_empty(self):
        resp = self.client.get("/api/v1/capabilities/did:mesh:unknown")
        assert resp.status_code == 200
        data = resp.json()
        assert data["capabilities"] == []


# ── Policy Server Tests ──────────────────────────────────────────────


class TestPolicyServer:
    """Tests for the policy-server HTTP server."""

    @pytest.fixture(autouse=True)
    def setup(self):
        from agentmesh.server.policy_server import app

        self.client = TestClient(app)

    def test_healthz(self):
        resp = self.client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json()["component"] == "policy-server"

    def test_readyz(self):
        resp = self.client.get("/readyz")
        assert resp.status_code == 200

    def test_evaluate_no_policies(self):
        resp = self.client.post("/api/v1/policy/evaluate", json={
            "agent_did": "did:mesh:test-agent",
            "action": "read",
            "resource": "data",
        })
        assert resp.status_code == 200
        data = resp.json()
        # PolicyEngine default_action is "allow" when no policies loaded
        assert data["decision"] in ("allow", "deny")

    def test_list_policies(self):
        resp = self.client.get("/api/v1/policies")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_loaded" in data

    def test_reload_policies(self):
        resp = self.client.post("/api/v1/policy/reload")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "reloaded"

    def test_trust_evaluate_no_policies(self):
        resp = self.client.post("/api/v1/policy/trust/evaluate", json={
            "context": {"action": "test"},
        })
        # No trust policies loaded → 503
        assert resp.status_code == 503


# ── Audit Collector Tests ────────────────────────────────────────────


class TestAuditCollector:
    """Tests for the audit-collector HTTP server."""

    @pytest.fixture(autouse=True)
    def setup(self):
        from agentmesh.server.audit_collector import app, _audit_service

        # Reset audit state between tests — recreate internal log
        _audit_service._log = __import__(
            "agentmesh.governance.audit", fromlist=["AuditLog"]
        ).AuditLog()
        self.client = TestClient(app)

    def test_healthz(self):
        resp = self.client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json()["component"] == "audit-collector"

    def test_log_entry(self):
        resp = self.client.post("/api/v1/audit/log", json={
            "event_type": "agent_action",
            "agent_did": "did:mesh:test-agent",
            "action": "read_data",
            "outcome": "success",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "entry_id" in data
        assert "entry_hash" in data

    def test_log_batch(self):
        resp = self.client.post("/api/v1/audit/batch", json={
            "entries": [
                {"event_type": "agent_action", "agent_did": "did:mesh:a1", "action": "read"},
                {"event_type": "agent_action", "agent_did": "did:mesh:a2", "action": "write"},
            ]
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["logged"] == 2

    def test_verify_integrity_empty(self):
        resp = self.client.get("/api/v1/audit/verify")
        assert resp.status_code == 200
        data = resp.json()
        assert data["chain_valid"] is True

    def test_verify_integrity_after_entries(self):
        # Log some entries
        for i in range(5):
            self.client.post("/api/v1/audit/log", json={
                "event_type": "test",
                "agent_did": f"did:mesh:agent-{i}",
                "action": f"action-{i}",
            })

        resp = self.client.get("/api/v1/audit/verify")
        assert resp.status_code == 200
        data = resp.json()
        assert data["chain_valid"] is True
        assert data["entry_count"] == 5

    def test_summary(self):
        self.client.post("/api/v1/audit/log", json={
            "event_type": "test",
            "agent_did": "did:mesh:a1",
            "action": "x",
        })
        resp = self.client.get("/api/v1/audit/summary")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_entries"] == 1
        assert data["chain_valid"] is True

    def test_query_by_agent(self):
        self.client.post("/api/v1/audit/log", json={
            "event_type": "test",
            "agent_did": "did:mesh:target",
            "action": "test_action",
        })
        resp = self.client.post("/api/v1/audit/query", json={
            "agent_did": "did:mesh:target",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1


# ── API Gateway Tests ────────────────────────────────────────────────


class TestApiGateway:
    """Tests for the api-gateway HTTP server."""

    @pytest.fixture(autouse=True)
    def setup(self):
        from agentmesh.server.api_gateway import app

        self.client = TestClient(app)

    def test_healthz(self):
        resp = self.client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json()["component"] == "api-gateway"

    def test_readyz(self):
        resp = self.client.get("/readyz")
        assert resp.status_code == 200

    def test_gateway_status(self):
        resp = self.client.get("/api/v1/gateway/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "trust-engine" in data["upstreams"]
        assert "policy-server" in data["upstreams"]
        assert "audit-collector" in data["upstreams"]

    def test_proxy_unknown_path(self):
        resp = self.client.get("/api/v1/unknown/endpoint")
        assert resp.status_code == 404

    def test_proxy_upstream_unreachable(self):
        import httpx
        from agentmesh.server import api_gateway
        # Ensure the async client is initialized for the test
        api_gateway._client = httpx.AsyncClient(timeout=5.0)
        try:
            resp = self.client.post(
                "/api/v1/handshake/challenge",
                json={"agent_did": "did:mesh:test"},
            )
            # Either 502 (upstream unreachable) or 504 (timeout)
            assert resp.status_code in (502, 504)
        finally:
            api_gateway._client = None


# ── __main__ Module Tests ────────────────────────────────────────────


class TestMainModule:
    """Tests for the __main__ CLI entry point."""

    def test_unknown_component_exits(self):
        import subprocess
        import os
        env = {**os.environ}
        env.pop("AGENTMESH_COMPONENT", None)
        result = subprocess.run(
            ["python", "-c", "import sys; sys.argv=['test','invalid']; from agentmesh.server.__main__ import main; main()"],
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
            cwd=str(
                __import__("pathlib").Path(__file__).parent.parent
            ),
        )
        assert result.returncode != 0

    def test_no_args_exits(self):
        import subprocess
        import os
        env = {**os.environ}
        env.pop("AGENTMESH_COMPONENT", None)
        result = subprocess.run(
            ["python", "-c", "import sys; sys.argv=['test']; from agentmesh.server.__main__ import main; main()"],
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
            cwd=str(
                __import__("pathlib").Path(__file__).parent.parent
            ),
        )
        assert result.returncode != 0
