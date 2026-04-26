# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Security regression tests for the trust handshake.

Verifies the fix for the MSRC-reported DID fabrication vulnerability:
fabricated DIDs must be rejected, only registered identities with valid
Ed25519 signatures may pass the handshake.
"""

import base64

import pytest

from agentmesh.identity.agent_id import AgentIdentity, IdentityRegistry
from agentmesh.trust.bridge import TrustBridge
from agentmesh.trust.handshake import (
    HandshakeChallenge,
    HandshakeResult,
    TrustHandshake,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_registry(*identities: AgentIdentity) -> IdentityRegistry:
    """Create a registry pre-populated with the given identities."""
    registry = IdentityRegistry()
    for identity in identities:
        registry.register(identity)
    return registry


def _make_identity(name: str, capabilities: list[str] | None = None) -> AgentIdentity:
    return AgentIdentity.create(
        name=name,
        sponsor=f"{name}@test.example.com",
        capabilities=capabilities or ["read:data", "write:reports"],
    )


# ---------------------------------------------------------------------------
# Core MSRC PoC — fabricated DID must be rejected
# ---------------------------------------------------------------------------

class TestFabricatedDIDRejection:
    """Reproduce the exact MSRC PoC scenario and verify it is now blocked."""

    @pytest.mark.asyncio
    async def test_fabricated_did_rejected_via_bridge(self):
        """TrustBridge.verify_peer() rejects a completely fabricated DID."""
        legit = _make_identity("legit-agent")
        registry = _make_registry(legit)
        bridge = TrustBridge(
            agent_did=str(legit.did),
            identity=legit,
            registry=registry,
        )

        result = await bridge.verify_peer(peer_did="did:mesh:fakefakefake")

        assert not result.verified
        assert result.trust_score == 0
        assert result.capabilities == []
        assert "did:mesh:fakefakefake" not in bridge.peers

    @pytest.mark.asyncio
    async def test_fabricated_did_rejected_via_handshake(self):
        """TrustHandshake.initiate() rejects a fabricated DID."""
        legit = _make_identity("legit-agent")
        registry = _make_registry(legit)
        hs = TrustHandshake(
            agent_did=str(legit.did),
            identity=legit,
            registry=registry,
        )

        result = await hs.initiate(
            peer_did="did:mesh:attacker123",
            required_trust_score=500,
        )

        assert not result.verified
        assert "attacker123" not in str(result.trust_level) or result.trust_level == "untrusted"

    @pytest.mark.asyncio
    async def test_multiple_fabricated_dids_all_rejected(self):
        """Multiple fabricated DIDs are all rejected (no accumulation)."""
        legit = _make_identity("legit-agent")
        registry = _make_registry(legit)
        bridge = TrustBridge(
            agent_did=str(legit.did),
            identity=legit,
            registry=registry,
        )

        fake_dids = [
            "did:mesh:fakefakefake",
            "did:mesh:attacker123",
            "did:mesh:evil-agent-9999",
        ]

        for fake_did in fake_dids:
            result = await bridge.verify_peer(peer_did=fake_did)
            assert not result.verified

        assert len(bridge.peers) == 0


# ---------------------------------------------------------------------------
# Registry-backed handshake — registered identity passes
# ---------------------------------------------------------------------------

class TestRegisteredIdentityHandshake:
    """Registered identities with valid Ed25519 keys pass the handshake."""

    @pytest.mark.asyncio
    async def test_registered_peer_passes(self):
        """A registered peer with a valid identity passes the handshake."""
        agent_a = _make_identity("agent-a")
        agent_b = _make_identity("agent-b")
        registry = _make_registry(agent_a, agent_b)

        hs = TrustHandshake(
            agent_did=str(agent_a.did),
            identity=agent_a,
            registry=registry,
        )

        result = await hs.initiate(
            peer_did=str(agent_b.did),
            required_trust_score=500,
        )

        assert result.verified
        assert result.trust_score > 0
        assert result.peer_did == str(agent_b.did)
        assert len(result.capabilities) > 0

    @pytest.mark.asyncio
    async def test_mutual_handshake_with_registry(self):
        """Both agents can verify each other when both are in the registry."""
        agent_a = _make_identity("mutual-a")
        agent_b = _make_identity("mutual-b")
        registry = _make_registry(agent_a, agent_b)

        hs_a = TrustHandshake(
            agent_did=str(agent_a.did), identity=agent_a, registry=registry
        )
        hs_b = TrustHandshake(
            agent_did=str(agent_b.did), identity=agent_b, registry=registry
        )

        result_ab = await hs_a.initiate(
            peer_did=str(agent_b.did), required_trust_score=500
        )
        result_ba = await hs_b.initiate(
            peer_did=str(agent_a.did), required_trust_score=500
        )

        assert result_ab.verified
        assert result_ba.verified

    @pytest.mark.asyncio
    async def test_bridge_stores_verified_peer(self):
        """TrustBridge stores a verified peer in its peers dict."""
        agent_a = _make_identity("bridge-a")
        agent_b = _make_identity("bridge-b")
        registry = _make_registry(agent_a, agent_b)

        bridge = TrustBridge(
            agent_did=str(agent_a.did),
            identity=agent_a,
            registry=registry,
            default_trust_threshold=500,
        )

        result = await bridge.verify_peer(peer_did=str(agent_b.did))

        assert result.verified
        peer = bridge.get_peer(str(agent_b.did))
        assert peer is not None
        assert peer.trust_verified


# ---------------------------------------------------------------------------
# Revoked / suspended identity rejection
# ---------------------------------------------------------------------------

class TestRevokedIdentityRejection:
    """Revoked or suspended identities must be rejected."""

    @pytest.mark.asyncio
    async def test_revoked_peer_rejected(self):
        """A revoked identity is rejected during handshake."""
        agent_a = _make_identity("revoker")
        agent_b = _make_identity("revokee")
        registry = _make_registry(agent_a, agent_b)

        # Revoke agent_b
        agent_b.revoke("Compromised")

        hs = TrustHandshake(
            agent_did=str(agent_a.did), identity=agent_a, registry=registry
        )

        result = await hs.initiate(
            peer_did=str(agent_b.did), required_trust_score=500
        )

        assert not result.verified

    @pytest.mark.asyncio
    async def test_suspended_peer_rejected(self):
        """A suspended identity is rejected during handshake."""
        agent_a = _make_identity("suspender")
        agent_b = _make_identity("suspendee")
        registry = _make_registry(agent_a, agent_b)

        agent_b.suspend("Under investigation")

        hs = TrustHandshake(
            agent_did=str(agent_a.did), identity=agent_a, registry=registry
        )

        result = await hs.initiate(
            peer_did=str(agent_b.did), required_trust_score=500
        )

        assert not result.verified


# ---------------------------------------------------------------------------
# No-registry rejects all peers
# ---------------------------------------------------------------------------

class TestNoRegistryRejectsAll:
    """Without a registry, all peers must be rejected."""

    @pytest.mark.asyncio
    async def test_no_registry_rejects_peer(self):
        """TrustHandshake without a registry rejects all peers."""
        hs = TrustHandshake(agent_did="did:mesh:lonely-agent")

        result = await hs.initiate(
            peer_did="did:mesh:any-peer",
            required_trust_score=500,
        )

        assert not result.verified

    @pytest.mark.asyncio
    async def test_bridge_without_registry_rejects_peer(self):
        """TrustBridge without a registry rejects all peers."""
        bridge = TrustBridge(agent_did="did:mesh:lonely-bridge")

        result = await bridge.verify_peer(peer_did="did:mesh:any-peer")

        assert not result.verified
        assert len(bridge.peers) == 0


# ---------------------------------------------------------------------------
# Signature tampering detection
# ---------------------------------------------------------------------------

class TestSignatureTampering:
    """Tampered signatures must be detected and rejected."""

    @pytest.mark.asyncio
    async def test_tampered_signature_rejected(self):
        """A response with a tampered signature is rejected."""
        agent_a = _make_identity("verifier")
        agent_b = _make_identity("responder")
        registry = _make_registry(agent_a, agent_b)

        hs = TrustHandshake(
            agent_did=str(agent_a.did), identity=agent_a, registry=registry
        )

        # Manually create a challenge and get a valid response
        challenge = HandshakeChallenge.generate()
        peer_hs = TrustHandshake(
            agent_did=str(agent_b.did), identity=agent_b, registry=registry
        )
        response = await peer_hs.respond(
            challenge=challenge,
            my_capabilities=["read:data"],
            my_trust_score=500,
            identity=agent_b,
        )

        # Tamper with the signature
        sig_bytes = base64.b64decode(response.signature)
        tampered = bytes([b ^ 0xFF for b in sig_bytes[:8]]) + sig_bytes[8:]
        response.signature = base64.b64encode(tampered).decode()

        verification = await hs._verify_response(
            response, challenge, 500, None
        )

        assert not verification["valid"]
        assert "signature" in verification["reason"].lower()

    @pytest.mark.asyncio
    async def test_wrong_key_signature_rejected(self):
        """A response signed by a different agent's key is rejected."""
        agent_a = _make_identity("verifier")
        agent_b = _make_identity("real-peer")
        agent_c = _make_identity("impersonator")
        registry = _make_registry(agent_a, agent_b, agent_c)

        hs = TrustHandshake(
            agent_did=str(agent_a.did), identity=agent_a, registry=registry
        )

        # Agent C tries to impersonate B by signing a response for B's DID
        challenge = HandshakeChallenge.generate()

        import secrets as _secrets
        response_nonce = _secrets.token_hex(16)
        payload = f"{challenge.challenge_id}:{challenge.nonce}:{response_nonce}:{str(agent_b.did)}"
        wrong_signature = agent_c.sign(payload.encode())

        from agentmesh.trust.handshake import HandshakeResponse
        fake_response = HandshakeResponse(
            challenge_id=challenge.challenge_id,
            response_nonce=response_nonce,
            agent_did=str(agent_b.did),
            capabilities=["read:data"],
            trust_score=500,
            signature=wrong_signature,
            public_key=agent_c.public_key,  # wrong key
        )

        verification = await hs._verify_response(
            fake_response, challenge, 500, None
        )

        assert not verification["valid"]


# ---------------------------------------------------------------------------
# S360 WI 1140377 — Self-reported trust score / capability inflation
# ---------------------------------------------------------------------------

class TestTrustScoreInflation:
    """Self-reported trust scores must be ignored in favour of the registry."""

    @pytest.mark.asyncio
    async def test_inflated_self_reported_trust_score_rejected(self):
        """A peer cannot inflate its trust score to pass a threshold."""
        agent_a = _make_identity("verifier")
        agent_b = _make_identity("low-trust-peer")
        registry = _make_registry(agent_a, agent_b)

        hs = TrustHandshake(
            agent_did=str(agent_a.did), identity=agent_a, registry=registry
        )

        # Get a valid challenge/response
        challenge = HandshakeChallenge.generate()
        peer_hs = TrustHandshake(
            agent_did=str(agent_b.did), identity=agent_b, registry=registry
        )
        response = await peer_hs.respond(
            challenge=challenge,
            my_capabilities=["read:data"],
            my_trust_score=999,  # self-report inflated score
            identity=agent_b,
        )

        # Registry trust score is the default (~500), require 900
        verification = await hs._verify_response(
            response, challenge, 900, None
        )

        # Must reject based on registry score, not self-reported 999
        assert not verification["valid"]
        assert "trust score" in verification["reason"].lower()

    @pytest.mark.asyncio
    async def test_registry_trust_score_used_in_result(self):
        """The result uses the registry trust score, not self-reported."""
        agent_a = _make_identity("verifier")
        agent_b = _make_identity("peer")
        registry = _make_registry(agent_a, agent_b)

        hs = TrustHandshake(
            agent_did=str(agent_a.did), identity=agent_a, registry=registry
        )

        result = await hs.initiate(
            peer_did=str(agent_b.did),
            required_trust_score=0,  # low threshold so it passes
        )

        assert result.verified
        # Trust score should come from registry, not arbitrary self-report
        assert result.trust_score == getattr(agent_b, "trust_score", result.trust_score)


class TestCapabilityInflation:
    """Self-reported capabilities must be ignored in favour of the registry."""

    @pytest.mark.asyncio
    async def test_fake_capabilities_rejected(self):
        """A peer cannot claim capabilities it does not have in the registry."""
        agent_a = _make_identity("verifier")
        # agent_b only has ["read:data", "write:reports"]
        agent_b = _make_identity("limited-peer")
        registry = _make_registry(agent_a, agent_b)

        hs = TrustHandshake(
            agent_did=str(agent_a.did), identity=agent_a, registry=registry
        )

        challenge = HandshakeChallenge.generate()
        peer_hs = TrustHandshake(
            agent_did=str(agent_b.did), identity=agent_b, registry=registry
        )
        response = await peer_hs.respond(
            challenge=challenge,
            my_capabilities=["read:data", "admin:delete"],  # inflated
            my_trust_score=500,
            identity=agent_b,
        )

        # Require admin:delete which is NOT in the registry
        verification = await hs._verify_response(
            response, challenge, 0, ["admin:delete"]
        )

        assert not verification["valid"]
        assert "missing capabilities" in verification["reason"].lower()

    @pytest.mark.asyncio
    async def test_registry_capabilities_used_in_result(self):
        """The HandshakeResult uses registry capabilities, not self-reported."""
        agent_a = _make_identity("verifier")
        agent_b = _make_identity("peer", capabilities=["read:data", "write:reports"])
        registry = _make_registry(agent_a, agent_b)

        hs = TrustHandshake(
            agent_did=str(agent_a.did), identity=agent_a, registry=registry
        )

        result = await hs.initiate(
            peer_did=str(agent_b.did),
            required_trust_score=0,
        )

        assert result.verified
        # Capabilities must come from registry, not self-reported
        assert set(result.capabilities) == {"read:data", "write:reports"}


class TestDIDBindingEnforcement:
    """Response DID must match the expected peer DID."""

    @pytest.mark.asyncio
    async def test_did_substitution_rejected(self):
        """A response for a different DID than requested is rejected."""
        agent_a = _make_identity("verifier")
        agent_b = _make_identity("expected-peer")
        agent_c = _make_identity("substitute-peer")
        registry = _make_registry(agent_a, agent_b, agent_c)

        hs = TrustHandshake(
            agent_did=str(agent_a.did), identity=agent_a, registry=registry
        )

        # Agent C creates a valid response for itself
        challenge = HandshakeChallenge.generate()
        peer_hs = TrustHandshake(
            agent_did=str(agent_c.did), identity=agent_c, registry=registry
        )
        response = await peer_hs.respond(
            challenge=challenge,
            my_capabilities=["read:data"],
            my_trust_score=500,
            identity=agent_c,
        )

        # Verify with expected_peer_did=agent_b, but response is from agent_c
        verification = await hs._verify_response(
            response, challenge, 0, None,
            expected_peer_did=str(agent_b.did),
        )

        assert not verification["valid"]
        assert "does not match" in verification["reason"].lower()
