# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for AgentMesh LangChain integration."""

import json
from datetime import datetime, timedelta, timezone
from threading import Thread

from langchain_agentmesh import (
    AgentDirectory,
    DelegationChain,
    TrustCallbackHandler,
    TrustGatedTool,
    TrustHandshake,
    TrustPolicy,
    TrustedAgentCard,
    UserContext,
    VerificationIdentity,
)


class TestVerificationIdentity:
    """Tests for VerificationIdentity class."""

    def test_generate_identity(self):
        """Test identity generation."""
        identity = VerificationIdentity.generate(
            agent_name="test-agent",
            capabilities=["read", "write"]
        )
        
        assert identity.did.startswith("did:verification:")
        assert identity.agent_name == "test-agent"
        assert identity.public_key
        assert identity.private_key
        assert identity.capabilities == ["read", "write"]

    def test_sign_and_verify(self):
        """Test signing and verification."""
        identity = VerificationIdentity.generate("signer-agent")
        data = "test data to sign"
        
        signature = identity.sign(data)
        
        assert signature.public_key == identity.public_key
        assert signature.signature
        assert identity.verify_signature(data, signature)

    def test_verify_fails_wrong_data(self):
        """Test verification fails with wrong data."""
        identity = VerificationIdentity.generate("signer-agent")
        signature = identity.sign("original data")
        
        # Verification should fail with different data
        assert not identity.verify_signature("tampered data", signature)

    def test_public_identity(self):
        """Test public identity excludes private key."""
        identity = VerificationIdentity.generate("test-agent")
        public = identity.public_identity()
        
        assert public.did == identity.did
        assert public.public_key == identity.public_key
        assert public.private_key is None


class TestTrustedAgentCard:
    """Tests for TrustedAgentCard class."""

    def test_create_and_sign_card(self):
        """Test card creation and signing."""
        identity = VerificationIdentity.generate("card-agent", ["capability1"])
        
        card = TrustedAgentCard(
            name="Test Agent",
            description="A test agent",
            capabilities=["capability1", "capability2"],
        )
        card.sign(identity)
        
        assert card.identity is not None
        assert card.card_signature is not None
        assert card.verify_signature()

    def test_serialization(self):
        """Test card JSON serialization."""
        identity = VerificationIdentity.generate("json-agent")
        card = TrustedAgentCard(
            name="JSON Agent",
            description="Tests JSON",
            capabilities=["serialize"],
        )
        card.sign(identity)
        
        json_data = card.to_json()
        restored = TrustedAgentCard.from_json(json_data)
        
        assert restored.name == card.name
        assert restored.capabilities == card.capabilities
        assert restored.identity.did == card.identity.did


class TestTrustHandshake:
    """Tests for TrustHandshake class."""

    def test_verify_valid_peer(self):
        """Test verification of a valid peer."""
        my_identity = VerificationIdentity.generate("my-agent")
        peer_identity = VerificationIdentity.generate("peer-agent", ["required_cap"])
        
        peer_card = TrustedAgentCard(
            name="Peer Agent",
            description="A peer",
            capabilities=["required_cap"],
        )
        peer_card.sign(peer_identity)
        
        handshake = TrustHandshake(my_identity)
        result = handshake.verify_peer(
            peer_card,
            required_capabilities=["required_cap"]
        )
        
        assert result.trusted
        assert result.trust_score == 1.0

    def test_verify_missing_capability(self):
        """Test verification fails for missing capability."""
        my_identity = VerificationIdentity.generate("my-agent")
        peer_identity = VerificationIdentity.generate("peer-agent", ["cap1"])
        
        peer_card = TrustedAgentCard(
            name="Peer Agent",
            description="A peer",
            capabilities=["cap1"],
        )
        peer_card.sign(peer_identity)
        
        handshake = TrustHandshake(my_identity)
        result = handshake.verify_peer(
            peer_card,
            required_capabilities=["cap1", "cap2"]
        )
        
        assert not result.trusted
        assert "Missing required capabilities" in result.reason

    def test_cache_ttl(self):
        """Test that verification results are cached."""
        my_identity = VerificationIdentity.generate("my-agent")
        peer_identity = VerificationIdentity.generate("peer-agent")
        
        peer_card = TrustedAgentCard(
            name="Peer Agent",
            description="A peer",
            capabilities=[],
        )
        peer_card.sign(peer_identity)
        
        handshake = TrustHandshake(my_identity)
        
        # First verification
        result1 = handshake.verify_peer(peer_card)
        # Second should use cache
        result2 = handshake.verify_peer(peer_card)
        
        assert result1.trusted == result2.trusted

    def test_verify_valid_peer_scope_chain(self):
        """Valid cryptographic scope chain should be trusted."""
        my_identity = VerificationIdentity.generate("my-agent")
        peer_identity = VerificationIdentity.generate("peer-agent", ["required_cap"])

        peer_card = TrustedAgentCard(
            name="Peer Agent",
            description="A peer",
            capabilities=["required_cap"],
        )
        peer_card.sign(peer_identity)

        chain = DelegationChain(my_identity)
        chain.add_delegation(
            delegatee=peer_card,
            capabilities=["required_cap"],
            expires_in_hours=24,
        )
        peer_card.scope_chain = chain.delegations

        handshake = TrustHandshake(my_identity)
        result = handshake.verify_peer(
            peer_card,
            required_capabilities=["required_cap"],
        )

        assert result.trusted
        assert result.reason == "Verification successful"

    def test_verify_peer_scope_chain_tampered_signature(self):
        """Tampering delegation payload should invalidate signature."""
        my_identity = VerificationIdentity.generate("my-agent")
        peer_identity = VerificationIdentity.generate("peer-agent", ["required_cap"])

        peer_card = TrustedAgentCard(
            name="Peer Agent",
            description="A peer",
            capabilities=["required_cap"],
        )
        peer_card.sign(peer_identity)

        chain = DelegationChain(my_identity)
        chain.add_delegation(
            delegatee=peer_card,
            capabilities=["required_cap"],
            expires_in_hours=24,
        )

        # Mutate signed content after signature generation.
        chain.delegations[0].capabilities.append("admin")
        peer_card.scope_chain = chain.delegations

        handshake = TrustHandshake(my_identity)
        result = handshake.verify_peer(peer_card)

        assert not result.trusted
        assert result.reason == "Scope chain verification failed"

    def test_verify_peer_scope_chain_tampered_linkage(self):
        """Broken delegation linkage should fail verification."""
        my_identity = VerificationIdentity.generate("my-agent")
        mid_identity = VerificationIdentity.generate("mid-agent")
        peer_identity = VerificationIdentity.generate("peer-agent", ["required_cap"])

        mid_card = TrustedAgentCard(
            name="Mid Agent",
            description="Delegation intermediary",
            capabilities=["delegator"],
        )
        mid_card.sign(mid_identity)

        peer_card = TrustedAgentCard(
            name="Peer Agent",
            description="Final peer",
            capabilities=["required_cap"],
        )
        peer_card.sign(peer_identity)

        chain = DelegationChain(my_identity)
        chain.add_delegation(
            delegatee=mid_card,
            capabilities=["delegate"],
            expires_in_hours=24,
        )
        chain.add_delegation(
            delegatee=peer_card,
            capabilities=["required_cap"],
            expires_in_hours=24,
            delegator_identity=mid_identity,
        )

        # Break did->did linkage between first delegatee and second delegator.
        chain.delegations[1].delegator = "did:verification:maliciousdelegator"
        peer_card.scope_chain = chain.delegations

        handshake = TrustHandshake(my_identity)
        result = handshake.verify_peer(peer_card)

        assert not result.trusted
        assert result.reason == "Scope chain verification failed"

    def test_verify_peer_scope_chain_expired(self):
        """Expired delegations should fail verification."""
        my_identity = VerificationIdentity.generate("my-agent")
        peer_identity = VerificationIdentity.generate("peer-agent", ["required_cap"])

        peer_card = TrustedAgentCard(
            name="Peer Agent",
            description="A peer",
            capabilities=["required_cap"],
        )
        peer_card.sign(peer_identity)

        chain = DelegationChain(my_identity)
        chain.add_delegation(
            delegatee=peer_card,
            capabilities=["required_cap"],
            expires_in_hours=24,
        )

        chain.delegations[0].expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
        peer_card.scope_chain = chain.delegations

        handshake = TrustHandshake(my_identity)
        result = handshake.verify_peer(peer_card)

        assert not result.trusted
        assert result.reason == "Scope chain verification failed"

    def test_verify_scope_chain_returns_effective_capabilities(self):
        """Public scope-chain verifier returns the final delegated permissions."""
        my_identity = VerificationIdentity.generate("my-agent", ["read", "write"])
        mid_identity = VerificationIdentity.generate("mid-agent")
        peer_identity = VerificationIdentity.generate("peer-agent", ["read", "write"])

        mid_card = TrustedAgentCard(
            name="Mid Agent",
            description="Delegation intermediary",
            capabilities=["read"],
        )
        mid_card.sign(mid_identity)

        peer_card = TrustedAgentCard(
            name="Peer Agent",
            description="A peer",
            capabilities=["read", "write"],
        )
        peer_card.sign(peer_identity)

        chain = DelegationChain(my_identity)
        chain.add_delegation(
            delegatee=mid_card,
            capabilities=["read"],
            expires_in_hours=24,
        )
        chain.add_delegation(
            delegatee=peer_card,
            capabilities=["read"],
            expires_in_hours=24,
            delegator_identity=mid_identity,
        )

        handshake = TrustHandshake(my_identity)
        is_valid, error, effective_caps = handshake.verify_scope_chain(
            chain.delegations,
            expected_leaf_did=peer_identity.did,
        )

        assert is_valid
        assert error == ""
        assert effective_caps == ["read"]

    def test_verify_peer_scope_chain_replay_detected(self):
        """Reusing the exact same scope chain inside replay window is rejected."""
        my_identity = VerificationIdentity.generate("my-agent")
        peer_identity = VerificationIdentity.generate("peer-agent", ["required_cap"])

        peer_card = TrustedAgentCard(
            name="Peer Agent",
            description="A peer",
            capabilities=["required_cap"],
        )
        peer_card.sign(peer_identity)

        chain = DelegationChain(my_identity)
        chain.add_delegation(
            delegatee=peer_card,
            capabilities=["required_cap"],
            expires_in_hours=24,
        )
        peer_card.scope_chain = chain.delegations

        handshake = TrustHandshake(
            my_identity,
            policy=TrustPolicy(cache_ttl_seconds=0),
        )
        result1 = handshake.verify_peer(peer_card)
        assert result1.trusted

        result2 = handshake.verify_peer(peer_card)
        assert not result2.trusted
        assert result2.reason == "Scope chain verification failed"

    def test_verify_peer_scope_chain_replay_window_expired(self):
        """Reusing chain after replay window should be allowed."""
        my_identity = VerificationIdentity.generate("my-agent")
        peer_identity = VerificationIdentity.generate("peer-agent", ["required_cap"])

        peer_card = TrustedAgentCard(
            name="Peer Agent",
            description="A peer",
            capabilities=["required_cap"],
        )
        peer_card.sign(peer_identity)

        chain = DelegationChain(my_identity)
        chain.add_delegation(
            delegatee=peer_card,
            capabilities=["required_cap"],
            expires_in_hours=24,
        )
        peer_card.scope_chain = chain.delegations

        handshake = TrustHandshake(
            my_identity,
            policy=TrustPolicy(cache_ttl_seconds=0, replay_window_seconds=1),
        )
        result1 = handshake.verify_peer(peer_card)
        assert result1.trusted

        for fingerprint in list(handshake._seen_scope_chains.keys()):
            handshake._seen_scope_chains[fingerprint] = datetime.now(timezone.utc) - timedelta(seconds=2)

        result2 = handshake.verify_peer(peer_card)
        assert result2.trusted

    def test_verify_peer_scope_chain_unsupported_algorithm(self):
        """Delegation signatures must use verification-Ed25519."""
        my_identity = VerificationIdentity.generate("my-agent")
        peer_identity = VerificationIdentity.generate("peer-agent", ["required_cap"])

        peer_card = TrustedAgentCard(
            name="Peer Agent",
            description="A peer",
            capabilities=["required_cap"],
        )
        peer_card.sign(peer_identity)

        chain = DelegationChain(my_identity)
        chain.add_delegation(
            delegatee=peer_card,
            capabilities=["required_cap"],
            expires_in_hours=24,
        )

        chain.delegations[0].signature.algorithm = "rsa-sha1"
        peer_card.scope_chain = chain.delegations

        handshake = TrustHandshake(my_identity)
        result = handshake.verify_peer(peer_card)

        assert not result.trusted
        assert result.reason == "Scope chain verification failed"

    def test_verify_peer_scope_chain_stale_signature(self):
        """Old delegation signatures are rejected as replay-hardening."""
        my_identity = VerificationIdentity.generate("my-agent")
        peer_identity = VerificationIdentity.generate("peer-agent", ["required_cap"])

        peer_card = TrustedAgentCard(
            name="Peer Agent",
            description="A peer",
            capabilities=["required_cap"],
        )
        peer_card.sign(peer_identity)

        chain = DelegationChain(my_identity)
        chain.add_delegation(
            delegatee=peer_card,
            capabilities=["required_cap"],
            expires_in_hours=24,
        )

        chain.delegations[0].signature.timestamp = datetime.now(timezone.utc) - timedelta(hours=2)
        peer_card.scope_chain = chain.delegations

        handshake = TrustHandshake(
            my_identity,
            policy=TrustPolicy(max_delegation_signature_age_seconds=60),
        )
        result = handshake.verify_peer(peer_card)

        assert not result.trusted
        assert result.reason == "Scope chain verification failed"

    def test_verify_peer_scope_chain_invalid_delegator_did(self):
        """Malformed DIDs in chain are rejected."""
        my_identity = VerificationIdentity.generate("my-agent")
        mid_identity = VerificationIdentity.generate("mid-agent")
        peer_identity = VerificationIdentity.generate("peer-agent", ["required_cap"])

        mid_card = TrustedAgentCard(
            name="Mid Agent",
            description="Delegation intermediary",
            capabilities=["delegate"],
        )
        mid_card.sign(mid_identity)

        peer_card = TrustedAgentCard(
            name="Peer Agent",
            description="A peer",
            capabilities=["required_cap"],
        )
        peer_card.sign(peer_identity)

        chain = DelegationChain(my_identity)
        chain.add_delegation(
            delegatee=mid_card,
            capabilities=["delegate"],
            expires_in_hours=24,
        )
        chain.add_delegation(
            delegatee=peer_card,
            capabilities=["required_cap"],
            expires_in_hours=24,
            delegator_identity=mid_identity,
        )

        chain.delegations[1].delegator = "invalid-did"
        peer_card.scope_chain = chain.delegations

        handshake = TrustHandshake(my_identity)
        result = handshake.verify_peer(peer_card)

        assert not result.trusted
        assert result.reason == "Scope chain verification failed"

    def test_verify_peer_scope_chain_circular_delegation(self):
        """Delegation loops are rejected."""
        my_identity = VerificationIdentity.generate("my-agent", ["delegate"])
        mid_identity = VerificationIdentity.generate("mid-agent", ["delegate"])
        peer_identity = VerificationIdentity.generate("peer-agent", ["delegate"])

        mid_card = TrustedAgentCard(
            name="Mid Agent",
            description="Delegation intermediary",
            capabilities=["delegate"],
        )
        mid_card.sign(mid_identity)

        peer_card = TrustedAgentCard(
            name="Peer Agent",
            description="A peer",
            capabilities=["delegate"],
        )
        peer_card.sign(peer_identity)

        chain = DelegationChain(my_identity)
        chain.add_delegation(
            delegatee=mid_card,
            capabilities=["delegate"],
            expires_in_hours=24,
        )
        chain.add_delegation(
            delegatee=peer_card,
            capabilities=["delegate"],
            expires_in_hours=24,
            delegator_identity=mid_identity,
        )

        loop_payload = json.dumps(
            {
                "delegator": peer_identity.did,
                "delegatee": my_identity.did,
                "capabilities": ["delegate"],
                "expires_at": None,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        chain.delegations.append(
            chain.delegations[-1].__class__(
                delegator=peer_identity.did,
                delegatee=my_identity.did,
                capabilities=["delegate"],
                signature=peer_identity.sign(loop_payload),
            )
        )
        peer_card.scope_chain = chain.delegations

        handshake = TrustHandshake(my_identity)
        result = handshake.verify_peer(peer_card)

        assert not result.trusted
        assert result.reason == "Scope chain verification failed"

    def test_verify_peer_scope_chain_rejects_permission_escalation(self):
        """A child cannot receive permissions absent from the parent delegation."""
        my_identity = VerificationIdentity.generate("my-agent", ["read"])
        mid_identity = VerificationIdentity.generate("mid-agent")
        peer_identity = VerificationIdentity.generate("peer-agent", ["write"])

        mid_card = TrustedAgentCard(
            name="Mid Agent",
            description="Delegation intermediary",
            capabilities=["read"],
        )
        mid_card.sign(mid_identity)

        peer_card = TrustedAgentCard(
            name="Peer Agent",
            description="A peer",
            capabilities=["write"],
        )
        peer_card.sign(peer_identity)

        chain = DelegationChain(my_identity)
        chain.add_delegation(
            delegatee=mid_card,
            capabilities=["read"],
            expires_in_hours=24,
        )
        chain.add_delegation(
            delegatee=peer_card,
            capabilities=["write"],
            expires_in_hours=24,
            delegator_identity=mid_identity,
        )
        peer_card.scope_chain = chain.delegations

        handshake = TrustHandshake(my_identity)
        result = handshake.verify_peer(peer_card)

        assert not result.trusted
        assert result.reason == "Scope chain verification failed"

    def test_verify_peer_uses_scope_chain_capabilities_for_authorization(self):
        """Peer card capabilities alone do not bypass delegated scope narrowing."""
        my_identity = VerificationIdentity.generate("my-agent", ["read", "write"])
        mid_identity = VerificationIdentity.generate("mid-agent")
        peer_identity = VerificationIdentity.generate("peer-agent", ["read", "write"])

        mid_card = TrustedAgentCard(
            name="Mid Agent",
            description="Delegation intermediary",
            capabilities=["read"],
        )
        mid_card.sign(mid_identity)

        peer_card = TrustedAgentCard(
            name="Peer Agent",
            description="A peer",
            capabilities=["read", "write"],
        )
        peer_card.sign(peer_identity)

        chain = DelegationChain(my_identity)
        chain.add_delegation(
            delegatee=mid_card,
            capabilities=["read"],
            expires_in_hours=24,
        )
        chain.add_delegation(
            delegatee=peer_card,
            capabilities=["read"],
            expires_in_hours=24,
            delegator_identity=mid_identity,
        )
        peer_card.scope_chain = chain.delegations

        handshake = TrustHandshake(my_identity)
        result = handshake.verify_peer(peer_card, required_capabilities=["write"])

        assert not result.trusted
        assert result.reason == "Missing required capabilities: {'write'}"

    def test_verify_peer_scope_chain_exposed_error_details(self):
        """Detailed errors can be exposed explicitly by policy."""
        my_identity = VerificationIdentity.generate("my-agent")
        peer_identity = VerificationIdentity.generate("peer-agent", ["required_cap"])

        peer_card = TrustedAgentCard(
            name="Peer Agent",
            description="A peer",
            capabilities=["required_cap"],
        )
        peer_card.sign(peer_identity)

        chain = DelegationChain(my_identity)
        chain.add_delegation(
            delegatee=peer_card,
            capabilities=["required_cap"],
            expires_in_hours=24,
        )
        chain.delegations[0].signature.algorithm = "rsa-sha1"
        peer_card.scope_chain = chain.delegations

        handshake = TrustHandshake(
            my_identity,
            policy=TrustPolicy(expose_scope_chain_errors=True),
        )
        result = handshake.verify_peer(peer_card)

        assert not result.trusted
        assert "unsupported signature algorithm" in result.reason

    def test_verify_peer_scope_chain_non_strict_mode(self):
        """Transitional non-strict mode keeps peer trusted and emits warning."""
        my_identity = VerificationIdentity.generate("my-agent")
        peer_identity = VerificationIdentity.generate("peer-agent", ["required_cap"])

        peer_card = TrustedAgentCard(
            name="Peer Agent",
            description="A peer",
            capabilities=["required_cap"],
        )
        peer_card.sign(peer_identity)

        chain = DelegationChain(my_identity)
        chain.add_delegation(
            delegatee=peer_card,
            capabilities=["required_cap"],
            expires_in_hours=24,
        )
        chain.delegations[0].signature.algorithm = "rsa-sha1"
        peer_card.scope_chain = chain.delegations

        handshake = TrustHandshake(
            my_identity,
            policy=TrustPolicy(strict_scope_chain_verification=False),
        )
        result = handshake.verify_peer(peer_card)

        assert result.trusted
        assert result.warnings == ["Scope chain verification failed"]

    def test_verify_peer_scope_chain_policy_cannot_enable_unsupported_algorithm(self):
        """Policy cannot enable algorithms unsupported by verifier implementation."""
        my_identity = VerificationIdentity.generate("my-agent")
        peer_identity = VerificationIdentity.generate("peer-agent", ["required_cap"])

        peer_card = TrustedAgentCard(
            name="Peer Agent",
            description="A peer",
            capabilities=["required_cap"],
        )
        peer_card.sign(peer_identity)

        chain = DelegationChain(my_identity)
        chain.add_delegation(
            delegatee=peer_card,
            capabilities=["required_cap"],
            expires_in_hours=24,
        )
        chain.delegations[0].signature.algorithm = "future-ed25519-v2"
        peer_card.scope_chain = chain.delegations

        handshake = TrustHandshake(
            my_identity,
            policy=TrustPolicy(allowed_signature_algorithms=["future-ed25519-v2"]),
        )
        result = handshake.verify_peer(peer_card)

        assert not result.trusted
        assert result.reason == "Scope chain verification failed"

    def test_verify_peer_scope_chain_expiry_skew_tolerance(self):
        """Delegation expiry allows bounded clock skew tolerance."""
        my_identity = VerificationIdentity.generate("my-agent")
        peer_identity = VerificationIdentity.generate("peer-agent", ["required_cap"])

        peer_card = TrustedAgentCard(
            name="Peer Agent",
            description="A peer",
            capabilities=["required_cap"],
        )
        peer_card.sign(peer_identity)

        chain = DelegationChain(my_identity)
        delegation = chain.add_delegation(
            delegatee=peer_card,
            capabilities=["required_cap"],
            expires_in_hours=1,
        )

        delegation.expires_at = datetime.now(timezone.utc) - timedelta(seconds=20)
        delegation_data = json.dumps(
            {
                "delegator": delegation.delegator,
                "delegatee": delegation.delegatee,
                "capabilities": sorted(delegation.capabilities),
                "expires_at": delegation.expires_at.isoformat(),
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        delegation.signature = my_identity.sign(delegation_data)
        peer_card.scope_chain = chain.delegations

        handshake = TrustHandshake(
            my_identity,
            policy=TrustPolicy(max_delegation_expiry_clock_skew_seconds=60),
        )
        result = handshake.verify_peer(peer_card)

        assert result.trusted

    def test_verify_peer_scope_chain_replay_cache_bounded(self):
        """Replay fingerprint map stays bounded under unique chains."""
        my_identity = VerificationIdentity.generate("my-agent")
        handshake = TrustHandshake(
            my_identity,
            policy=TrustPolicy(
                cache_ttl_seconds=0,
                replay_window_seconds=3600,
                max_seen_scope_chain_fingerprints=2,
            ),
        )

        for i in range(3):
            peer_identity = VerificationIdentity.generate(f"peer-agent-{i}", ["required_cap"])
            peer_card = TrustedAgentCard(
                name=f"Peer Agent {i}",
                description="A peer",
                capabilities=["required_cap"],
            )
            peer_card.sign(peer_identity)

            chain = DelegationChain(my_identity)
            chain.add_delegation(
                delegatee=peer_card,
                capabilities=["required_cap"],
                expires_in_hours=24,
            )
            peer_card.scope_chain = chain.delegations

            result = handshake.verify_peer(peer_card)
            assert result.trusted

        assert len(handshake._seen_scope_chains) <= 2

    def test_verify_peer_scope_chain_rate_limited(self):
        """Scope-chain verification enforces per-peer request limits."""
        my_identity = VerificationIdentity.generate("my-agent")
        peer_identity = VerificationIdentity.generate("peer-agent", ["required_cap"])

        peer_card = TrustedAgentCard(
            name="Peer Agent",
            description="A peer",
            capabilities=["required_cap"],
        )
        peer_card.sign(peer_identity)

        chain = DelegationChain(my_identity)
        chain.add_delegation(
            delegatee=peer_card,
            capabilities=["required_cap"],
            expires_in_hours=24,
        )
        peer_card.scope_chain = chain.delegations

        handshake = TrustHandshake(
            my_identity,
            policy=TrustPolicy(
                cache_ttl_seconds=0,
                replay_detection_enabled=False,
                max_scope_chain_attempts_per_window=1,
                scope_chain_rate_limit_window_seconds=60,
            ),
        )

        first = handshake.verify_peer(peer_card)
        second = handshake.verify_peer(peer_card)

        assert first.trusted
        assert not second.trusted
        assert second.reason == "Scope chain verification failed"

    def test_verify_peer_scope_chain_mixed_valid_invalid_delegations(self):
        """Mixed chains fail when any delegation is invalid."""
        my_identity = VerificationIdentity.generate("my-agent")
        mid_identity = VerificationIdentity.generate("mid-agent")
        peer_identity = VerificationIdentity.generate("peer-agent", ["required_cap"])

        mid_card = TrustedAgentCard(
            name="Mid Agent",
            description="Delegation intermediary",
            capabilities=["delegate"],
        )
        mid_card.sign(mid_identity)

        peer_card = TrustedAgentCard(
            name="Peer Agent",
            description="A peer",
            capabilities=["required_cap"],
        )
        peer_card.sign(peer_identity)

        chain = DelegationChain(my_identity)
        chain.add_delegation(
            delegatee=mid_card,
            capabilities=["delegate"],
            expires_in_hours=24,
        )
        chain.add_delegation(
            delegatee=peer_card,
            capabilities=["required_cap"],
            expires_in_hours=24,
            delegator_identity=mid_identity,
        )

        # Corrupt only one delegation in the middle of an otherwise valid chain.
        chain.delegations[1].capabilities.append("tampered")
        peer_card.scope_chain = chain.delegations

        handshake = TrustHandshake(my_identity)
        result = handshake.verify_peer(peer_card)

        assert not result.trusted
        assert result.reason == "Scope chain verification failed"

    def test_verify_peer_scope_chain_overlapping_expirations(self):
        """Overlapping expiration times are accepted when signatures are valid."""
        my_identity = VerificationIdentity.generate("my-agent", ["delegate", "required_cap"])
        mid_identity = VerificationIdentity.generate("mid-agent")
        peer_identity = VerificationIdentity.generate("peer-agent", ["required_cap"])

        mid_card = TrustedAgentCard(
            name="Mid Agent",
            description="Delegation intermediary",
            capabilities=["delegate", "required_cap"],
        )
        mid_card.sign(mid_identity)

        peer_card = TrustedAgentCard(
            name="Peer Agent",
            description="A peer",
            capabilities=["required_cap"],
        )
        peer_card.sign(peer_identity)

        chain = DelegationChain(my_identity)
        d1 = chain.add_delegation(
            delegatee=mid_card,
            capabilities=["delegate", "required_cap"],
            expires_in_hours=24,
        )
        d2 = chain.add_delegation(
            delegatee=peer_card,
            capabilities=["required_cap"],
            expires_in_hours=24,
            delegator_identity=mid_identity,
        )

        # Force overlapping expirations and re-sign both payloads.
        overlap_expiry = datetime.now(timezone.utc) + timedelta(hours=2)
        d1.expires_at = overlap_expiry
        d2.expires_at = overlap_expiry

        d1_payload = json.dumps(
            {
                "delegator": d1.delegator,
                "delegatee": d1.delegatee,
                "capabilities": sorted(d1.capabilities),
                "expires_at": d1.expires_at.isoformat(),
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        d2_payload = json.dumps(
            {
                "delegator": d2.delegator,
                "delegatee": d2.delegatee,
                "capabilities": sorted(d2.capabilities),
                "expires_at": d2.expires_at.isoformat(),
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        d1.signature = my_identity.sign(d1_payload)
        d2.signature = mid_identity.sign(d2_payload)

        peer_card.scope_chain = chain.delegations
        handshake = TrustHandshake(my_identity)
        result = handshake.verify_peer(peer_card)

        assert result.trusted

    def test_verify_peer_scope_chain_thread_safety_smoke(self):
        """Concurrent verification should not raise or corrupt state."""
        my_identity = VerificationIdentity.generate("my-agent")
        peer_identity = VerificationIdentity.generate("peer-agent", ["required_cap"])

        peer_card = TrustedAgentCard(
            name="Peer Agent",
            description="A peer",
            capabilities=["required_cap"],
        )
        peer_card.sign(peer_identity)

        chain = DelegationChain(my_identity)
        chain.add_delegation(
            delegatee=peer_card,
            capabilities=["required_cap"],
            expires_in_hours=24,
        )
        peer_card.scope_chain = chain.delegations

        handshake = TrustHandshake(
            my_identity,
            policy=TrustPolicy(cache_ttl_seconds=0, replay_detection_enabled=False),
        )

        outcomes = []

        def worker() -> None:
            outcomes.append(handshake.verify_peer(peer_card).trusted)

        threads = [Thread(target=worker) for _ in range(20)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert len(outcomes) == 20
        assert all(outcomes)


class TestDelegationChain:
    """Tests for DelegationChain class."""

    def test_add_delegation(self):
        """Test adding a delegation."""
        root = VerificationIdentity.generate("root-agent")
        worker_identity = VerificationIdentity.generate("worker-agent")
        
        worker_card = TrustedAgentCard(
            name="Worker",
            description="Worker agent",
            capabilities=[],
        )
        worker_card.sign(worker_identity)
        
        chain = DelegationChain(root)
        delegation = chain.add_delegation(
            delegatee=worker_card,
            capabilities=["read", "write"],
            expires_in_hours=24,
        )
        
        assert delegation.delegator == root.did
        assert delegation.delegatee == worker_identity.did
        assert "read" in delegation.capabilities

    def test_verify_chain(self):
        """Test chain verification."""
        root = VerificationIdentity.generate("root-agent")
        worker_identity = VerificationIdentity.generate("worker-agent")
        
        worker_card = TrustedAgentCard(
            name="Worker",
            description="Worker agent",
            capabilities=[],
        )
        worker_card.sign(worker_identity)
        
        chain = DelegationChain(root)
        chain.add_delegation(
            delegatee=worker_card,
            capabilities=["read"],
        )
        
        assert chain.verify()


class TestTrustGatedTool:
    """Tests for TrustGatedTool class."""

    def test_can_invoke_with_capability(self):
        """Test capability check for tool invocation."""
        my_identity = VerificationIdentity.generate("executor")
        invoker_identity = VerificationIdentity.generate("invoker", ["database"])
        
        def mock_tool(query: str) -> str:
            return f"Result: {query}"
        
        gated_tool = TrustGatedTool(
            tool=mock_tool,
            required_capabilities=["database"],
        )
        
        invoker_card = TrustedAgentCard(
            name="Invoker",
            description="Has database cap",
            capabilities=["database"],
        )
        invoker_card.sign(invoker_identity)
        
        handshake = TrustHandshake(my_identity)
        result = gated_tool.can_invoke(invoker_card, handshake)
        
        assert result.trusted


class TestTrustCallbackHandler:
    """Tests for TrustCallbackHandler class."""

    def test_event_logging(self):
        """Test that events are logged."""
        identity = VerificationIdentity.generate("callback-agent")
        policy = TrustPolicy(audit_all_calls=True)
        
        handler = TrustCallbackHandler(identity, policy)
        
        # Simulate some events
        from uuid import uuid4
        run_id = uuid4()
        
        handler.on_llm_start(
            {"name": "test-model"},
            ["prompt"],
            run_id=run_id,
        )
        
        events = handler.get_events()
        assert len(events) == 1
        assert events[0].event_type == "llm_start"

    def test_trust_summary(self):
        """Test trust summary generation."""
        identity = VerificationIdentity.generate("summary-agent")
        handler = TrustCallbackHandler(identity)
        
        summary = handler.get_trust_summary()
        
        assert "total_events" in summary
        assert "verified_events" in summary
        assert "verification_rate" in summary


class TestVerificationIdentityTTL:
    """Tests for VerificationIdentity TTL support."""

    def test_generate_without_ttl(self):
        """Identity without TTL never expires."""
        identity = VerificationIdentity.generate("no-ttl-agent")
        assert identity.expires_at is None
        assert not identity.is_expired()

    def test_generate_with_ttl(self):
        """Identity with TTL has expiration set."""
        identity = VerificationIdentity.generate("ttl-agent", ttl_seconds=3600)
        assert identity.expires_at is not None
        assert not identity.is_expired()
        # Should expire roughly 1 hour from now
        delta = identity.expires_at - datetime.now(timezone.utc)
        assert 3500 < delta.total_seconds() < 3700

    def test_expired_identity(self):
        """Manually expired identity reports correctly."""
        identity = VerificationIdentity.generate("expired-agent", ttl_seconds=1)
        # Force expiration
        identity.expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)
        assert identity.is_expired()

    def test_ttl_survives_serialization(self):
        """TTL round-trips through to_dict/from_dict."""
        identity = VerificationIdentity.generate("serial-agent", ttl_seconds=900)
        data = identity.to_dict()
        assert "expires_at" in data

        restored = VerificationIdentity.from_dict(data)
        assert restored.expires_at is not None
        assert not restored.is_expired()

    def test_ttl_in_public_identity(self):
        """Public identity preserves expiration."""
        identity = VerificationIdentity.generate("pub-agent", ttl_seconds=600)
        public = identity.public_identity()
        assert public.expires_at == identity.expires_at
        assert public.private_key is None


class TestUserContext:
    """Tests for UserContext OBO support."""

    def test_create_user_context(self):
        """Test basic user context creation."""
        ctx = UserContext.create(
            user_id="user-123",
            user_email="alice@example.com",
            roles=["admin"],
            permissions=["read:data", "write:reports"],
            ttl_seconds=1800,
        )
        assert ctx.user_id == "user-123"
        assert ctx.is_valid()
        assert ctx.has_role("admin")
        assert ctx.has_permission("read:data")
        assert not ctx.has_permission("delete:data")

    def test_expired_user_context(self):
        """Expired context reports invalid."""
        ctx = UserContext.create(user_id="user-456", ttl_seconds=1)
        ctx.expires_at = datetime.now(timezone.utc) - timedelta(seconds=10)
        assert not ctx.is_valid()

    def test_wildcard_permission(self):
        """Wildcard permission grants everything."""
        ctx = UserContext.create(user_id="admin", permissions=["*"])
        assert ctx.has_permission("anything")

    def test_user_context_serialization(self):
        """UserContext round-trips through to_dict/from_dict."""
        ctx = UserContext.create(
            user_id="user-789",
            user_email="bob@example.com",
            roles=["viewer"],
        )
        data = ctx.to_dict()
        restored = UserContext.from_dict(data)
        assert restored.user_id == "user-789"
        assert restored.user_email == "bob@example.com"
        assert restored.roles == ["viewer"]

    def test_user_context_on_agent_card(self):
        """UserContext propagates through TrustedAgentCard."""
        identity = VerificationIdentity.generate("obo-agent", ["read:data"])
        ctx = UserContext.create(user_id="end-user-1", roles=["analyst"])

        card = TrustedAgentCard(
            name="OBO Agent",
            description="Acting on behalf of user",
            capabilities=["read:data"],
            user_context=ctx,
        )
        card.sign(identity)

        # Verify round-trip
        json_data = card.to_json()
        assert "user_context" in json_data

        restored = TrustedAgentCard.from_json(json_data)
        assert restored.user_context is not None
        assert restored.user_context.user_id == "end-user-1"
        assert restored.user_context.has_role("analyst")


class TestAgentDirectory:
    """Tests for AgentDirectory service discovery."""

    def test_register_and_find(self):
        """Register an agent and find by DID."""
        directory = AgentDirectory()
        identity = VerificationIdentity.generate("discoverable-agent", ["search"])

        card = TrustedAgentCard(
            name="Discoverable",
            description="Can be found",
            capabilities=["search"],
        )
        card.sign(identity)

        assert directory.register(card)
        found = directory.find_by_did(identity.did)
        assert found is not None
        assert found.name == "Discoverable"

    def test_find_by_capability(self):
        """Find agents by capability."""
        directory = AgentDirectory()

        for name, caps in [("agent-a", ["read"]), ("agent-b", ["write"]), ("agent-c", ["read", "write"])]:
            identity = VerificationIdentity.generate(name, caps)
            card = TrustedAgentCard(name=name, description="", capabilities=caps)
            card.sign(identity)
            directory.register(card)

        readers = directory.find_by_capability("read")
        assert len(readers) == 2

        writers = directory.find_by_capability("write")
        assert len(writers) == 2

    def test_list_trusted(self):
        """Filter agents by trust score."""
        directory = AgentDirectory()

        identity = VerificationIdentity.generate("trusted-agent")
        card = TrustedAgentCard(
            name="Trusted",
            description="High trust",
            capabilities=[],
            trust_score=0.9,
        )
        card.sign(identity)
        directory.register(card)

        identity_low = VerificationIdentity.generate("low-trust-agent")
        card_low = TrustedAgentCard(
            name="Low Trust",
            description="Below threshold",
            capabilities=[],
            trust_score=0.3,
        )
        card_low.sign(identity_low)
        directory.register(card_low)

        trusted = directory.list_trusted(min_trust_score=0.7)
        assert len(trusted) == 1
        assert trusted[0].name == "Trusted"

    def test_reject_unsigned_card(self):
        """Unsigned cards are rejected."""
        directory = AgentDirectory()
        card = TrustedAgentCard(
            name="Unsigned",
            description="No signature",
            capabilities=[],
        )
        assert not directory.register(card)
        assert directory.count() == 0

    def test_remove(self):
        """Remove an agent from directory."""
        directory = AgentDirectory()
        identity = VerificationIdentity.generate("removable-agent")
        card = TrustedAgentCard(name="Remove Me", description="", capabilities=[])
        card.sign(identity)
        directory.register(card)

        assert directory.count() == 1
        assert directory.remove(identity.did)
        assert directory.count() == 0
        assert not directory.remove("nonexistent")
