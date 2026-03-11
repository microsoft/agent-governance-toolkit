"""Tests for AgentMesh LangChain integration."""

import pytest
from datetime import datetime, timedelta, timezone
from langchain_agentmesh import (
    VerificationIdentity,
    VerificationSignature,
    TrustedAgentCard,
    TrustHandshake,
    TrustPolicy,
    TrustGatedTool,
    TrustedToolExecutor,
    TrustCallbackHandler,
    DelegationChain,
    UserContext,
    AgentDirectory,
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
