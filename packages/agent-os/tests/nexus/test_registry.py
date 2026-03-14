# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for Nexus Registry
"""

import pytest
from datetime import datetime

from nexus.registry import AgentRegistry, RegistrationResult, PeerVerification
from nexus.schemas.manifest import AgentManifest, AgentIdentity, AgentCapabilities, AgentPrivacy
from nexus.exceptions import (
    AgentAlreadyRegisteredError,
    AgentNotFoundError,
    IATPUnverifiedPeerException,
    IATPInsufficientTrustException,
)


def create_test_manifest(agent_id: str = "test-agent") -> AgentManifest:
    """Create a test manifest."""
    return AgentManifest(
        identity=AgentIdentity(
            did=f"did:nexus:{agent_id}",
            verification_key="ed25519:test_key_123",
            owner_id="test-org",
            display_name=f"Test Agent {agent_id}",
        ),
        capabilities=AgentCapabilities(
            domains=["data-analysis", "code-generation"],
            reversibility="full",
        ),
        privacy=AgentPrivacy(
            retention_policy="ephemeral",
            pii_handling="reject",
        ),
    )


class TestAgentRegistry:
    """Tests for AgentRegistry."""
    
    @pytest.mark.asyncio
    async def test_register_agent(self):
        """Test agent registration."""
        registry = AgentRegistry()
        manifest = create_test_manifest()
        
        result = await registry.register(manifest, "test_signature")
        
        assert result.success is True
        assert result.agent_did == "did:nexus:test-agent"
        assert result.trust_score > 0
    
    @pytest.mark.asyncio
    async def test_register_duplicate(self):
        """Test duplicate registration fails."""
        registry = AgentRegistry()
        manifest = create_test_manifest()
        
        await registry.register(manifest, "sig")
        
        with pytest.raises(AgentAlreadyRegisteredError):
            await registry.register(manifest, "sig")
    
    @pytest.mark.asyncio
    async def test_get_manifest(self):
        """Test getting agent manifest."""
        registry = AgentRegistry()
        manifest = create_test_manifest()
        
        await registry.register(manifest, "sig")
        
        retrieved = await registry.get_manifest("did:nexus:test-agent")
        assert retrieved.identity.did == "did:nexus:test-agent"
    
    @pytest.mark.asyncio
    async def test_get_nonexistent_manifest(self):
        """Test getting nonexistent agent fails."""
        registry = AgentRegistry()
        
        with pytest.raises(AgentNotFoundError):
            await registry.get_manifest("did:nexus:nonexistent")
    
    @pytest.mark.asyncio
    async def test_verify_peer_success(self):
        """Test successful peer verification."""
        registry = AgentRegistry()
        manifest = create_test_manifest()
        
        # Register with good reputation
        result = await registry.register(manifest, "sig")
        
        # Build up reputation to meet threshold
        for _ in range(50):
            registry.reputation_engine.record_task_outcome(
                "did:nexus:test-agent", "success"
            )
        
        verification = await registry.verify_peer(
            "did:nexus:test-agent",
            min_score=400,  # Lower threshold for test
        )
        
        assert verification.verified is True
        assert verification.trust_score > 0
    
    @pytest.mark.asyncio
    async def test_verify_unregistered_peer(self):
        """Test verifying unregistered peer raises exception."""
        registry = AgentRegistry()
        
        with pytest.raises(IATPUnverifiedPeerException) as exc:
            await registry.verify_peer("did:nexus:unknown")
        
        assert "unknown" in str(exc.value)
        assert exc.value.registration_url.startswith("https://nexus.agent-os.dev/register")
    
    @pytest.mark.asyncio
    async def test_verify_low_trust_peer(self):
        """Test verifying peer with low trust score."""
        registry = AgentRegistry()
        manifest = create_test_manifest()
        
        await registry.register(manifest, "sig")
        
        # Slash reputation heavily
        for _ in range(5):
            registry.reputation_engine.slash_reputation(
                "did:nexus:test-agent",
                reason="hallucination",
                severity="critical",
            )
        
        with pytest.raises(IATPInsufficientTrustException) as exc:
            await registry.verify_peer("did:nexus:test-agent", min_score=700)
        
        assert exc.value.score_gap > 0
    
    @pytest.mark.asyncio
    async def test_discover_agents(self):
        """Test agent discovery."""
        registry = AgentRegistry()
        
        # Register multiple agents
        for i in range(5):
            manifest = create_test_manifest(f"agent-{i}")
            await registry.register(manifest, f"sig-{i}")
        
        # Discover all
        agents = await registry.discover_agents(min_score=0)
        assert len(agents) == 5
    
    @pytest.mark.asyncio
    async def test_discover_by_capability(self):
        """Test discovery filtering by capability."""
        registry = AgentRegistry()
        
        # Register agent with specific capability
        manifest = create_test_manifest("special")
        manifest.capabilities.domains = ["special-capability"]
        await registry.register(manifest, "sig")
        
        # Discover with filter
        agents = await registry.discover_agents(
            capabilities=["special-capability"],
            min_score=0,
        )
        
        assert len(agents) == 1
        assert agents[0].identity.did == "did:nexus:special"
    
    @pytest.mark.asyncio
    async def test_deregister_agent(self):
        """Test agent deregistration."""
        registry = AgentRegistry()
        manifest = create_test_manifest()
        
        await registry.register(manifest, "sig")
        assert registry.is_registered("did:nexus:test-agent")
        
        await registry.deregister("did:nexus:test-agent", "sig")
        assert not registry.is_registered("did:nexus:test-agent")


class TestIATPExceptions:
    """Tests for IATP exceptions (the viral mechanism)."""
    
    def test_unverified_peer_exception_format(self):
        """Test the viral error message format."""
        exc = IATPUnverifiedPeerException("unknown-agent")
        
        assert "unknown-agent" in str(exc)
        assert exc.registration_url.startswith("https://nexus.agent-os.dev/register")
        assert exc.code == "IATP_UNVERIFIED_PEER"
    
    def test_unverified_peer_iatp_error(self):
        """Test conversion to IATP error format."""
        exc = IATPUnverifiedPeerException("unknown-agent")
        error = exc.to_iatp_error()
        
        assert error["error"] == "IATP_UNVERIFIED_PEER"
        assert "registration_url" in error
        assert "action_required" in error
    
    def test_insufficient_trust_exception(self):
        """Test insufficient trust exception."""
        exc = IATPInsufficientTrustException(
            peer_did="did:nexus:low-trust",
            current_score=400,
            required_score=700,
        )
        
        assert exc.score_gap == 300
        assert exc.code == "IATP_INSUFFICIENT_TRUST"
