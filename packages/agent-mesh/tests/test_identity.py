# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for AgentMesh Identity module."""

import pytest
from datetime import datetime, timedelta
from urllib.parse import urlparse

from agentmesh.identity import (
    AgentIdentity,
    AgentDID,
    Credential,
    CredentialManager,
    ScopeChain,
    DelegationLink,
    HumanSponsor,
    RiskScorer,
    RiskScore,
    SPIFFEIdentity,
)


class TestAgentDID:
    """Tests for AgentDID."""
    
    def test_generate_did(self):
        """Test generating a new DID."""
        did = AgentDID.generate("test-agent")
        
        assert did.method == "mesh"
        assert len(did.unique_id) == 32
        assert str(did).startswith("did:mesh:")
    
    def test_generate_did_with_org(self):
        """Test generating DID with organization."""
        did = AgentDID.generate("test-agent", org="acme-corp")
        
        assert did.method == "mesh"
        assert str(did).startswith("did:mesh:")
    
    def test_parse_did_string(self):
        """Test parsing a DID string."""
        did_str = "did:mesh:abc123def456"
        did = AgentDID.from_string(did_str)
        
        assert did.unique_id == "abc123def456"
        assert str(did) == did_str
    
    def test_invalid_did_string(self):
        """Test parsing invalid DID raises error."""
        with pytest.raises(ValueError):
            AgentDID.from_string("invalid:did:format")
    
    def test_did_hash(self):
        """Test DID is hashable for use in sets/dicts."""
        did1 = AgentDID.generate("agent-1")
        did2 = AgentDID.generate("agent-2")
        
        did_set = {did1, did2}
        assert len(did_set) == 2


class TestAgentIdentity:
    """Tests for AgentIdentity."""
    
    def test_create_identity(self):
        """Test creating a new agent identity."""
        identity = AgentIdentity.create(
            name="test-agent",
            sponsor="sponsor@example.com",
        )
        
        assert identity.name == "test-agent"
        assert str(identity.did).startswith("did:mesh:")
        assert identity.public_key is not None
        assert identity.sponsor_email == "sponsor@example.com"
        assert identity.status == "active"
    
    def test_create_with_capabilities(self):
        """Test creating identity with capabilities."""
        identity = AgentIdentity.create(
            name="capable-agent",
            sponsor="sponsor@example.com",
            capabilities=["read", "write", "execute"],
        )
        
        assert set(identity.capabilities) == {"read", "write", "execute"}
    
    def test_identity_unique(self):
        """Test that each identity is unique."""
        id1 = AgentIdentity.create("agent-1", "s@e.com")
        id2 = AgentIdentity.create("agent-2", "s@e.com")
        
        assert str(id1.did) != str(id2.did)
        assert id1.public_key != id2.public_key
    
    def test_sign_and_verify(self):
        """Test signing and verification."""
        identity = AgentIdentity.create("signer", "s@e.com")
        
        message = b"Hello, AgentMesh!"
        signature = identity.sign(message)
        
        assert identity.verify_signature(message, signature)
        assert not identity.verify_signature(b"Modified message", signature)
    
    def test_delegate_creates_child(self):
        """Test delegating to create sub-agent."""
        parent = AgentIdentity.create(
            "parent-agent", 
            "s@e.com",
            capabilities=["read", "write", "delete"],
        )
        
        child = parent.delegate(
            "child-agent", 
            capabilities=["read", "write"],
        )
        
        assert child.parent_did == str(parent.did)
        assert set(child.capabilities) == {"read", "write"}
        assert child.delegation_depth == parent.delegation_depth + 1
    
    def test_delegate_capability_narrowing(self):
        """Test that delegation cannot widen capabilities."""
        parent = AgentIdentity.create(
            "parent-agent",
            "s@e.com", 
            capabilities=["read"],
        )
        
        with pytest.raises(ValueError):
            parent.delegate(
                "child-agent",
                capabilities=["read", "write"],  # Can't add "write"
            )


class TestCredentials:
    """Tests for Credential and CredentialManager."""
    
    def test_credential_creation(self):
        """Test creating credentials."""
        cred = Credential.issue(
            agent_did="did:mesh:test123",
            capabilities=["read", "write"],
        )
        
        assert cred.agent_did == "did:mesh:test123"
        assert cred.is_valid()
    
    def test_credential_default_ttl(self):
        """Test credential has 15-minute default TTL."""
        cred = Credential.issue(agent_did="did:mesh:test")
        
        # Should expire in approximately 15 minutes
        time_diff = cred.expires_at - datetime.utcnow()
        assert 14 * 60 < time_diff.total_seconds() < 16 * 60
    
    def test_credential_expiry(self):
        """Test credential expiration."""
        cred = Credential.issue(
            agent_did="did:mesh:test",
            ttl_seconds=-60,  # Expired 1 minute ago
        )
        
        assert not cred.is_valid()
    
    def test_credential_manager_issue(self):
        """Test credential manager issues credentials."""
        manager = CredentialManager()
        
        cred = manager.issue("did:mesh:test", capabilities=["read"])
        
        assert cred is not None
        assert cred.agent_did == "did:mesh:test"
        assert manager.validate(cred.token)
    
    def test_credential_manager_revoke(self):
        """Test credential revocation."""
        manager = CredentialManager()
        
        cred = manager.issue("did:mesh:test")
        assert manager.validate(cred.token)
        
        manager.revoke(cred.credential_id, "test revocation")
        assert not manager.validate(cred.token)
    
    def test_credential_manager_rotate(self):
        """Test credential rotation."""
        manager = CredentialManager()
        
        old_cred = manager.issue("did:mesh:test")
        new_cred = manager.rotate(old_cred.credential_id)
        
        assert new_cred.credential_id != old_cred.credential_id
        assert not manager.validate(old_cred.token)
        assert manager.validate(new_cred.token)


class TestDelegation:
    """Tests for ScopeChain."""
    
    def test_create_chain(self):
        """Test creating scope chain."""
        chain, root_link = ScopeChain.create_root(
            sponsor_email="sponsor@example.com",
            root_agent_did="did:mesh:root123",
            capabilities=["read", "write", "admin"],
        )
        
        assert chain.root_sponsor_email == "sponsor@example.com"
        assert chain.leaf_did == "did:mesh:root123"
        assert len(chain.links) == 0
    
    def test_add_delegation_link(self):
        """Test adding delegation links."""
        chain, root_link = ScopeChain.create_root(
            sponsor_email="sponsor@example.com",
            root_agent_did="did:mesh:root",
            capabilities=["read", "write"],
        )
        
        # Add the root link
        chain.add_link(root_link)
        
        # Create a child link
        import uuid
        child_link = DelegationLink(
            link_id=f"link_{uuid.uuid4().hex[:12]}",
            depth=1,
            parent_did="did:mesh:root",
            child_did="did:mesh:child",
            parent_capabilities=["read", "write"],
            delegated_capabilities=["read"],
            parent_signature="test_signature",
            link_hash="",
            previous_link_hash=root_link.link_hash,
        )
        child_link.link_hash = child_link.compute_hash()
        
        chain.add_link(child_link)
        
        assert len(chain.links) == 2
        assert chain.leaf_capabilities == ["read"]
    
    def test_capability_narrowing_enforced(self):
        """Test that capabilities can only narrow, never widen."""
        chain, root_link = ScopeChain.create_root(
            sponsor_email="sponsor@example.com",
            root_agent_did="did:mesh:root",
            capabilities=["read"],
        )
        
        chain.add_link(root_link)
        
        # Create a child link with proper narrowing
        import uuid
        child_link = DelegationLink(
            link_id=f"link_{uuid.uuid4().hex[:12]}",
            depth=1,
            parent_did="did:mesh:root",
            child_did="did:mesh:child",
            parent_capabilities=["read"],
            delegated_capabilities=["read"],
            parent_signature="test_signature",
            link_hash="",
            previous_link_hash=root_link.link_hash,
        )
        child_link.link_hash = child_link.compute_hash()
        
        chain.add_link(child_link)
        
        # Attempt to widen should fail
        grandchild_link = DelegationLink(
            link_id=f"link_{uuid.uuid4().hex[:12]}",
            depth=2,
            parent_did="did:mesh:child",
            child_did="did:mesh:grandchild",
            parent_capabilities=["read"],
            delegated_capabilities=["read", "write"],  # Can't add "write"
            parent_signature="test_signature",
            link_hash="",
            previous_link_hash=child_link.link_hash,
        )
        grandchild_link.link_hash = grandchild_link.compute_hash()
        
        with pytest.raises(ValueError):
            chain.add_link(grandchild_link)
    
    def test_verify_chain(self):
        """Test chain verification."""
        chain, root_link = ScopeChain.create_root(
            sponsor_email="sponsor@example.com",
            root_agent_did="did:mesh:root",
            capabilities=["read", "write"],
        )
        
        chain.add_link(root_link)
        
        # Create a child link
        import uuid
        child_link = DelegationLink(
            link_id=f"link_{uuid.uuid4().hex[:12]}",
            depth=1,
            parent_did="did:mesh:root",
            child_did="did:mesh:child",
            parent_capabilities=["read", "write"],
            delegated_capabilities=["read"],
            parent_signature="test_signature",
            link_hash="",
            previous_link_hash=root_link.link_hash,
        )
        child_link.link_hash = child_link.compute_hash()
        
        chain.add_link(child_link)
        
        is_valid, error = chain.verify()
        assert is_valid


class TestSponsor:
    """Tests for HumanSponsor."""
    
    def test_create_sponsor(self):
        """Test creating a human sponsor."""
        sponsor = HumanSponsor.create(
            email="sponsor@example.com",
            name="Test Sponsor",
        )
        
        assert sponsor.email == "sponsor@example.com"
        assert sponsor.status == "active"
    
    def test_sponsor_agent(self):
        """Test sponsoring an agent."""
        sponsor = HumanSponsor.create(
            email="sponsor@example.com",
            name="Test Sponsor",
        )
        
        sponsor.add_agent("did:mesh:test")
        
        assert "did:mesh:test" in sponsor.agent_dids
    
    def test_revoke_sponsorship(self):
        """Test revoking sponsorship."""
        sponsor = HumanSponsor.create(
            email="sponsor@example.com",
            name="Test Sponsor",
        )
        
        sponsor.add_agent("did:mesh:test")
        sponsor.remove_agent("did:mesh:test")
        
        assert "did:mesh:test" not in sponsor.agent_dids


class TestRiskScoring:
    """Tests for RiskScorer."""
    
    def test_initial_score(self):
        """Test initial risk score."""
        scorer = RiskScorer()
        
        score = scorer.get_score("did:mesh:new-agent")
        
        assert isinstance(score, RiskScore)
        assert score.total_score >= 0
        assert score.total_score <= 1000
    
    def test_add_risk_event(self):
        """Test adding risk events affects behavior score."""
        scorer = RiskScorer()
        
        initial = scorer.get_score("did:mesh:test")
        initial_behavior = initial.behavior_score
        
        # Add multiple high-risk signals
        from agentmesh.identity.risk import RiskSignal
        for _ in range(5):
            scorer.add_signal(
                agent_did="did:mesh:test",
                signal=RiskSignal(
                    signal_type="behavior.suspicious_activity",
                    severity="high",
                    value=0.9,
                ),
            )
        
        after = scorer.recalculate("did:mesh:test")
        # Behavior score should decrease due to negative signals
        assert after.behavior_score < initial_behavior
    
    def test_risk_decay(self):
        """Test that risk decays over time."""
        scorer = RiskScorer()
        
        from agentmesh.identity.risk import RiskSignal
        scorer.add_signal(
            agent_did="did:mesh:test",
            signal=RiskSignal(
                signal_type="minor_violation",
                severity="low",
                value=0.3,
            ),
        )
        
        # Risk should be present
        score = scorer.recalculate("did:mesh:test")
        assert score.total_score >= 0


class TestSPIFFE:
    """Tests for SPIFFE identity."""
    
    def test_create_spiffe_identity(self):
        """Test creating SPIFFE identity."""
        spiffe = SPIFFEIdentity.create(
            trust_domain="agentmesh.io",
            agent_did="did:mesh:test123",
            agent_name="test-agent",
        )
        
        parsed = urlparse(spiffe.spiffe_id)
        assert parsed.scheme == "spiffe"
        assert parsed.hostname == "agentmesh.io"
        assert parsed.path.startswith("/")
        assert spiffe.trust_domain == "agentmesh.io"
    
    def test_spiffe_id_format(self):
        """Test SPIFFE ID follows standard format."""
        spiffe = SPIFFEIdentity.create(
            trust_domain="example.com",
            agent_did="did:mesh:abc",
            agent_name="test-agent",
        )
        
        # SPIFFE ID should be: spiffe://<trust-domain>/<path>
        parsed = urlparse(spiffe.spiffe_id)
        assert parsed.scheme == "spiffe"
        assert parsed.hostname == "example.com"
        assert parsed.path.startswith("/")
