# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for revocation integration with CardRegistry."""

import pytest
from datetime import datetime, timezone

from agentmesh.identity.agent_id import AgentIdentity
from agentmesh.identity.revocation import RevocationList, RevocationEntry
from agentmesh.trust.cards import TrustedAgentCard, CardRegistry


@pytest.fixture
def identity():
    return AgentIdentity.create("test-agent", sponsor="test@example.com")


@pytest.fixture
def signed_card(identity):
    card = TrustedAgentCard.from_identity(identity)
    return card


class TestRevocationList:
    def test_revoke_and_check(self):
        rl = RevocationList()
        rl.revoke("did:agent:bad", reason="compromised")
        assert rl.is_revoked("did:agent:bad") is True
        assert rl.is_revoked("did:agent:good") is False

    def test_unrevoke(self):
        rl = RevocationList()
        rl.revoke("did:agent:temp", reason="testing")
        assert rl.unrevoke("did:agent:temp") is True
        assert rl.is_revoked("did:agent:temp") is False

    def test_temporary_revocation_expires(self):
        rl = RevocationList()
        rl.revoke("did:agent:temp", reason="timeout", ttl_seconds=0)
        # TTL=0 means it expires immediately
        assert rl.is_revoked("did:agent:temp") is False

    def test_list_revoked(self):
        rl = RevocationList()
        rl.revoke("did:agent:a", reason="r1")
        rl.revoke("did:agent:b", reason="r2")
        assert len(rl.list_revoked()) == 2

    def test_cleanup_expired(self):
        rl = RevocationList()
        rl.revoke("did:agent:a", reason="r", ttl_seconds=0)
        removed = rl.cleanup_expired()
        assert removed == 1
        assert len(rl) == 0


class TestCardRegistryRevocation:
    def test_registry_without_revocation(self, signed_card):
        registry = CardRegistry()
        assert registry.register(signed_card) is True
        assert registry.is_verified(signed_card.agent_did) is True

    def test_registry_blocks_revoked_agent(self, signed_card):
        rl = RevocationList()
        rl.revoke(signed_card.agent_did, reason="compromised key")
        registry = CardRegistry(revocation_list=rl)
        registry.register(signed_card)
        assert registry.is_verified(signed_card.agent_did) is False

    def test_registry_allows_after_unrevoke(self, signed_card):
        rl = RevocationList()
        rl.revoke(signed_card.agent_did, reason="temporary")
        registry = CardRegistry(revocation_list=rl)
        registry.register(signed_card)
        assert registry.is_verified(signed_card.agent_did) is False
        rl.unrevoke(signed_card.agent_did)
        assert registry.is_verified(signed_card.agent_did) is True

    def test_setting_revocation_list_clears_cache(self, signed_card):
        registry = CardRegistry()
        registry.register(signed_card)
        assert registry.is_verified(signed_card.agent_did) is True
        rl = RevocationList()
        rl.revoke(signed_card.agent_did, reason="late revoke")
        registry.revocation_list = rl
        assert registry.is_verified(signed_card.agent_did) is False

    def test_revocation_list_property(self):
        rl = RevocationList()
        registry = CardRegistry(revocation_list=rl)
        assert registry.revocation_list is rl


class TestKeyRotationManager:
    def test_rotate_preserves_did(self):
        from agentmesh.identity.rotation import KeyRotationManager

        identity = AgentIdentity.create("rotate-agent", sponsor="test@example.com")
        original_did = str(identity.did)
        mgr = KeyRotationManager(identity, rotation_ttl_seconds=0)
        mgr.rotate()
        assert str(identity.did) == original_did

    def test_rotate_changes_public_key(self):
        from agentmesh.identity.rotation import KeyRotationManager

        identity = AgentIdentity.create("rotate-agent", sponsor="test@example.com")
        original_key = identity.public_key
        mgr = KeyRotationManager(identity, rotation_ttl_seconds=0)
        mgr.rotate()
        assert identity.public_key != original_key

    def test_key_history_tracked(self):
        from agentmesh.identity.rotation import KeyRotationManager

        identity = AgentIdentity.create("rotate-agent", sponsor="test@example.com")
        mgr = KeyRotationManager(identity, rotation_ttl_seconds=0)
        mgr.rotate()
        mgr.rotate()
        history = mgr.get_key_history()
        assert len(history) == 2

    def test_rotation_proof_valid(self):
        from agentmesh.identity.rotation import KeyRotationManager

        identity = AgentIdentity.create("rotate-agent", sponsor="test@example.com")
        old_key = identity.public_key
        mgr = KeyRotationManager(identity, rotation_ttl_seconds=0)
        mgr.rotate()
        new_key = identity.public_key
        proof = mgr.get_rotation_proof()
        assert KeyRotationManager.verify_rotation(old_key, new_key, proof) is True

    def test_needs_rotation_respects_ttl(self):
        from agentmesh.identity.rotation import KeyRotationManager

        identity = AgentIdentity.create("rotate-agent", sponsor="test@example.com")
        mgr = KeyRotationManager(identity, rotation_ttl_seconds=86400)
        assert mgr.needs_rotation() is False

    def test_max_history_trimmed(self):
        from agentmesh.identity.rotation import KeyRotationManager

        identity = AgentIdentity.create("rotate-agent", sponsor="test@example.com")
        mgr = KeyRotationManager(identity, rotation_ttl_seconds=0, max_history=2)
        for _ in range(5):
            mgr.rotate()
        assert len(mgr.get_key_history()) == 2
