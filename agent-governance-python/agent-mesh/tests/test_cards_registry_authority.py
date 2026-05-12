# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for authoritative-registry verification on TrustedAgentCard.

These tests pin the verification-authority precedence documented on
``TrustedAgentCard.verify_signature``:

1. Explicit ``identity`` is authoritative.
2. ``identity_registry`` is consulted by ``agent_did``; the embedded
   key must NOT be used as a fallback when the registry is provided.
3. Bare verification with neither argument is self-attesting only.
"""

import pytest

from agentmesh.identity.agent_id import AgentIdentity, IdentityRegistry
from agentmesh.trust.cards import TrustedAgentCard, CardRegistry


@pytest.fixture
def authoritative_identity():
    return AgentIdentity.create("alice", sponsor="alice@example.com")


@pytest.fixture
def authoritative_card(authoritative_identity):
    return TrustedAgentCard.from_identity(authoritative_identity)


class TestRegistryLookupPrecedence:
    def test_card_verified_against_registered_identity(
        self, authoritative_identity, authoritative_card
    ):
        registry = IdentityRegistry()
        registry.register(authoritative_identity)
        assert (
            authoritative_card.verify_signature(identity_registry=registry)
            is True
        )

    def test_unregistered_did_fails_when_registry_supplied(
        self, authoritative_card
    ):
        """The embedded public key must NOT be a fallback when a
        registry is provided -- if the DID is not registered,
        verification fails."""
        empty_registry = IdentityRegistry()
        assert (
            authoritative_card.verify_signature(
                identity_registry=empty_registry
            )
            is False
        )

    def test_tampered_card_with_self_signed_key_fails_registry_check(
        self, authoritative_identity
    ):
        """An attacker mints a card claiming alice's DID but signs it
        with their own key. Registry lookup rejects it because the
        registry holds alice's real public key."""
        attacker = AgentIdentity.create(
            "attacker", sponsor="evil@example.com"
        )
        registry = IdentityRegistry()
        registry.register(authoritative_identity)

        forged = TrustedAgentCard(
            name="alice",
            description="impersonator",
            capabilities=["read:everything"],
        )
        # Sign with attacker's key but claim alice's DID
        forged.sign(attacker)
        forged.agent_did = str(authoritative_identity.did)
        # Re-sign so the card is internally consistent with the new DID
        forged.card_signature = attacker.sign(
            forged._get_signable_content().encode()
        )
        forged.public_key = attacker.public_key

        # Self-attestation path: passes (the card is internally
        # consistent with the attacker's embedded key).
        assert forged.verify_signature() is True
        # Registry path: fails because alice's authoritative key does
        # not match the attacker's signature.
        assert (
            forged.verify_signature(identity_registry=registry) is False
        )

    def test_explicit_identity_overrides_registry(
        self, authoritative_identity, authoritative_card
    ):
        empty_registry = IdentityRegistry()
        # Even though registry doesn't know this DID, the explicit
        # identity argument is authoritative.
        assert (
            authoritative_card.verify_signature(
                identity=authoritative_identity,
                identity_registry=empty_registry,
            )
            is True
        )


class TestCardRegistryUsesIdentityRegistry:
    def test_register_uses_identity_registry_when_supplied(
        self, authoritative_identity, authoritative_card
    ):
        id_registry = IdentityRegistry()
        id_registry.register(authoritative_identity)
        card_registry = CardRegistry(identity_registry=id_registry)
        assert card_registry.register(authoritative_card) is True

    def test_register_rejects_unregistered_did(self, authoritative_card):
        """If a CardRegistry is configured with an identity registry,
        cards whose DIDs are not registered fail to register."""
        id_registry = IdentityRegistry()
        card_registry = CardRegistry(identity_registry=id_registry)
        assert card_registry.register(authoritative_card) is False

    def test_register_without_identity_registry_falls_back_to_self_attestation(
        self, authoritative_card
    ):
        """Backward-compatible path: when no identity registry is
        configured, the embedded key is honoured (self-attestation)."""
        card_registry = CardRegistry()
        assert card_registry.register(authoritative_card) is True
