# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for cache invalidation on TrustedAgentCard mutation.

``CardRegistry.is_verified`` previously returned a cached ``True`` for
the full TTL after a successful ``register()`` call, even if the card
was mutated in place afterwards. These tests pin the new behaviour:
the verification verdict is bound to the card's signed content via a
content hash, so any mutation invalidates the cache on the next read.
"""

import pytest

from agentmesh.identity.agent_id import AgentIdentity
from agentmesh.trust.cards import TrustedAgentCard, CardRegistry


@pytest.fixture
def identity():
    return AgentIdentity.create("alice", sponsor="alice@example.com")


@pytest.fixture
def signed_card(identity):
    return TrustedAgentCard.from_identity(identity)


class TestCacheInvalidation:
    def test_register_caches_only_for_matching_content(self, signed_card):
        registry = CardRegistry()
        assert registry.register(signed_card) is True
        # First read hits cache and matches stored hash
        assert registry.is_verified(signed_card.agent_did) is True

    def test_mutating_capabilities_invalidates_cache(self, signed_card):
        """A tampered card whose capabilities list grows after
        registration must NOT remain ``is_verified == True``."""
        registry = CardRegistry()
        assert registry.register(signed_card) is True
        # Cached as True
        assert registry.is_verified(signed_card.agent_did) is True

        # Mutate the registered card in place
        signed_card.capabilities.append("admin:everything")

        # is_verified must re-check and find the signature no longer
        # matches the mutated content
        assert registry.is_verified(signed_card.agent_did) is False

    def test_mutating_trust_score_invalidates_cache(self, signed_card):
        registry = CardRegistry()
        registry.register(signed_card)
        assert registry.is_verified(signed_card.agent_did) is True

        signed_card.trust_score = 0.01  # different signed field
        assert registry.is_verified(signed_card.agent_did) is False

    def test_tampered_signature_invalidates_cache(self, signed_card):
        registry = CardRegistry()
        registry.register(signed_card)
        assert registry.is_verified(signed_card.agent_did) is True

        # Ensure the replacement byte actually differs from the original
        original = signed_card.card_signature
        first_char = original[0]
        replacement = "B" if first_char != "B" else "C"
        signed_card.card_signature = replacement + original[1:]
        assert registry.is_verified(signed_card.agent_did) is False

    def test_unmutated_card_stays_cached(self, signed_card):
        """Sanity: an unchanged card keeps using the cache."""
        registry = CardRegistry()
        registry.register(signed_card)
        # Multiple reads stay True
        for _ in range(5):
            assert registry.is_verified(signed_card.agent_did) is True
