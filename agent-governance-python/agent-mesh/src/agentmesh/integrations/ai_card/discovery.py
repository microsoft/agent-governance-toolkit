# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
AI Card Discovery

Handles serving AI Cards at ``/.well-known/ai-card.json`` and
managing a local catalog of cards for discovery.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from .schema import AICard

logger = logging.getLogger(__name__)


class AICardDiscovery:
    """Manages AI Card discovery and catalog.

    Provides:
    - Local card catalog for registered agents
    - JSON responses for ``/.well-known/ai-card.json``
    - Card lookup by DID, name, or capability
    - TTL-based verification caching

    Example:
        >>> discovery = AICardDiscovery()
        >>> discovery.register(card)
        >>> # Serve at /.well-known/ai-card.json
        >>> json_response = discovery.get_card_json("did:mesh:abc123")
    """

    def __init__(self, cache_ttl_seconds: int = 900):
        self._cards: Dict[str, AICard] = {}  # keyed by DID
        self._verified_cache: Dict[str, tuple[bool, datetime]] = {}
        self._cache_ttl = timedelta(seconds=cache_ttl_seconds)

    def register(self, card: AICard, verify: bool = True) -> bool:
        """Register an AI Card in the catalog.

        Args:
            card: The AI Card to register.
            verify: Whether to verify the card signature before registering.

        Returns:
            True if registered successfully.
        """
        if not card.identity:
            logger.warning("Cannot register card without identity")
            return False

        if verify and not card.verify_signature():
            logger.warning(f"Card signature verification failed for {card.identity.did}")
            return False

        self._cards[card.identity.did] = card
        self._verified_cache[card.identity.did] = (True, datetime.now(timezone.utc))
        logger.info(f"Registered AI Card for {card.identity.did}")
        return True

    def get(self, did: str) -> Optional[AICard]:
        """Get a card by agent DID."""
        return self._cards.get(did)

    def get_card_json(self, did: str) -> Optional[str]:
        """Get AI Card JSON for serving at ``/.well-known/ai-card.json``.

        Args:
            did: Agent DID to look up.

        Returns:
            JSON string or None if not found.
        """
        card = self._cards.get(did)
        return card.to_json() if card else None

    def get_catalog_json(self, indent: int = 2) -> str:
        """Get the full catalog as JSON.

        Returns:
            JSON string with all registered cards.
        """
        catalog = {
            "cards": [
                json.loads(card.to_json()) for card in self._cards.values()
            ],
            "total": len(self._cards),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
        return json.dumps(catalog, indent=indent)

    def is_verified(self, did: str) -> bool:
        """Check if a card is verified (with caching)."""
        if did in self._verified_cache:
            verified, timestamp = self._verified_cache[did]
            if datetime.now(timezone.utc) - timestamp < self._cache_ttl:
                return verified

        card = self._cards.get(did)
        if not card:
            return False

        verified = card.verify_signature()
        self._verified_cache[did] = (verified, datetime.now(timezone.utc))
        return verified

    def find_by_capability(self, capability: str) -> List[AICard]:
        """Find cards that have a specific capability attestation."""
        return [
            card for card in self._cards.values()
            if capability in card.verifiable.capability_attestations
        ]

    def find_by_protocol(self, protocol: str) -> List[AICard]:
        """Find cards that support a specific protocol."""
        return [
            card for card in self._cards.values()
            if any(s.protocol == protocol for s in card.services)
        ]

    def list_cards(self) -> List[AICard]:
        """List all registered cards."""
        return list(self._cards.values())

    def remove(self, did: str) -> bool:
        """Remove a card from the catalog."""
        if did in self._cards:
            del self._cards[did]
            self._verified_cache.pop(did, None)
            return True
        return False

    def clear_cache(self) -> None:
        """Clear the verification cache."""
        self._verified_cache.clear()
