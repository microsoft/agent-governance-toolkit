# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""IdentityProviderChain — ordered resolution across identity backends.

Implements the provider-chain architecture described in ADR-0007:

    TrustHandshake.verify_peer()
            │
    IdentityProviderChain
    ┌───────┼───────────────────┐
    │       │                   │
    LocalRegistry  EntraBridge   ExternalJWKS

Each provider returns an ``IdentityResult`` on success or ``None`` on
miss. The chain tries providers in registration order and returns the
first hit. This keeps resolution logic out of ``TrustHandshake`` and
lets operators compose backends without modifying the handshake code.
"""

from __future__ import annotations

import contextvars
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Task-local token storage for ExternalJWKSProviderAdapter.
# Each asyncio Task gets its own isolated copy so concurrent callers
# cannot overwrite each other's tokens (fixes the _pending_token race).
_jwks_pending_token: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "_jwks_pending_token", default=None
)


@dataclass
class IdentityResult:
    """Unified result from any identity provider.

    Fields map to what ``TrustHandshake._verify_response`` needs:
    peer DID, public key, trust score, capabilities, and an optional
    external identity record for cross-org agents.
    """

    peer_did: str
    public_key: str
    trust_score: int = 0
    capabilities: list[str] = field(default_factory=list)
    is_active: bool = True
    provider_name: str = ""
    external_identity: Any = None  # Optional[ExternalIdentity]
    metadata: dict[str, Any] = field(default_factory=dict)


class IdentityProvider(ABC):
    """Abstract identity provider interface.

    Subclasses resolve a peer DID string to an ``IdentityResult``.
    Returning ``None`` signals "not my domain — pass to the next
    provider in the chain."
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable provider name for logging and diagnostics."""

    @abstractmethod
    async def resolve(self, peer_did: str) -> Optional[IdentityResult]:
        """Try to resolve *peer_did* to an identity.

        Returns ``IdentityResult`` on success, ``None`` if this
        provider cannot handle the DID.
        """


class LocalRegistryProvider(IdentityProvider):
    """Provider backed by the in-process ``IdentityRegistry``.

    Handles ``did:mesh:`` DIDs — the default path for agents in the
    same governance domain.
    """

    def __init__(self, registry: Any) -> None:  # IdentityRegistry
        self._registry = registry

    @property
    def name(self) -> str:
        return "local-registry"

    async def resolve(self, peer_did: str) -> Optional[IdentityResult]:
        if not peer_did.startswith("did:mesh:"):
            return None

        identity = self._registry.get(peer_did)
        if identity is None:
            return None

        return IdentityResult(
            peer_did=peer_did,
            public_key=identity.public_key,
            trust_score=getattr(identity, "trust_score", 0),
            capabilities=list(identity.capabilities),
            is_active=identity.is_active(),
            provider_name=self.name,
        )


class ExternalJWKSProviderAdapter(IdentityProvider):
    """Adapter wrapping ``ExternalJWKSProvider`` for chain integration.

    Handles ``did:web:`` DIDs and JWTs with external issuers by
    delegating to the existing ``ExternalJWKSProvider.verify()`` flow.

    Because ``ExternalJWKSProvider.verify()`` takes a *token* (not a
    DID), this adapter expects the token to be stashed via
    ``set_pending_token()`` before ``resolve()`` is called.

    Thread safety: token stashing uses ``contextvars.ContextVar`` so
    each asyncio Task sees only its own token. Concurrent callers on
    different Tasks cannot overwrite each other's tokens.
    """

    def __init__(self, provider: Any) -> None:  # ExternalJWKSProvider
        self._provider = provider

    @property
    def name(self) -> str:
        return "external-jwks"

    def set_pending_token(self, token: str) -> None:
        """Stash a token for the next resolve call (task-local via ContextVar)."""
        _jwks_pending_token.set(token)

    async def resolve(self, peer_did: str) -> Optional[IdentityResult]:
        if not peer_did.startswith("did:web:"):
            return None

        token = _jwks_pending_token.get()
        _jwks_pending_token.set(None)  # Clear after read — prevents stale reuse

        if not token:
            return None

        ext_id = await self._provider.verify(token)
        if ext_id is None:
            return None

        return IdentityResult(
            peer_did=ext_id.did_web,
            public_key="",  # key verified internally by ExternalJWKSProvider
            trust_score=0,
            capabilities=list(ext_id.delegation_claims.authority_scope),
            is_active=True,
            provider_name=self.name,
            external_identity=ext_id,
        )


class IdentityProviderChain:
    """Ordered chain of identity providers.

    Tries each provider in registration order. Returns the first
    successful ``IdentityResult``. If no provider can resolve the DID,
    returns ``None``.

    Usage::

        chain = IdentityProviderChain()
        chain.add(LocalRegistryProvider(registry))
        chain.add(ExternalJWKSProviderAdapter(jwks_provider))

        result = await chain.resolve("did:web:partner.example.com:agent:xyz")
    """

    def __init__(self) -> None:
        self._providers: list[IdentityProvider] = []

    def add(self, provider: IdentityProvider) -> "IdentityProviderChain":
        """Append a provider to the chain. Returns self for chaining."""
        self._providers.append(provider)
        return self

    @property
    def providers(self) -> list[IdentityProvider]:
        """Read-only view of registered providers."""
        return list(self._providers)

    async def resolve(self, peer_did: str) -> Optional[IdentityResult]:
        """Resolve *peer_did* by trying each provider in order.

        Returns the first successful result, or ``None`` if every
        provider returns ``None``.
        """
        for provider in self._providers:
            try:
                result = await provider.resolve(peer_did)
                if result is not None:
                    logger.debug(
                        "Identity resolved by %s for %s",
                        provider.name,
                        peer_did,
                    )
                    return result
            except Exception:
                logger.warning(
                    "Provider %s raised an error for %s, skipping",
                    provider.name,
                    peer_did,
                    exc_info=True,
                )
                continue

        logger.debug("No provider could resolve %s", peer_did)
        return None
