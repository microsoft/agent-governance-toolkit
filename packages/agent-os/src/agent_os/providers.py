# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Provider Discovery System

Enables plug-and-play upgrades from Public Preview to Advanced implementations.
When an advanced provider package is installed (e.g., agent-governance-providers),
factory functions automatically return the advanced implementation. Otherwise,
they return the built-in Public Preview.

Usage:
    from agent_os.providers import get_verification_engine, get_self_correction_kernel

    engine = get_verification_engine()   # Advanced if available, else CE
    kernel = get_self_correction_kernel() # Advanced if available, else CE

Advanced: pip install agent-governance-providers (from PyPI)
Community: pip install agent-os-kernel (from PyPI) — works out of the box
"""

from __future__ import annotations

import logging
from importlib.metadata import entry_points
from typing import Any

logger = logging.getLogger(__name__)

# Entry point group names — internal packages register under these
PROVIDER_GROUPS = {
    "verification": "agent_os.providers.verification",
    "self_correction": "agent_os.providers.self_correction",
    "policy_engine": "agent_os.providers.policy_engine",
    "context_service": "agent_os.providers.context_service",
    "memory": "agent_os.providers.memory",
    "trust_protocol": "agent_os.providers.trust_protocol",
    "mute_agent": "agent_os.providers.mute_agent",
}

# Cache loaded providers to avoid repeated discovery
_provider_cache: dict[str, Any] = {}


def _discover_provider(group: str) -> type | None:
    """Discover an advanced provider via entry_points.

    Returns the provider class if found, None otherwise.
    """
    if group in _provider_cache:
        return _provider_cache[group]

    try:
        eps = entry_points(group=group)
        if eps:
            # Use the first registered provider (highest priority)
            ep = next(iter(eps))
            provider_cls = ep.load()
            _provider_cache[group] = provider_cls
            logger.info(
                "Advanced provider loaded: %s from %s", ep.name, ep.value
            )
            return provider_cls
    except Exception:
        logger.debug("Provider discovery failed for %s", group, exc_info=True)

    _provider_cache[group] = None
    return None


def get_verification_engine(**kwargs: Any):
    """Get the best available verification engine.

    Advanced: Cross-model adversarial verification with strategy banning.
    Community: Single-model self-check using difflib comparison.
    """
    provider = _discover_provider(PROVIDER_GROUPS["verification"])
    if provider is not None:
        return provider(**kwargs)

    from cmvk.verification import VerificationEngine
    return VerificationEngine(**kwargs)


def get_self_correction_kernel(**kwargs: Any):
    """Get the best available self-correction kernel.

    Advanced: Dual-loop OODA with differential auditing and semantic purge.
    Community: Simple retry with exponential backoff.
    """
    provider = _discover_provider(PROVIDER_GROUPS["self_correction"])
    if provider is not None:
        return provider(**kwargs)

    from agent_kernel.kernel import SelfCorrectingAgentKernel
    return SelfCorrectingAgentKernel(**kwargs)


def get_policy_engine(**kwargs: Any):
    """Get the best available policy engine.

    Advanced: ABAC with attribute evaluation, constraint graphs, shadow mode.
    Community: YAML-driven allow/deny rules with first-match semantics.
    """
    provider = _discover_provider(PROVIDER_GROUPS["policy_engine"])
    if provider is not None:
        return provider(**kwargs)

    from agent_os.integrations.base import GovernancePolicy
    return GovernancePolicy(**kwargs)


def get_context_service(**kwargs: Any):
    """Get the best available context service.

    Advanced: Hot/Warm/Cold tiers with heuristic routing and pragmatic truth.
    Community: Single-tier context with TTL-based expiry.
    """
    provider = _discover_provider(PROVIDER_GROUPS["context_service"])
    if provider is not None:
        return provider(**kwargs)

    from caas.triad import ContextTriadManager
    return ContextTriadManager(**kwargs)


def get_memory_store(**kwargs: Any):
    """Get the best available episodic memory store.

    Advanced: Immutable append-only store with hash chaining (GARR).
    Community: Mutable JSON file-based episode store.
    """
    provider = _discover_provider(PROVIDER_GROUPS["memory"])
    if provider is not None:
        return provider(**kwargs)

    from emk.store import EpisodicMemoryStore
    return EpisodicMemoryStore(**kwargs)


def get_trust_protocol(**kwargs: Any):
    """Get the best available trust protocol engine.

    Advanced: Full IATP with sidecar attestation and capability handshake.
    Community: Basic policy engine with nonce-based verification.
    """
    provider = _discover_provider(PROVIDER_GROUPS["trust_protocol"])
    if provider is not None:
        return provider(**kwargs)

    from iatp.policy_engine import IATPPolicyEngine
    return IATPPolicyEngine(**kwargs)


def get_mute_agent(**kwargs: Any):
    """Get the best available mute agent implementation.

    Advanced: NULL response pattern with zero information leakage.
    Community: Simple empty-string response on policy block.
    """
    provider = _discover_provider(PROVIDER_GROUPS["mute_agent"])
    if provider is not None:
        return provider(**kwargs)

    from agent_os.mute_agent import MuteAgent
    return MuteAgent(**kwargs)


def list_providers() -> dict[str, str]:
    """List all provider slots and their current implementations.

    Returns a dict of {slot_name: "advanced" | "community"}.
    """
    result = {}
    for name, group in PROVIDER_GROUPS.items():
        provider = _discover_provider(group)
        result[name] = "advanced" if provider is not None else "community"
    return result


def clear_cache() -> None:
    """Clear the provider cache. Useful for testing."""
    _provider_cache.clear()
