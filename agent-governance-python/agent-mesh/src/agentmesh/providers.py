# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Provider Discovery System for AgentMesh

Enables plug-and-play upgrades from Public Preview to Advanced implementations.
When an advanced provider package is installed, factory functions automatically
return the advanced implementation. Otherwise, Public Preview is used.

Usage:
    from agentmesh.providers import get_reward_engine, get_trust_bridge

    engine = get_reward_engine()   # Advanced if available, else CE
    bridge = get_trust_bridge()    # Advanced if available, else CE
"""

from __future__ import annotations

import logging
from importlib.metadata import entry_points
from typing import Any, Dict, Optional, Type

logger = logging.getLogger(__name__)

PROVIDER_GROUPS = {
    "reward_engine": "agentmesh.providers.reward_engine",
    "trust_bridge": "agentmesh.providers.trust_bridge",
    "delegation": "agentmesh.providers.delegation",
    "audit": "agentmesh.providers.audit",
    "trust_decay": "agentmesh.providers.trust_decay",
    "capability": "agentmesh.providers.capability",
}

_provider_cache: Dict[str, Any] = {}


def _discover_provider(group: str) -> Optional[Type]:
    """Discover an advanced provider via entry_points."""
    if group in _provider_cache:
        return _provider_cache[group]

    try:
        eps = entry_points(group=group)
        if eps:
            ep = next(iter(eps))
            provider_cls = ep.load()
            _provider_cache[group] = provider_cls
            logger.info("Advanced provider loaded: %s from %s", ep.name, ep.value)
            return provider_cls
    except Exception:
        logger.debug("Provider discovery failed for %s", group, exc_info=True)

    _provider_cache[group] = None
    return None


def get_reward_engine(**kwargs: Any):
    """Get the best available reward engine.

    Advanced: 5-dimension EMA scoring with adaptive weight learning.
    Community: Single-dimension trust score (0-1 float).
    """
    provider = _discover_provider(PROVIDER_GROUPS["reward_engine"])
    if provider is not None:
        return provider(**kwargs)

    from agentmesh.reward.engine import RewardEngine
    return RewardEngine(**kwargs)


def get_trust_bridge(**kwargs: Any):
    """Get the best available trust bridge.

    Advanced: Cross-protocol trust translation (A2A/MCP/IATP).
    Community: Direct passthrough without translation.
    """
    provider = _discover_provider(PROVIDER_GROUPS["trust_bridge"])
    if provider is not None:
        return provider(**kwargs)

    from agentmesh.trust.bridge import TrustBridge
    return TrustBridge(**kwargs)


def get_delegation_chain(**kwargs: Any):
    """Get the best available delegation chain.

    Advanced: Cryptographic delegation chains with attenuation.
    Community: Simple parent-to-child scope passing.
    """
    provider = _discover_provider(PROVIDER_GROUPS["delegation"])
    if provider is not None:
        return provider(**kwargs)

    from agentmesh.identity.delegation import DelegationChain
    return DelegationChain(**kwargs)


def get_audit_logger(**kwargs: Any):
    """Get the best available audit logger.

    Advanced: Merkle-chained audit with hash verification.
    Community: Append-only JSON log file.
    """
    provider = _discover_provider(PROVIDER_GROUPS["audit"])
    if provider is not None:
        return provider(**kwargs)

    from agentmesh.governance.audit import AuditLogger
    return AuditLogger(**kwargs)


def get_trust_decay(**kwargs: Any):
    """Get the best available trust decay engine.

    Advanced: Trust contagion + KL divergence regime detection.
    Community: Linear decay over time.
    """
    provider = _discover_provider(PROVIDER_GROUPS["trust_decay"])
    if provider is not None:
        return provider(**kwargs)

    from agentmesh.reward.trust_decay import TrustDecayEngine
    return TrustDecayEngine(**kwargs)


def get_capability_engine(**kwargs: Any):
    """Get the best available capability engine.

    Advanced: Cryptographic capability narrowing enforcement.
    Community: Simple string-based scope checking.
    """
    provider = _discover_provider(PROVIDER_GROUPS["capability"])
    if provider is not None:
        return provider(**kwargs)

    from agentmesh.trust.capability import CapabilityEngine
    return CapabilityEngine(**kwargs)


def list_providers() -> Dict[str, str]:
    """List all provider slots and their current implementations."""
    result = {}
    for name, group in PROVIDER_GROUPS.items():
        provider = _discover_provider(group)
        result[name] = "advanced" if provider is not None else "community"
    return result


def clear_cache() -> None:
    """Clear the provider cache. Useful for testing."""
    _provider_cache.clear()
