# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Provider Discovery System for Agent Hypervisor

Enables plug-and-play upgrades from Public Preview to Advanced implementations.
"""

from __future__ import annotations

import logging
from importlib.metadata import entry_points
from typing import Any

logger = logging.getLogger(__name__)

PROVIDER_GROUPS = {
    "ring_engine": "hypervisor.providers.ring_engine",
    "liability": "hypervisor.providers.liability",
    "saga_engine": "hypervisor.providers.saga_engine",
    "breach_detector": "hypervisor.providers.breach_detector",
    "session_manager": "hypervisor.providers.session_manager",
    "audit_engine": "hypervisor.providers.audit_engine",
}

_provider_cache: dict[str, Any] = {}


def _discover_provider(group: str) -> type | None:
    """Discover an advanced provider via entry_points."""
    if group in _provider_cache:
        return _provider_cache[group]

    try:
        eps = entry_points(group=group)
        if eps:
            ep = next(iter(eps))
            provider_cls = ep.load()
            if not isinstance(provider_cls, type):
                logger.warning(
                    "Provider %s is not a class, skipping", ep.name
                )
            else:
                _provider_cache[group] = provider_cls
                logger.info("Advanced provider loaded: %s from %s", ep.name, ep.value)
                return provider_cls
    except Exception:
        logger.debug("Provider discovery failed for %s", group, exc_info=True)

    _provider_cache[group] = None
    return None


def get_ring_engine(**kwargs: Any):
    """Get the best available execution ring engine.

    Advanced: 4-ring privilege escalation with breach detection.
    Community: Basic ring assignment with classifier.
    """
    provider = _discover_provider(PROVIDER_GROUPS["ring_engine"])
    if provider is not None:
        return provider(**kwargs)

    from hypervisor.rings.enforcer import RingEnforcer
    return RingEnforcer(**kwargs)


def get_liability_engine(**kwargs: Any):
    """Get the best available liability engine.

    Advanced: Shapley-value fault attribution with vouch cascades.
    Community: Basic vouching with linear slashing.
    """
    provider = _discover_provider(PROVIDER_GROUPS["liability"])
    if provider is not None:
        return provider(**kwargs)

    from hypervisor.liability.engine import LiabilityEngine
    return LiabilityEngine(**kwargs)


def get_saga_engine(**kwargs: Any):
    """Get the best available saga orchestration engine.

    Advanced: Multi-pattern saga with parallel fan-out and escalation.
    Community: Sequential saga with basic compensation.
    """
    provider = _discover_provider(PROVIDER_GROUPS["saga_engine"])
    if provider is not None:
        return provider(**kwargs)

    from hypervisor.saga.engine import SagaOrchestrator
    return SagaOrchestrator(**kwargs)


def get_breach_detector(**kwargs: Any):
    """Get the best available breach detector.

    Advanced: Multi-signal breach detection with severity scoring.
    Community: Basic threshold-based detection with safe defaults.
    """
    provider = _discover_provider(PROVIDER_GROUPS["breach_detector"])
    if provider is not None:
        return provider(**kwargs)

    from hypervisor.rings.breach_detector import RingBreachDetector
    return RingBreachDetector(**kwargs)


def list_providers() -> dict[str, str]:
    """List all provider slots and their current implementations."""
    result = {}
    for name, group in PROVIDER_GROUPS.items():
        provider = _discover_provider(group)
        result[name] = "advanced" if provider is not None else "community"
    return result


def clear_cache() -> None:
    """Clear the provider cache."""
    _provider_cache.clear()
