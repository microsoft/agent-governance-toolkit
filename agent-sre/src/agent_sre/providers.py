# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Provider Discovery System for Agent SRE

Enables plug-and-play upgrades from Public Preview to Advanced implementations.
"""

from __future__ import annotations

import logging
from importlib.metadata import entry_points
from typing import Any

logger = logging.getLogger(__name__)

PROVIDER_GROUPS = {
    "slo_detection": "agent_sre.providers.slo_detection",
    "replay_engine": "agent_sre.providers.replay_engine",
    "chaos_engine": "agent_sre.providers.chaos_engine",
    "cost_optimizer": "agent_sre.providers.cost_optimizer",
    "delivery": "agent_sre.providers.delivery",
    "incident": "agent_sre.providers.incident",
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
            _provider_cache[group] = provider_cls
            logger.info("Advanced provider loaded: %s from %s", ep.name, ep.value)
            return provider_cls
    except Exception:
        logger.debug("Provider discovery failed for %s", group, exc_info=True)

    _provider_cache[group] = None
    return None


def get_slo_detector(**kwargs: Any):
    """Get the best available SLO detection engine.

    Advanced: Multi-signal SLO detection with agent SLIs.
    Community: Threshold-based SLO monitoring.
    """
    provider = _discover_provider(PROVIDER_GROUPS["slo_detection"])
    if provider is not None:
        return provider(**kwargs)

    from agent_sre.slo.detector import SLODetector
    return SLODetector(**kwargs)


def get_replay_engine(**kwargs: Any):
    """Get the best available replay engine.

    Advanced: Full execution replay with differential analysis.
    Community: Log-based trace replay.
    """
    provider = _discover_provider(PROVIDER_GROUPS["replay_engine"])
    if provider is not None:
        return provider(**kwargs)

    from agent_sre.replay.engine import ReplayEngine
    return ReplayEngine(**kwargs)


def get_chaos_engine(**kwargs: Any):
    """Get the best available chaos engine.

    Advanced: Template-driven chaos with coverage analysis.
    Community: Basic fault injection with scheduling.
    """
    provider = _discover_provider(PROVIDER_GROUPS["chaos_engine"])
    if provider is not None:
        return provider(**kwargs)

    from agent_sre.chaos.engine import ChaosEngine
    return ChaosEngine(**kwargs)


def get_cost_optimizer(**kwargs: Any):
    """Get the best available cost optimizer.

    Advanced: Multi-dimensional cost optimization with anomaly detection.
    Community: Basic budget guard with threshold alerts.
    """
    provider = _discover_provider(PROVIDER_GROUPS["cost_optimizer"])
    if provider is not None:
        return provider(**kwargs)

    from agent_sre.cost.optimizer import CostOptimizer
    return CostOptimizer(**kwargs)


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
