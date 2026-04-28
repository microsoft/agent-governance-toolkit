# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Plugin Trust Tiers

Maps agentmesh trust scoring (0-1000, five tiers) into agent-marketplace so
plugins receive progressive capability limits based on their trust level.

The module is designed to work standalone — no hard dependency on the
agentmesh package being installed.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

from agent_marketplace.manifest import PluginManifest

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Trust tier definitions (matching agentmesh conventions)
# ---------------------------------------------------------------------------

TRUST_TIERS: dict[str, tuple[int, int]] = {
    "revoked": (0, 299),
    "probationary": (300, 499),
    "standard": (500, 699),
    "trusted": (700, 899),
    "verified": (900, 1000),
}

TIER_ORDER: list[str] = ["revoked", "probationary", "standard", "trusted", "verified"]

# ---------------------------------------------------------------------------
# Per-tier capability configuration
# ---------------------------------------------------------------------------


class PluginTrustConfig(BaseModel):
    """Per-tier capability limits for a plugin."""

    max_token_budget: int = Field(..., description="Maximum token budget allowed")
    max_tool_calls: int = Field(..., description="Maximum tool calls per invocation")
    allowed_tool_access: str = Field(
        ...,
        description="Tool access level: read-only, read-write, or full",
    )


DEFAULT_TIER_CONFIGS: dict[str, PluginTrustConfig] = {
    "revoked": PluginTrustConfig(
        max_token_budget=0,
        max_tool_calls=0,
        allowed_tool_access="read-only",
    ),
    "probationary": PluginTrustConfig(
        max_token_budget=1000,
        max_tool_calls=5,
        allowed_tool_access="read-only",
    ),
    "standard": PluginTrustConfig(
        max_token_budget=5000,
        max_tool_calls=25,
        allowed_tool_access="read-write",
    ),
    "trusted": PluginTrustConfig(
        max_token_budget=20000,
        max_tool_calls=100,
        allowed_tool_access="read-write",
    ),
    "verified": PluginTrustConfig(
        max_token_budget=100000,
        max_tool_calls=500,
        allowed_tool_access="full",
    ),
}

# Capabilities that require a minimum tier to be enabled
_TIER_CAPABILITY_REQUIREMENTS: dict[str, int] = {
    "network": 2,       # standard+
    "filesystem": 2,    # standard+
    "execute": 3,       # trusted+
    "admin": 4,         # verified only
}

# ---------------------------------------------------------------------------
# Public helper functions
# ---------------------------------------------------------------------------


def get_trust_tier(score: int) -> str:
    """Return the tier name for a given trust score.

    Args:
        score: Integer trust score in the range 0-1000.

    Returns:
        Tier name (e.g. ``"standard"``).

    Raises:
        ValueError: If *score* is outside the 0-1000 range.
    """
    if score < 0 or score > 1000:
        raise ValueError(f"Trust score must be between 0 and 1000, got {score}")
    for tier, (low, high) in TRUST_TIERS.items():
        if low <= score <= high:
            return tier
    # Should be unreachable given the ranges cover 0-1000
    return "revoked"  # pragma: no cover


def get_tier_config(tier: str) -> PluginTrustConfig:
    """Return the capability configuration for a tier.

    Args:
        tier: Tier name (must be a key in :data:`TRUST_TIERS`).

    Returns:
        The :class:`PluginTrustConfig` for the tier.

    Raises:
        ValueError: If *tier* is not a recognised tier name.
    """
    if tier not in DEFAULT_TIER_CONFIGS:
        raise ValueError(f"Unknown trust tier: {tier}")
    return DEFAULT_TIER_CONFIGS[tier]


def filter_capabilities(capabilities: list[str], tier: str) -> list[str]:
    """Filter a list of capabilities based on the plugin's trust tier.

    Capabilities with a higher minimum-tier requirement than the given
    *tier* are removed.

    Args:
        capabilities: Declared capability strings.
        tier: Current trust tier name.

    Returns:
        Filtered list containing only the capabilities the tier permits.
    """
    if tier not in TIER_ORDER:
        raise ValueError(f"Unknown trust tier: {tier}")
    tier_index = TIER_ORDER.index(tier)
    return [
        cap
        for cap in capabilities
        if tier_index >= _TIER_CAPABILITY_REQUIREMENTS.get(cap, 0)
    ]


def compute_initial_score(manifest: PluginManifest) -> int:
    """Compute an initial trust score for a newly registered plugin.

    Heuristics:
    - Base score: 500 (``standard`` floor).
    - +100 if the manifest carries a cryptographic signature.
    - +50 if the manifest declares at least one capability.
    - -50 if the manifest has no description or it is very short (<20 chars).

    The result is clamped to the 0-1000 range.

    Args:
        manifest: The plugin manifest to evaluate.

    Returns:
        Integer trust score.
    """
    score = 500

    if manifest.signature:
        score += 100

    if manifest.capabilities:
        score += 50

    if len(manifest.description) < 20:
        score -= 50

    return max(0, min(1000, score))


# ---------------------------------------------------------------------------
# Persistent trust store
# ---------------------------------------------------------------------------


class PluginTrustStore:
    """File-backed JSON store for plugin trust scores and event history.

    Args:
        store_path: Path to the JSON file used for persistence.
    """

    def __init__(self, store_path: Path) -> None:
        self._store_path = store_path
        self._data: dict = self._load()

    # -- public API --------------------------------------------------------

    def get_score(self, plugin_name: str) -> int:
        """Return the current trust score for *plugin_name*.

        Returns 500 (``standard`` floor) if the plugin has no recorded score.
        """
        return self._data.get("scores", {}).get(plugin_name, 500)

    def set_score(self, plugin_name: str, score: int) -> None:
        """Set the trust score for *plugin_name* (clamped to 0-1000)."""
        score = max(0, min(1000, score))
        self._data.setdefault("scores", {})[plugin_name] = score
        self._persist()

    def record_event(self, plugin_name: str, event: str, delta: int) -> None:
        """Record a trust event and adjust the plugin's score.

        Args:
            plugin_name: Plugin identifier.
            event: Short description of the event (e.g. ``"policy_violation"``).
            delta: Score adjustment (positive or negative).
        """
        current = self.get_score(plugin_name)
        new_score = max(0, min(1000, current + delta))
        self._data.setdefault("scores", {})[plugin_name] = new_score

        entry = {
            "event": event,
            "delta": delta,
            "score_before": current,
            "score_after": new_score,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._data.setdefault("events", {}).setdefault(plugin_name, []).append(entry)
        self._persist()
        logger.info(
            "Trust event for %s: %s (%+d) → %d",
            plugin_name,
            event,
            delta,
            new_score,
        )

    def get_tier(self, plugin_name: str) -> str:
        """Return the current trust tier for *plugin_name*."""
        return get_trust_tier(self.get_score(plugin_name))

    # -- persistence -------------------------------------------------------

    def _load(self) -> dict:
        if self._store_path.exists():
            try:
                with open(self._store_path) as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                logger.warning("Corrupt trust store at %s — starting fresh", self._store_path)
        return {"scores": {}, "events": {}}

    def _persist(self) -> None:
        self._store_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._store_path, "w") as f:
            json.dump(self._data, f, indent=2)
