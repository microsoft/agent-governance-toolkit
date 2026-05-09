# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Trust-level helpers shared across CLI, servers, and integrations."""

from __future__ import annotations

from agentmesh.constants import (
    TIER_PROBATIONARY_THRESHOLD,
    TIER_STANDARD_THRESHOLD,
    TIER_TRUSTED_THRESHOLD,
    TIER_VERIFIED_PARTNER_THRESHOLD,
)

__all__ = ["trust_level_for_score"]


def trust_level_for_score(score: int) -> str:
    """Return the canonical trust-level label for a numeric score (0-1000).

    The mapping mirrors the tiers defined in ``agentmesh.constants`` and is
    the single source of truth used by the trust-engine HTTP API, the
    ``agentmesh trust`` CLI, and any caller that needs to render a score
    as a human-readable label.

    Returns one of: ``"verified_partner"``, ``"trusted"``, ``"standard"``,
    ``"probationary"``, ``"untrusted"``.
    """
    if score >= TIER_VERIFIED_PARTNER_THRESHOLD:
        return "verified_partner"
    if score >= TIER_TRUSTED_THRESHOLD:
        return "trusted"
    if score >= TIER_STANDARD_THRESHOLD:
        return "standard"
    if score >= TIER_PROBATIONARY_THRESHOLD:
        return "probationary"
    return "untrusted"
