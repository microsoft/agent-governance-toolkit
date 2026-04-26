# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
IATP Integration Stub — Capability Manifest parsing.

Provides the interface for parsing agent capability manifests
into Hypervisor-compatible action descriptors and ring hints.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Protocol

from hypervisor.models import (
    ActionDescriptor,
    ExecutionRing,
    ReversibilityLevel,
)


class IATPManifest(Protocol):
    """Protocol for a capability manifest."""

    agent_id: str
    trust_level: Any
    capabilities: Any
    scopes: list[str]

    def calculate_trust_score(self) -> int: ...


class IATPTrustLevel(str, Enum):
    VERIFIED_PARTNER = "verified_partner"
    TRUSTED = "trusted"
    STANDARD = "standard"
    UNKNOWN = "unknown"
    UNTRUSTED = "untrusted"


TRUST_LEVEL_RING_HINTS = {
    IATPTrustLevel.VERIFIED_PARTNER: ExecutionRing.RING_1_PRIVILEGED,
    IATPTrustLevel.TRUSTED: ExecutionRing.RING_2_STANDARD,
    IATPTrustLevel.STANDARD: ExecutionRing.RING_2_STANDARD,
    IATPTrustLevel.UNKNOWN: ExecutionRing.RING_3_SANDBOX,
    IATPTrustLevel.UNTRUSTED: ExecutionRing.RING_3_SANDBOX,
}

REVERSIBILITY_MAP = {
    "full": ReversibilityLevel.FULL,
    "partial": ReversibilityLevel.PARTIAL,
    "none": ReversibilityLevel.NONE,
}


@dataclass
class ManifestAnalysis:
    """Result of analyzing a capability manifest."""

    agent_did: str
    trust_level: IATPTrustLevel
    ring_hint: ExecutionRing
    iatp_trust_score: int
    sigma_hint: float
    actions: list[ActionDescriptor]
    scopes: list[str]
    has_reversible_actions: bool
    has_non_reversible_actions: bool
    analyzed_at: datetime = field(default_factory=lambda: datetime.now(UTC))


class IATPAdapter:
    """Stub adapter for capability manifest parsing."""

    def __init__(self) -> None:
        self._manifest_cache: dict[str, ManifestAnalysis] = {}

    def analyze_manifest(self, manifest: IATPManifest) -> ManifestAnalysis:
        """Analyze a manifest and extract ring hints and actions."""
        agent_did = manifest.agent_id
        trust_str = str(getattr(manifest.trust_level, "value", manifest.trust_level))
        try:
            trust_level = IATPTrustLevel(trust_str)
        except ValueError:
            trust_level = IATPTrustLevel.UNKNOWN
        ring_hint = TRUST_LEVEL_RING_HINTS.get(trust_level, ExecutionRing.RING_3_SANDBOX)
        iatp_score = manifest.calculate_trust_score()
        import math
        if not isinstance(iatp_score, (int, float)) or not math.isfinite(iatp_score):
            iatp_score = 0.0
        iatp_score = min(max(iatp_score, 0.0), 100.0)
        sigma_hint = min(max(iatp_score / 10.0, 0.0), 1.0)
        analysis = ManifestAnalysis(
            agent_did=agent_did, trust_level=trust_level, ring_hint=ring_hint,
            iatp_trust_score=iatp_score, sigma_hint=sigma_hint, actions=[],
            scopes=list(manifest.scopes) if manifest.scopes else [],
            has_reversible_actions=False, has_non_reversible_actions=False,
        )
        self._manifest_cache[agent_did] = analysis
        return analysis

    def analyze_manifest_dict(self, manifest_dict: dict) -> ManifestAnalysis:
        """Analyze a manifest provided as a dictionary."""
        agent_did = manifest_dict.get("agent_id", "unknown")
        trust_str = manifest_dict.get("trust_level", "unknown")
        try:
            trust_level = IATPTrustLevel(trust_str)
        except ValueError:
            trust_level = IATPTrustLevel.UNKNOWN
        ring_hint = TRUST_LEVEL_RING_HINTS.get(trust_level, ExecutionRing.RING_3_SANDBOX)
        iatp_score = manifest_dict.get("trust_score", 5)
        import math
        if not isinstance(iatp_score, (int, float)) or not math.isfinite(iatp_score):
            iatp_score = 0.0
        iatp_score = min(max(iatp_score, 0.0), 100.0)
        sigma_hint = min(max(iatp_score / 10.0, 0.0), 1.0)
        actions = []
        for cap in manifest_dict.get("actions", []):
            rev_str = cap.get("reversibility", "none")
            actions.append(ActionDescriptor(
                action_id=cap.get("action_id", "unknown"),
                name=cap.get("name", ""),
                execute_api=cap.get("execute_api", ""),
                undo_api=cap.get("undo_api"),
                reversibility=REVERSIBILITY_MAP.get(rev_str, ReversibilityLevel.NONE),
                is_read_only=cap.get("is_read_only", False),
                is_admin=cap.get("is_admin", False),
            ))
        analysis = ManifestAnalysis(
            agent_did=agent_did, trust_level=trust_level, ring_hint=ring_hint,
            iatp_trust_score=iatp_score, sigma_hint=sigma_hint, actions=actions,
            scopes=manifest_dict.get("scopes", []),
            has_reversible_actions=any(a.reversibility != ReversibilityLevel.NONE for a in actions),
            has_non_reversible_actions=any(a.reversibility == ReversibilityLevel.NONE and not a.is_read_only for a in actions),
        )
        self._manifest_cache[agent_did] = analysis
        return analysis

    def get_cached_analysis(self, agent_did: str) -> ManifestAnalysis | None:
        return self._manifest_cache.get(agent_did)
