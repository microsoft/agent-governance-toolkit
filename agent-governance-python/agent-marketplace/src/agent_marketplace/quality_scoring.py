# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Plugin quality scoring model — separate from trust/compliance scoring.

Trust tiers answer 'is this plugin safe?'
Quality scoring answers 'is this plugin good?'
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class QualityDimension(str, Enum):
    """Dimensions along which plugin quality is assessed."""

    DOCUMENTATION = "documentation"
    TEST_COVERAGE = "test_coverage"
    OUTPUT_ACCURACY = "output_accuracy"
    RELIABILITY = "reliability"
    PERFORMANCE = "performance"
    USER_SATISFACTION = "user_satisfaction"


class QualityBadge(str, Enum):
    """Badge tiers awarded based on overall quality score."""

    UNRATED = "unrated"
    BRONZE = "bronze"
    SILVER = "silver"
    GOLD = "gold"
    PLATINUM = "platinum"


@dataclass
class QualityScore:
    """Quality assessment for a single dimension."""

    dimension: QualityDimension
    score: float  # 0.0 to 1.0
    evidence: str = ""
    assessed_at: str = ""


@dataclass
class PluginQualityProfile:
    """Aggregated quality profile for a plugin."""

    plugin_name: str
    plugin_version: str
    scores: list[QualityScore] = field(default_factory=list)

    @property
    def overall_score(self) -> float:
        """Return the mean score across all assessed dimensions."""
        if not self.scores:
            return 0.0
        return sum(s.score for s in self.scores) / len(self.scores)

    @property
    def badge(self) -> QualityBadge:
        """Derive a badge from the overall score."""
        score = self.overall_score
        if score >= 0.9:
            return QualityBadge.PLATINUM
        elif score >= 0.75:
            return QualityBadge.GOLD
        elif score >= 0.6:
            return QualityBadge.SILVER
        elif score >= 0.4:
            return QualityBadge.BRONZE
        return QualityBadge.UNRATED

    def get_score(self, dimension: QualityDimension) -> float | None:
        """Return the score for a specific dimension, or ``None`` if unrated."""
        for s in self.scores:
            if s.dimension == dimension:
                return s.score
        return None


@dataclass
class QualityStore:
    """In-memory store for plugin quality profiles."""

    _profiles: dict[str, PluginQualityProfile] = field(default_factory=dict)

    def _key(self, name: str, version: str) -> str:
        return f"{name}@{version}"

    def record_score(
        self,
        plugin_name: str,
        plugin_version: str,
        score: QualityScore,
    ) -> None:
        """Record (or update) a quality score for a plugin dimension."""
        key = self._key(plugin_name, plugin_version)
        if key not in self._profiles:
            self._profiles[key] = PluginQualityProfile(
                plugin_name=plugin_name, plugin_version=plugin_version
            )
        profile = self._profiles[key]
        # Update existing dimension or add new
        profile.scores = [s for s in profile.scores if s.dimension != score.dimension]
        profile.scores.append(score)

    def get_profile(
        self, plugin_name: str, plugin_version: str
    ) -> PluginQualityProfile | None:
        """Retrieve the quality profile for a specific plugin version."""
        return self._profiles.get(self._key(plugin_name, plugin_version))

    def get_badge(self, plugin_name: str, plugin_version: str) -> QualityBadge:
        """Return the quality badge for a plugin, defaulting to UNRATED."""
        profile = self.get_profile(plugin_name, plugin_version)
        return profile.badge if profile else QualityBadge.UNRATED
