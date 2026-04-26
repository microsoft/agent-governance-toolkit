# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Usage telemetry signals for trust scoring.

Extends trust tiers with real-world usage data: invocation counts,
error rates, adoption trends, and incident history.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class UsageSignals:
    """Aggregated usage telemetry for a plugin."""

    plugin_name: str
    plugin_version: str
    daily_active_users: int = 0
    total_invocations: int = 0
    error_count: int = 0
    incident_count: int = 0
    days_since_update: int = 0
    adoption_trend: float = 0.0  # positive = growing, negative = declining

    @property
    def error_rate(self) -> float:
        if self.total_invocations == 0:
            return 0.0
        return self.error_count / self.total_invocations

    @property
    def is_stale(self) -> bool:
        return self.days_since_update > 180


@dataclass
class UsageTrustAdjustment:
    """Trust score adjustment based on usage signals."""

    reason: str
    adjustment: int  # positive = trust increase, negative = decrease
    signal_name: str
    signal_value: float


class UsageTrustScorer:
    """Computes trust adjustments from usage telemetry."""

    def __init__(self, max_adjustment: int = 200) -> None:
        self._max_adjustment = max_adjustment

    def compute_adjustments(
        self, signals: UsageSignals,
    ) -> list[UsageTrustAdjustment]:
        adjustments: list[UsageTrustAdjustment] = []

        # Adoption bonus: more users = more trust
        if signals.daily_active_users >= 1000:
            adjustments.append(
                UsageTrustAdjustment(
                    "High adoption", 100,
                    "daily_active_users", signals.daily_active_users,
                ),
            )
        elif signals.daily_active_users >= 100:
            adjustments.append(
                UsageTrustAdjustment(
                    "Moderate adoption", 50,
                    "daily_active_users", signals.daily_active_users,
                ),
            )
        elif signals.daily_active_users >= 10:
            adjustments.append(
                UsageTrustAdjustment(
                    "Low adoption", 10,
                    "daily_active_users", signals.daily_active_users,
                ),
            )

        # Reliability bonus/penalty
        if signals.total_invocations >= 1000:
            if signals.error_rate < 0.001:
                adjustments.append(
                    UsageTrustAdjustment(
                        "Excellent reliability", 75,
                        "error_rate", signals.error_rate,
                    ),
                )
            elif signals.error_rate < 0.01:
                adjustments.append(
                    UsageTrustAdjustment(
                        "Good reliability", 25,
                        "error_rate", signals.error_rate,
                    ),
                )
            elif signals.error_rate > 0.1:
                adjustments.append(
                    UsageTrustAdjustment(
                        "Poor reliability", -100,
                        "error_rate", signals.error_rate,
                    ),
                )

        # Incident penalty
        if signals.incident_count > 0:
            penalty = max(signals.incident_count * -50, -200)
            adjustments.append(
                UsageTrustAdjustment(
                    "Security incidents", penalty,
                    "incident_count", signals.incident_count,
                ),
            )

        # Staleness penalty
        if signals.is_stale:
            adjustments.append(
                UsageTrustAdjustment(
                    "Stale package", -50,
                    "days_since_update", signals.days_since_update,
                ),
            )

        # Adoption trend
        if signals.adoption_trend > 0.1:
            adjustments.append(
                UsageTrustAdjustment(
                    "Growing adoption", 25,
                    "adoption_trend", signals.adoption_trend,
                ),
            )
        elif signals.adoption_trend < -0.2:
            adjustments.append(
                UsageTrustAdjustment(
                    "Declining adoption", -25,
                    "adoption_trend", signals.adoption_trend,
                ),
            )

        return adjustments

    def compute_total_adjustment(self, signals: UsageSignals) -> int:
        total = sum(a.adjustment for a in self.compute_adjustments(signals))
        return max(-self._max_adjustment, min(self._max_adjustment, total))