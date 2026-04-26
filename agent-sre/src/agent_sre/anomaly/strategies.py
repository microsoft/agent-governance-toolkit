# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Detection strategies for behavioral anomaly detection."""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING

from agent_sre.anomaly.detector import AnomalySeverity, BehaviorBaseline

if TYPE_CHECKING:
    from collections.abc import Sequence


class StatisticalStrategy:
    """Z-score and IQR based anomaly detection."""

    def __init__(self, z_threshold: float = 2.5, iqr_multiplier: float = 1.5) -> None:
        self.z_threshold = z_threshold
        self.iqr_multiplier = iqr_multiplier

    def check_zscore(self, value: float, mean: float, std_dev: float) -> tuple[bool, float]:
        """Check if a value is anomalous using z-score.

        Returns (is_anomaly, z_score).
        """
        if std_dev == 0:
            return False, 0.0
        z = abs(value - mean) / std_dev
        return z > self.z_threshold, z

    def check_iqr(self, value: float, values: Sequence[float]) -> tuple[bool, float]:
        """Check if a value is an outlier using the IQR method.

        Returns (is_anomaly, distance_from_boundary).
        """
        if len(values) < 4:
            return False, 0.0

        sorted_vals = sorted(values)
        n = len(sorted_vals)
        q1 = sorted_vals[n // 4]
        q3 = sorted_vals[(3 * n) // 4]
        iqr = q3 - q1

        lower = q1 - self.iqr_multiplier * iqr
        upper = q3 + self.iqr_multiplier * iqr

        if value < lower:
            return True, lower - value
        if value > upper:
            return True, value - upper
        return False, 0.0

    def determine_severity(self, score: float) -> AnomalySeverity:
        """Map an anomaly score to a severity level."""
        if score > 4.0:
            return AnomalySeverity.CRITICAL
        if score >= 3.0:
            return AnomalySeverity.WARNING
        return AnomalySeverity.INFO


class SequentialStrategy:
    """Detect unusual tool-call sequences by transition frequency."""

    def __init__(
        self,
        max_sequence_length: int = 50,
        min_pattern_frequency: int = 5,
    ) -> None:
        self.max_sequence_length = max_sequence_length
        self.min_pattern_frequency = min_pattern_frequency

    def check_sequence(
        self,
        sequence: list[str],
        new_item: str,
    ) -> tuple[bool, float, str]:
        """Check if a transition from the last item to *new_item* is rare.

        Builds a transition frequency map from *sequence* and flags rare
        transitions (frequency below *min_pattern_frequency*).

        Returns (is_anomaly, anomaly_score, explanation).
        """
        if not sequence:
            return False, 0.0, ""

        last_item = sequence[-1]
        transition_counts: Counter[str] = Counter()
        total_transitions = 0

        for i in range(len(sequence) - 1):
            if sequence[i] == last_item:
                transition_counts[sequence[i + 1]] += 1
                total_transitions += 1

        if total_transitions < self.min_pattern_frequency:
            return False, 0.0, "insufficient data"

        observed = transition_counts.get(new_item, 0)
        frequency = observed / total_transitions if total_transitions else 0.0

        if observed == 0:
            score = 1.0
            explanation = (
                f"transition '{last_item}' -> '{new_item}' never seen "
                f"({total_transitions} samples)"
            )
            return True, score, explanation

        if frequency < 0.05:
            score = 1.0 - frequency
            explanation = (
                f"transition '{last_item}' -> '{new_item}' is rare "
                f"(frequency {frequency:.2%})"
            )
            return True, score, explanation

        return False, 0.0, ""


class ResourceStrategy:
    """Detect resource-limit breaches (tokens, API calls)."""

    def __init__(
        self,
        token_budget: float | None = None,
        api_rate_limit: float | None = None,
    ) -> None:
        self.token_budget = token_budget
        self.api_rate_limit = api_rate_limit

    def check_resource(
        self,
        metric_name: str,
        value: float,
        baseline: BehaviorBaseline,
    ) -> tuple[bool, float]:
        """Check if *value* exceeds resource limits.

        Returns (is_anomaly, score).
        """
        # Check explicit budgets
        if self.token_budget is not None and "token" in metric_name.lower() and value > self.token_budget:
            score = value / self.token_budget if self.token_budget > 0 else 1.0
            return True, score

        if self.api_rate_limit is not None and "api" in metric_name.lower() and value > self.api_rate_limit:
            score = value / self.api_rate_limit if self.api_rate_limit > 0 else 1.0
            return True, score

        # Check against p99 baseline
        if baseline.sample_count > 0 and baseline.p99 > 0:
            threshold = baseline.p99 * 1.5
            if value > threshold:
                score = value / baseline.p99 if baseline.p99 > 0 else 1.0
                return True, score

        return False, 0.0
