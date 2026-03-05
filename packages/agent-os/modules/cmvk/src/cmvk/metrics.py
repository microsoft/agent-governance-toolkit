# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Community Edition — basic single-model verification
"""
CMVK Distance Metrics Module — Community Edition

Basic distance metrics using Python stdlib only (no numpy/scipy).

Supported Metrics:
    - cosine: Cosine distance (default)
    - euclidean: Euclidean distance
    - manhattan: Manhattan/L1 distance
    - chebyshev: Chebyshev/L∞ distance
    - mahalanobis: Mahalanobis distance (identity covariance only)
"""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any


class DistanceMetric(Enum):
    """Supported distance metrics for embedding comparison."""

    COSINE = "cosine"
    EUCLIDEAN = "euclidean"
    MANHATTAN = "manhattan"
    CHEBYSHEV = "chebyshev"
    MAHALANOBIS = "mahalanobis"


@dataclass(frozen=True)
class MetricResult:
    """
    Result of a distance metric calculation.

    Attributes:
        distance: Raw distance value
        normalized: Distance normalized to [0, 1] range
        metric: The metric used
        details: Additional metric-specific information
    """

    distance: float
    normalized: float
    metric: DistanceMetric
    details: dict


def _dot(a: list[float], b: list[float]) -> float:
    return sum(ai * bi for ai, bi in zip(a, b))


def _norm(v: list[float]) -> float:
    return math.sqrt(sum(x * x for x in v))


def _to_floats(v: Any) -> list[float]:
    """Convert any array-like to list[float]."""
    if isinstance(v, list):
        return [float(x) for x in v]
    # handle numpy arrays or other iterables
    return [float(x) for x in v]


def cosine_distance(vec_a: list[float], vec_b: list[float]) -> MetricResult:
    """Calculate cosine distance between two vectors."""
    dot_val = _dot(vec_a, vec_b)
    norm_a = _norm(vec_a)
    norm_b = _norm(vec_b)

    if norm_a == 0 or norm_b == 0:
        dist = 1.0
    else:
        dist = 1.0 - dot_val / (norm_a * norm_b)

    dist = max(0.0, min(2.0, dist))

    return MetricResult(
        distance=dist,
        normalized=dist / 2.0,
        metric=DistanceMetric.COSINE,
        details={
            "cosine_similarity": 1.0 - dist,
            "norm_a": norm_a,
            "norm_b": norm_b,
        },
    )


def euclidean_distance(
    vec_a: list[float],
    vec_b: list[float],
    expected_range: tuple[float, float] | None = None,
) -> MetricResult:
    """Calculate Euclidean (L2) distance between two vectors."""
    dim_diffs = [abs(a - b) for a, b in zip(vec_a, vec_b)]
    dist = math.sqrt(sum(d * d for d in dim_diffs))

    max_diff_dim = max(range(len(dim_diffs)), key=lambda i: dim_diffs[i]) if dim_diffs else 0
    max_diff_value = dim_diffs[max_diff_dim] if dim_diffs else 0.0

    if expected_range is not None:
        min_val, max_val = expected_range
        max_possible_dist = math.sqrt(len(vec_a)) * (max_val - min_val)
    else:
        max_possible_dist = math.sqrt(len(vec_a) * 4)

    normalized = min(dist / max_possible_dist, 1.0) if max_possible_dist > 0 else 0.0

    mean_diff = sum(dim_diffs) / len(dim_diffs) if dim_diffs else 0.0

    return MetricResult(
        distance=dist,
        normalized=normalized,
        metric=DistanceMetric.EUCLIDEAN,
        details={
            "max_diff_dimension": max_diff_dim,
            "max_diff_value": max_diff_value,
            "mean_diff": mean_diff,
        },
    )


def manhattan_distance(
    vec_a: list[float],
    vec_b: list[float],
    expected_range: tuple[float, float] | None = None,
) -> MetricResult:
    """Calculate Manhattan (L1/city-block) distance between two vectors."""
    dim_diffs = [abs(a - b) for a, b in zip(vec_a, vec_b)]
    dist = sum(dim_diffs)

    if expected_range is not None:
        min_val, max_val = expected_range
        max_possible_dist = len(vec_a) * (max_val - min_val)
    else:
        max_possible_dist = len(vec_a) * 2

    normalized = min(dist / max_possible_dist, 1.0) if max_possible_dist > 0 else 0.0

    return MetricResult(
        distance=dist,
        normalized=normalized,
        metric=DistanceMetric.MANHATTAN,
        details={
            "mean_contribution": sum(dim_diffs) / len(dim_diffs) if dim_diffs else 0.0,
            "total_dimensions": len(vec_a),
        },
    )


def chebyshev_distance(
    vec_a: list[float],
    vec_b: list[float],
    expected_range: tuple[float, float] | None = None,
) -> MetricResult:
    """Calculate Chebyshev (L∞) distance between two vectors."""
    dim_diffs = [abs(a - b) for a, b in zip(vec_a, vec_b)]
    dist = max(dim_diffs) if dim_diffs else 0.0
    max_diff_dim = max(range(len(dim_diffs)), key=lambda i: dim_diffs[i]) if dim_diffs else 0

    if expected_range is not None:
        min_val, max_val = expected_range
        max_possible_dist = max_val - min_val
    else:
        max_possible_dist = 2.0

    normalized = min(dist / max_possible_dist, 1.0) if max_possible_dist > 0 else 0.0

    return MetricResult(
        distance=dist,
        normalized=normalized,
        metric=DistanceMetric.CHEBYSHEV,
        details={
            "max_diff_dimension": max_diff_dim,
            "max_diff_value": dim_diffs[max_diff_dim] if dim_diffs else 0.0,
        },
    )


def mahalanobis_distance(
    vec_a: list[float],
    vec_b: list[float],
    cov_inv: Any | None = None,
) -> MetricResult:
    """
    Calculate Mahalanobis distance (identity covariance only in community edition).

    Falls back to Euclidean distance since we only support identity covariance.
    """
    diff = [a - b for a, b in zip(vec_a, vec_b)]
    dist = math.sqrt(sum(d * d for d in diff))

    n_dims = len(vec_a)
    normalized = min(dist / math.sqrt(n_dims), 1.0) if n_dims > 0 else 0.0

    return MetricResult(
        distance=dist,
        normalized=normalized,
        metric=DistanceMetric.MAHALANOBIS,
        details={
            "using_identity_covariance": True,
            "dimensions": n_dims,
            "squared_distance": dist ** 2,
        },
    )


def calculate_distance(
    vec_a: Any,
    vec_b: Any,
    metric: str | DistanceMetric = "cosine",
    **kwargs: Any,
) -> MetricResult:
    """
    Calculate distance between two vectors using specified metric.

    Args:
        vec_a: First vector
        vec_b: Second vector
        metric: Distance metric to use
        **kwargs: Additional arguments passed to the specific metric function

    Returns:
        MetricResult with distance and normalized score

    Raises:
        ValueError: If metric is not supported or vectors have different lengths
    """
    a = _to_floats(vec_a)
    b = _to_floats(vec_b)

    if len(a) != len(b):
        raise ValueError(f"Shape mismatch: {len(a)} vs {len(b)}")

    if isinstance(metric, str):
        try:
            metric = DistanceMetric(metric.lower())
        except ValueError:
            valid_metrics = [m.value for m in DistanceMetric]
            raise ValueError(f"Unknown metric '{metric}'. Valid metrics: {valid_metrics}")

    metric_functions: dict[DistanceMetric, Callable[..., MetricResult]] = {
        DistanceMetric.COSINE: cosine_distance,
        DistanceMetric.EUCLIDEAN: euclidean_distance,
        DistanceMetric.MANHATTAN: manhattan_distance,
        DistanceMetric.CHEBYSHEV: chebyshev_distance,
        DistanceMetric.MAHALANOBIS: mahalanobis_distance,
    }

    func = metric_functions[metric]
    return func(a, b, **kwargs)


def get_available_metrics() -> list[str]:
    """Return list of available distance metric names."""
    return [m.value for m in DistanceMetric]


# ============================================================================
# Weighted Distance Functions
# ============================================================================


def weighted_euclidean_distance(
    vec_a: list[float],
    vec_b: list[float],
    weights: list[float] | None = None,
    expected_range: tuple[float, float] | None = None,
) -> MetricResult:
    """Calculate weighted Euclidean distance between two vectors."""
    if weights is None:
        w = [1.0] * len(vec_a)
    else:
        w = _to_floats(weights)
        if len(w) != len(vec_a):
            raise ValueError(f"Weight length {len(w)} != vector length {len(vec_a)}")

    # Normalize weights to sum to number of dimensions
    weight_sum = sum(w)
    n = len(w)
    w = [wi * n / weight_sum for wi in w]

    diff_sq = [wi * (a - b) ** 2 for a, b, wi in zip(vec_a, vec_b, w)]
    dist = math.sqrt(sum(diff_sq))

    if expected_range is not None:
        min_val, max_val = expected_range
        max_possible_dist = math.sqrt(sum(wi * ((max_val - min_val) ** 2) for wi in w))
    else:
        max_possible_dist = math.sqrt(sum(wi * 4 for wi in w))

    normalized = min(dist / max_possible_dist, 1.0) if max_possible_dist > 0 else 0.0

    return MetricResult(
        distance=dist,
        normalized=normalized,
        metric=DistanceMetric.EUCLIDEAN,
        details={
            "weighted": True,
        },
    )


def calculate_weighted_distance(
    vec_a: Any,
    vec_b: Any,
    weights: Any | None = None,
    metric: str | DistanceMetric = "euclidean",
    **kwargs: Any,
) -> MetricResult:
    """
    Calculate weighted distance between two vectors.

    Currently supports weighted versions of euclidean.
    For other metrics, falls back to unweighted.

    Args:
        vec_a: First vector
        vec_b: Second vector
        weights: Weight for each dimension
        metric: Distance metric to use
        **kwargs: Additional arguments

    Returns:
        MetricResult with distance score
    """
    a = _to_floats(vec_a)
    b = _to_floats(vec_b)

    if isinstance(metric, str):
        try:
            metric = DistanceMetric(metric.lower())
        except ValueError:
            valid_metrics = [m.value for m in DistanceMetric]
            raise ValueError(f"Unknown metric '{metric}'. Valid metrics: {valid_metrics}")

    if weights is not None and metric == DistanceMetric.EUCLIDEAN:
        w = _to_floats(weights)
        return weighted_euclidean_distance(a, b, weights=w, **kwargs)
    else:
        return calculate_distance(a, b, metric=metric, **kwargs)
