# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
CMVK Distance Metrics Module

Provides configurable distance metrics for embedding verification.
All functions are pure (no side effects) and use only numpy/scipy.

Supported Metrics:
    - cosine: Cosine distance (default, normalizes vectors)
    - euclidean: Euclidean distance (preserves magnitude)
    - manhattan: Manhattan/L1 distance
    - chebyshev: Chebyshev/L∞ distance (max absolute difference)
    - mahalanobis: Mahalanobis distance (accounts for correlation)
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import Any

import numpy as np
from numpy.typing import ArrayLike

try:
    from scipy import spatial

    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False


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


def cosine_distance(vec_a: np.ndarray, vec_b: np.ndarray) -> MetricResult:
    """
    Calculate cosine distance between two vectors.

    Cosine distance = 1 - cosine_similarity
    Range: [0, 2] where 0 = identical direction, 1 = orthogonal, 2 = opposite

    Note: Cosine distance normalizes vectors, losing magnitude information.
    Use Euclidean distance when magnitude matters.

    Args:
        vec_a: First vector
        vec_b: Second vector

    Returns:
        MetricResult with cosine distance
    """
    if HAS_SCIPY:
        dist = spatial.distance.cosine(vec_a, vec_b)
    else:
        dot = np.dot(vec_a, vec_b)
        norm_a = np.linalg.norm(vec_a)
        norm_b = np.linalg.norm(vec_b)
        dist = 1.0 if norm_a == 0 or norm_b == 0 else 1.0 - dot / (norm_a * norm_b)

    # Handle numerical precision issues
    dist = float(np.clip(dist, 0.0, 2.0))

    return MetricResult(
        distance=dist,
        normalized=dist / 2.0,  # Normalize to [0, 1]
        metric=DistanceMetric.COSINE,
        details={
            "cosine_similarity": 1.0 - dist,
            "norm_a": float(np.linalg.norm(vec_a)),
            "norm_b": float(np.linalg.norm(vec_b)),
        },
    )


def euclidean_distance(
    vec_a: np.ndarray, vec_b: np.ndarray, expected_range: tuple[float, float] | None = None
) -> MetricResult:
    """
    Calculate Euclidean (L2) distance between two vectors.

    Unlike cosine distance, Euclidean distance preserves magnitude information.
    This is critical for detecting drift in absolute values (e.g., NDVI scores).

    Args:
        vec_a: First vector
        vec_b: Second vector
        expected_range: Optional (min, max) expected range for normalization.
                       If None, uses vector dimension for normalization.

    Returns:
        MetricResult with Euclidean distance
    """
    if HAS_SCIPY:
        dist = spatial.distance.euclidean(vec_a, vec_b)
    else:
        dist = float(np.linalg.norm(vec_a - vec_b))

    # Calculate per-dimension differences
    dim_diffs = np.abs(vec_a - vec_b)
    max_diff_dim = int(np.argmax(dim_diffs))
    max_diff_value = float(dim_diffs[max_diff_dim])

    # Normalization
    if expected_range is not None:
        min_val, max_val = expected_range
        max_possible_dist = np.sqrt(len(vec_a)) * (max_val - min_val)
    else:
        # Assume normalized embeddings in [-1, 1]
        max_possible_dist = np.sqrt(len(vec_a) * 4)

    normalized = min(dist / max_possible_dist, 1.0) if max_possible_dist > 0 else 0.0

    return MetricResult(
        distance=dist,
        normalized=float(normalized),
        metric=DistanceMetric.EUCLIDEAN,
        details={
            "max_diff_dimension": max_diff_dim,
            "max_diff_value": max_diff_value,
            "per_dimension_diff": dim_diffs.tolist() if len(dim_diffs) <= 20 else None,
            "mean_diff": float(np.mean(dim_diffs)),
            "std_diff": float(np.std(dim_diffs)),
        },
    )


def manhattan_distance(
    vec_a: np.ndarray, vec_b: np.ndarray, expected_range: tuple[float, float] | None = None
) -> MetricResult:
    """
    Calculate Manhattan (L1/city-block) distance between two vectors.

    Sum of absolute differences across all dimensions.
    More robust to outliers than Euclidean distance.

    Args:
        vec_a: First vector
        vec_b: Second vector
        expected_range: Optional (min, max) expected range for normalization.

    Returns:
        MetricResult with Manhattan distance
    """
    if HAS_SCIPY:
        dist = spatial.distance.cityblock(vec_a, vec_b)
    else:
        dist = float(np.sum(np.abs(vec_a - vec_b)))

    # Per-dimension contributions
    dim_diffs = np.abs(vec_a - vec_b)
    contributions = dim_diffs / dist if dist > 0 else np.zeros_like(dim_diffs)

    # Normalization
    if expected_range is not None:
        min_val, max_val = expected_range
        max_possible_dist = len(vec_a) * (max_val - min_val)
    else:
        max_possible_dist = len(vec_a) * 2  # Assuming [-1, 1] range

    normalized = min(dist / max_possible_dist, 1.0) if max_possible_dist > 0 else 0.0

    return MetricResult(
        distance=float(dist),
        normalized=float(normalized),
        metric=DistanceMetric.MANHATTAN,
        details={
            "per_dimension_contributions": (
                contributions.tolist() if len(contributions) <= 20 else None
            ),
            "mean_contribution": float(np.mean(dim_diffs)),
            "total_dimensions": len(vec_a),
        },
    )


def chebyshev_distance(
    vec_a: np.ndarray, vec_b: np.ndarray, expected_range: tuple[float, float] | None = None
) -> MetricResult:
    """
    Calculate Chebyshev (L∞) distance between two vectors.

    Maximum absolute difference across any single dimension.
    Useful for detecting if ANY dimension has significant drift.

    Args:
        vec_a: First vector
        vec_b: Second vector
        expected_range: Optional (min, max) expected range for normalization.

    Returns:
        MetricResult with Chebyshev distance
    """
    if HAS_SCIPY:
        dist = spatial.distance.chebyshev(vec_a, vec_b)
    else:
        dist = float(np.max(np.abs(vec_a - vec_b)))

    dim_diffs = np.abs(vec_a - vec_b)
    max_diff_dim = int(np.argmax(dim_diffs))

    # Normalization
    if expected_range is not None:
        min_val, max_val = expected_range
        max_possible_dist = max_val - min_val
    else:
        max_possible_dist = 2.0  # Assuming [-1, 1] range

    normalized = min(dist / max_possible_dist, 1.0) if max_possible_dist > 0 else 0.0

    return MetricResult(
        distance=float(dist),
        normalized=float(normalized),
        metric=DistanceMetric.CHEBYSHEV,
        details={
            "max_diff_dimension": max_diff_dim,
            "max_diff_value": float(dim_diffs[max_diff_dim]),
            "second_max_diff": (
                float(np.partition(dim_diffs, -2)[-2]) if len(dim_diffs) > 1 else 0.0
            ),
        },
    )


def mahalanobis_distance(
    vec_a: np.ndarray, vec_b: np.ndarray, cov_inv: np.ndarray | None = None
) -> MetricResult:
    """
    Calculate Mahalanobis distance between two vectors.

    Accounts for correlation between dimensions using covariance matrix.
    Useful when dimensions are correlated (e.g., related environmental factors).

    Args:
        vec_a: First vector
        vec_b: Second vector
        cov_inv: Inverse of covariance matrix. If None, uses identity (= Euclidean).

    Returns:
        MetricResult with Mahalanobis distance
    """
    diff = vec_a - vec_b

    if cov_inv is None:
        # Without covariance info, use identity matrix (equivalent to Euclidean)
        cov_inv = np.eye(len(vec_a))
        using_identity = True
    else:
        using_identity = False

    if HAS_SCIPY:
        try:
            dist = spatial.distance.mahalanobis(vec_a, vec_b, cov_inv)
        except Exception:
            # Fallback if scipy fails
            dist = float(np.sqrt(diff @ cov_inv @ diff))
    else:
        dist = float(np.sqrt(diff @ cov_inv @ diff))

    # For Mahalanobis, normalization depends on the covariance structure
    # Chi-squared with n degrees of freedom has expected value n
    n_dims = len(vec_a)
    # Normalize using expected value under null hypothesis
    normalized = min(dist / np.sqrt(n_dims), 1.0)

    return MetricResult(
        distance=float(dist),
        normalized=float(normalized),
        metric=DistanceMetric.MAHALANOBIS,
        details={
            "using_identity_covariance": using_identity,
            "dimensions": n_dims,
            "squared_distance": float(dist**2),
        },
    )


def calculate_distance(
    vec_a: ArrayLike,
    vec_b: ArrayLike,
    metric: str | DistanceMetric = "cosine",
    **kwargs: Any,
) -> MetricResult:
    """
    Calculate distance between two vectors using specified metric.

    This is the primary entry point for distance calculations.

    Args:
        vec_a: First vector
        vec_b: Second vector
        metric: Distance metric to use. One of:
            - "cosine": Cosine distance (default)
            - "euclidean": Euclidean/L2 distance
            - "manhattan": Manhattan/L1 distance
            - "chebyshev": Chebyshev/L∞ distance
            - "mahalanobis": Mahalanobis distance
        **kwargs: Additional arguments passed to the specific metric function

    Returns:
        MetricResult with distance and normalized score

    Raises:
        ValueError: If metric is not supported or vectors have different shapes
    """
    vec_a = np.asarray(vec_a, dtype=np.float64)
    vec_b = np.asarray(vec_b, dtype=np.float64)

    if vec_a.shape != vec_b.shape:
        raise ValueError(f"Shape mismatch: {vec_a.shape} vs {vec_b.shape}")

    # Convert string to enum
    if isinstance(metric, str):
        try:
            metric = DistanceMetric(metric.lower())
        except ValueError:
            valid_metrics = [m.value for m in DistanceMetric]
            raise ValueError(f"Unknown metric '{metric}'. Valid metrics: {valid_metrics}")

    # Dispatch to appropriate function
    metric_functions: dict[DistanceMetric, Callable[..., MetricResult]] = {
        DistanceMetric.COSINE: cosine_distance,
        DistanceMetric.EUCLIDEAN: euclidean_distance,
        DistanceMetric.MANHATTAN: manhattan_distance,
        DistanceMetric.CHEBYSHEV: chebyshev_distance,
        DistanceMetric.MAHALANOBIS: mahalanobis_distance,
    }

    func = metric_functions[metric]
    return func(vec_a, vec_b, **kwargs)


def get_available_metrics() -> list[str]:
    """Return list of available distance metric names."""
    return [m.value for m in DistanceMetric]


# ============================================================================
# Weighted Distance Functions
# ============================================================================


def weighted_euclidean_distance(
    vec_a: np.ndarray,
    vec_b: np.ndarray,
    weights: np.ndarray | list[float] | None = None,
    expected_range: tuple[float, float] | None = None,
) -> MetricResult:
    """
    Calculate weighted Euclidean distance between two vectors.

    Allows certain dimensions to contribute more to the overall distance.

    Args:
        vec_a: First vector
        vec_b: Second vector
        weights: Weight for each dimension. If None, uses uniform weights.
        expected_range: Optional (min, max) expected range for normalization.

    Returns:
        MetricResult with weighted Euclidean distance
    """
    weights_arr: np.ndarray
    if weights is None:
        weights_arr = np.ones(len(vec_a))
    else:
        weights_arr = np.asarray(weights, dtype=np.float64)
        if len(weights_arr) != len(vec_a):
            raise ValueError(f"Weight length {len(weights_arr)} != vector length {len(vec_a)}")

    # Normalize weights to sum to number of dimensions (preserve scale)
    weight_sum = float(np.sum(weights_arr))
    weights_arr = weights_arr * len(weights_arr) / weight_sum

    diff = vec_a - vec_b
    weighted_diff_sq = weights_arr * (diff**2)
    dist = float(np.sqrt(np.sum(weighted_diff_sq)))

    # Per-dimension weighted contributions
    weighted_contributions = weighted_diff_sq / (dist**2) if dist > 0 else np.zeros_like(diff)

    # Normalization
    if expected_range is not None:
        min_val, max_val = expected_range
        max_possible_dist = np.sqrt(np.sum(weights_arr * ((max_val - min_val) ** 2)))
    else:
        max_possible_dist = np.sqrt(np.sum(weights_arr * 4))  # Assuming [-1, 1] range

    normalized = min(dist / max_possible_dist, 1.0) if max_possible_dist > 0 else 0.0

    return MetricResult(
        distance=dist,
        normalized=float(normalized),
        metric=DistanceMetric.EUCLIDEAN,
        details={
            "weighted": True,
            "weights": weights_arr.tolist() if len(weights_arr) <= 20 else None,
            "weighted_contributions": (
                weighted_contributions.tolist() if len(weighted_contributions) <= 20 else None
            ),
            "top_contributing_dimension": int(np.argmax(weighted_contributions)),
            "top_contribution_value": float(np.max(weighted_contributions)),
        },
    )


def calculate_weighted_distance(
    vec_a: ArrayLike,
    vec_b: ArrayLike,
    weights: ArrayLike | None = None,
    metric: str | DistanceMetric = "euclidean",
    **kwargs: Any,
) -> MetricResult:
    """
    Calculate weighted distance between two vectors.

    Currently supports weighted versions of:
    - euclidean: Weighted Euclidean distance

    For other metrics, weights are not applied (falls back to unweighted).

    Args:
        vec_a: First vector
        vec_b: Second vector
        weights: Weight for each dimension
        metric: Distance metric to use
        **kwargs: Additional arguments

    Returns:
        MetricResult with distance score
    """
    vec_a = np.asarray(vec_a, dtype=np.float64)
    vec_b = np.asarray(vec_b, dtype=np.float64)

    if isinstance(metric, str):
        try:
            metric = DistanceMetric(metric.lower())
        except ValueError:
            valid_metrics = [m.value for m in DistanceMetric]
            raise ValueError(f"Unknown metric '{metric}'. Valid metrics: {valid_metrics}")

    if weights is not None and metric == DistanceMetric.EUCLIDEAN:
        return weighted_euclidean_distance(vec_a, vec_b, weights=weights, **kwargs)
    else:
        # Fall back to unweighted calculation
        return calculate_distance(vec_a, vec_b, metric=metric, **kwargs)
