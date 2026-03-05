# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Community Edition — basic single-model verification
"""
CMVK Verification Module — Community Edition

Basic single-model self-check using Python stdlib (difflib).
Preserves the same public API as the full version.
"""

from __future__ import annotations

import difflib
import math
import re
import statistics
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any


class DriftType(Enum):
    """Types of drift/divergence detected between outputs."""

    SEMANTIC = "semantic"
    STRUCTURAL = "structural"
    NUMERICAL = "numerical"
    LEXICAL = "lexical"


@dataclass(frozen=True)
class VerificationScore:
    """
    Immutable result of verification between two outputs.

    Attributes:
        drift_score: Overall drift score between 0.0 (identical) and 1.0 (completely different)
        confidence: Confidence in the score (0.0 to 1.0)
        drift_type: Primary type of drift detected
        details: Dictionary with component scores
        explanation: Optional drift explanation with dimension contributions
    """

    drift_score: float
    confidence: float
    drift_type: DriftType
    details: dict
    explanation: dict | None = None

    def passed(self, threshold: float = 0.3) -> bool:
        """Check if drift is within acceptable threshold."""
        return self.drift_score <= threshold

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "drift_score": self.drift_score,
            "confidence": self.confidence,
            "drift_type": self.drift_type.value,
            "details": self.details,
            "explanation": self.explanation,
        }


@dataclass(frozen=True)
class DriftExplanation:
    """
    Detailed explanation of drift between two vectors.

    Attributes:
        primary_drift_dimension: Index or name of dimension with highest contribution
        dimension_contributions: Mapping of dimension to its contribution percentage
        top_contributors: List of top N contributing dimensions
        metric_used: The distance metric used
        interpretation: Human-readable interpretation of the drift
    """

    primary_drift_dimension: str | int
    dimension_contributions: dict[str | int, float]
    top_contributors: list[tuple[str | int, float]]
    metric_used: str
    interpretation: str

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "primary_drift_dimension": self.primary_drift_dimension,
            "dimension_contributions": self.dimension_contributions,
            "top_contributors": self.top_contributors,
            "metric_used": self.metric_used,
            "interpretation": self.interpretation,
        }


# ============================================================================
# Helper utilities
# ============================================================================


def _clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, value))


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _stdev(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    return statistics.stdev(values)


def _pstdev(values: list[float]) -> float:
    if len(values) < 1:
        return 0.0
    return statistics.pstdev(values)


# ============================================================================
# Core verification functions
# ============================================================================


def verify(output_a: str, output_b: str) -> VerificationScore:
    """
    Calculate drift/hallucination score between two text outputs.

    Uses difflib.SequenceMatcher for basic string similarity.

    Args:
        output_a: First output (typically from model A / generator)
        output_b: Second output (typically from model B / verifier)

    Returns:
        VerificationScore with drift score, confidence, and details
    """
    if not output_a and not output_b:
        return VerificationScore(
            drift_score=0.0,
            confidence=1.0,
            drift_type=DriftType.LEXICAL,
            details={"reason": "both_empty"},
        )

    if not output_a or not output_b:
        return VerificationScore(
            drift_score=1.0,
            confidence=1.0,
            drift_type=DriftType.STRUCTURAL,
            details={"reason": "one_empty"},
        )

    # Character-level similarity via SequenceMatcher
    char_ratio = difflib.SequenceMatcher(None, output_a, output_b).ratio()

    # Word-level similarity
    words_a = output_a.split()
    words_b = output_b.split()
    word_ratio = difflib.SequenceMatcher(None, words_a, words_b).ratio()

    # Structural: line-count ratio
    lines_a = output_a.split("\n")
    lines_b = output_b.split("\n")
    line_ratio = (
        min(len(lines_a), len(lines_b)) / max(len(lines_a), len(lines_b))
        if max(len(lines_a), len(lines_b)) > 0
        else 1.0
    )

    # Weighted combination (similarity → drift)
    similarity = 0.3 * char_ratio + 0.5 * word_ratio + 0.2 * line_ratio
    combined_drift = 1.0 - similarity

    # Determine primary drift type
    scores = {
        DriftType.LEXICAL: 1.0 - char_ratio,
        DriftType.STRUCTURAL: 1.0 - line_ratio,
        DriftType.NUMERICAL: 0.0,  # simple edition has no numerical sub-score
    }
    primary_drift = max(scores, key=lambda k: scores[k])

    # Confidence from agreement between sub-scores
    score_values = list(scores.values())
    confidence = 1.0 - _pstdev(score_values) if len(score_values) > 1 else 0.8

    return VerificationScore(
        drift_score=_clamp(combined_drift),
        confidence=_clamp(confidence),
        drift_type=primary_drift,
        details={
            "char_similarity": char_ratio,
            "word_similarity": word_ratio,
            "line_ratio": line_ratio,
        },
    )


def verify_embeddings(
    embedding_a: Any,
    embedding_b: Any,
    metric: str = "cosine",
    weights: Any | None = None,
    threshold_profile: str | None = None,
    explain: bool = False,
    dimension_names: list[str] | None = None,
    audit_trail: Any | None = None,
) -> VerificationScore:
    """
    Calculate drift score between two embedding vectors.

    Basic implementation using Python stdlib only.

    Args:
        embedding_a: Embedding vector for output A
        embedding_b: Embedding vector for output B
        metric: Distance metric (cosine | euclidean). Others fall back to cosine.
        weights: Optional per-dimension weights (list of floats)
        threshold_profile: Ignored in community edition
        explain: If True, include basic drift explanation
        dimension_names: Optional names for dimensions
        audit_trail: Ignored in community edition

    Returns:
        VerificationScore with drift score and confidence
    """
    from .metrics import calculate_distance, calculate_weighted_distance

    vec_a = list(embedding_a) if not isinstance(embedding_a, list) else embedding_a
    vec_b = list(embedding_b) if not isinstance(embedding_b, list) else embedding_b

    # Shape validation
    if len(vec_a) != len(vec_b):
        return VerificationScore(
            drift_score=1.0,
            confidence=0.5,
            drift_type=DriftType.STRUCTURAL,
            details={"reason": "shape_mismatch", "len_a": len(vec_a), "len_b": len(vec_b)},
        )

    # Calculate distance
    if weights is not None:
        metric_result = calculate_weighted_distance(vec_a, vec_b, weights=weights, metric=metric)
    else:
        metric_result = calculate_distance(vec_a, vec_b, metric=metric)

    drift_score = _clamp(metric_result.normalized)
    confidence = _calculate_embedding_confidence(vec_a, vec_b)

    # Build explanation if requested
    explanation_dict = None
    if explain:
        explanation = _build_drift_explanation(
            vec_a, vec_b, metric_result, weights, dimension_names
        )
        explanation_dict = explanation.to_dict()

    details: dict[str, Any] = {
        "metric": metric,
        "raw_distance": metric_result.distance,
        "normalized_distance": metric_result.normalized,
        **metric_result.details,
    }

    return VerificationScore(
        drift_score=drift_score,
        confidence=confidence,
        drift_type=DriftType.SEMANTIC,
        details=details,
        explanation=explanation_dict,
    )


def verify_embeddings_batch(
    embeddings_a: Sequence[Any],
    embeddings_b: Sequence[Any],
    metric: str = "cosine",
    weights: Any | None = None,
    threshold_profile: str | None = None,
    explain: bool = False,
    dimension_names: list[str] | None = None,
    audit_trail: Any | None = None,
) -> list[VerificationScore]:
    """
    Verify multiple embedding pairs.

    Args:
        embeddings_a: Sequence of embedding vectors from source A
        embeddings_b: Sequence of embedding vectors from source B
        metric: Distance metric (applied to all pairs)
        weights: Dimensional weights (applied to all pairs)
        threshold_profile: Ignored in community edition
        explain: Whether to include explanations
        dimension_names: Optional dimension names for explainability
        audit_trail: Ignored in community edition

    Returns:
        List of VerificationScore for each pair

    Raises:
        ValueError: If sequence lengths don't match
    """
    if len(embeddings_a) != len(embeddings_b):
        raise ValueError(
            f"Length mismatch: embeddings_a has {len(embeddings_a)} items, "
            f"embeddings_b has {len(embeddings_b)} items"
        )

    return [
        verify_embeddings(
            a, b,
            metric=metric,
            weights=weights,
            threshold_profile=threshold_profile,
            explain=explain,
            dimension_names=dimension_names,
            audit_trail=audit_trail,
        )
        for a, b in zip(embeddings_a, embeddings_b)
    ]


def aggregate_embedding_scores(
    scores: Sequence[VerificationScore],
    threshold_profile: str | None = None,
) -> dict[str, Any]:
    """
    Aggregate multiple embedding verification scores.

    Args:
        scores: Sequence of VerificationScore objects
        threshold_profile: Ignored in community edition

    Returns:
        Dictionary with aggregate statistics and pass rates
    """
    if not scores:
        return {"count": 0}

    drift_values = sorted(s.drift_score for s in scores)
    confidence_values = [s.confidence for s in scores]

    passed_count = sum(1 for s in scores if s.drift_score <= 0.3)

    n = len(drift_values)
    p95_idx = min(int(n * 0.95), n - 1)

    return {
        "count": n,
        "passed_count": passed_count,
        "failed_count": n - passed_count,
        "pass_rate": passed_count / n,
        "mean_drift": _mean(drift_values),
        "std_drift": _pstdev(drift_values),
        "min_drift": drift_values[0],
        "max_drift": drift_values[-1],
        "median_drift": statistics.median(drift_values),
        "mean_confidence": _mean(confidence_values),
        "p95_drift": drift_values[p95_idx],
    }


def verify_distributions(dist_a: Any, dist_b: Any) -> VerificationScore:
    """
    Calculate drift between two probability distributions using basic KL divergence.

    Args:
        dist_a: First probability distribution (list/tuple of floats)
        dist_b: Second probability distribution

    Returns:
        VerificationScore with distribution-based drift score
    """
    p = list(dist_a)
    q = list(dist_b)

    eps = 1e-10
    sum_p = sum(p) + eps
    sum_q = sum(q) + eps
    p = [max(v / sum_p, eps) for v in p]
    q = [max(v / sum_q, eps) for v in q]

    # KL divergence
    kl_div = sum(pi * math.log(pi / qi) for pi, qi in zip(p, q))

    # Jensen-Shannon divergence
    m = [0.5 * (pi + qi) for pi, qi in zip(p, q)]
    js_div = 0.5 * sum(pi * math.log(pi / mi) for pi, mi in zip(p, m)) + \
             0.5 * sum(qi * math.log(qi / mi) for qi, mi in zip(q, m))

    # Total variation distance
    tv_dist = 0.5 * sum(abs(pi - qi) for pi, qi in zip(p, q))

    drift_score = js_div / math.log(2)  # Normalize to [0, 1]

    return VerificationScore(
        drift_score=_clamp(drift_score),
        confidence=0.9,
        drift_type=DriftType.NUMERICAL,
        details={
            "kl_divergence": kl_div,
            "js_divergence": js_div,
            "total_variation": tv_dist,
        },
    )


def verify_sequences(seq_a: Sequence[str], seq_b: Sequence[str]) -> VerificationScore:
    """
    Calculate drift between two sequences of tokens/items.

    Args:
        seq_a: First sequence
        seq_b: Second sequence

    Returns:
        VerificationScore with sequence-based drift score
    """
    if not seq_a and not seq_b:
        return VerificationScore(
            drift_score=0.0,
            confidence=1.0,
            drift_type=DriftType.LEXICAL,
            details={"reason": "both_empty"},
        )

    # Edit distance via SequenceMatcher
    sm = difflib.SequenceMatcher(None, list(seq_a), list(seq_b))
    seq_ratio = sm.ratio()
    max_len = max(len(seq_a), len(seq_b))
    # Approximate edit distance from ratio
    edit_dist = round(max_len * (1.0 - seq_ratio))
    normalized_edit = edit_dist / max_len if max_len > 0 else 0.0

    # Jaccard similarity (set-based)
    set_a = set(seq_a)
    set_b = set(seq_b)
    intersection = len(set_a & set_b)
    union = len(set_a | set_b)
    jaccard = intersection / union if union > 0 else 1.0
    jaccard_drift = 1.0 - jaccard

    # LCS ratio from SequenceMatcher matching blocks
    matching = sum(block.size for block in sm.get_matching_blocks())
    total_len = len(seq_a) + len(seq_b)
    lcs_ratio = 2 * matching / total_len if total_len > 0 else 1.0
    lcs_drift = 1.0 - lcs_ratio

    drift_score = 0.4 * normalized_edit + 0.3 * jaccard_drift + 0.3 * lcs_drift

    return VerificationScore(
        drift_score=_clamp(drift_score),
        confidence=0.85,
        drift_type=DriftType.STRUCTURAL,
        details={
            "edit_distance": edit_dist,
            "normalized_edit": normalized_edit,
            "jaccard_similarity": jaccard,
            "lcs_ratio": lcs_ratio,
        },
    )


# ============================================================================
# Batch verification functions
# ============================================================================


def verify_batch(outputs_a: Sequence[str], outputs_b: Sequence[str]) -> list[VerificationScore]:
    """
    Verify multiple output pairs.

    Args:
        outputs_a: Sequence of outputs from source A
        outputs_b: Sequence of outputs from source B (same length as outputs_a)

    Returns:
        List of VerificationScore for each pair
    """
    if len(outputs_a) != len(outputs_b):
        raise ValueError(
            f"Length mismatch: outputs_a has {len(outputs_a)} items, "
            f"outputs_b has {len(outputs_b)} items"
        )

    return [verify(a, b) for a, b in zip(outputs_a, outputs_b)]


def aggregate_scores(scores: Sequence[VerificationScore]) -> dict:
    """
    Aggregate multiple verification scores into summary statistics.

    Args:
        scores: Sequence of VerificationScore objects

    Returns:
        Dictionary with aggregate statistics
    """
    if not scores:
        return {"count": 0}

    drift_values = [s.drift_score for s in scores]
    confidence_values = [s.confidence for s in scores]

    drift_types: dict[str, int] = {}
    for s in scores:
        drift_types[s.drift_type.value] = drift_types.get(s.drift_type.value, 0) + 1

    return {
        "count": len(scores),
        "mean_drift": _mean(drift_values),
        "std_drift": _pstdev(drift_values),
        "min_drift": min(drift_values),
        "max_drift": max(drift_values),
        "median_drift": statistics.median(drift_values),
        "mean_confidence": _mean(confidence_values),
        "drift_type_distribution": drift_types,
    }


# ============================================================================
# Internal helpers
# ============================================================================


def _calculate_embedding_confidence(vec_a: list[float], vec_b: list[float]) -> float:
    """Calculate confidence score for embedding verification."""
    confidence = 0.9

    if len(vec_a) < 10:
        confidence *= 0.9

    norm_a = math.sqrt(sum(x * x for x in vec_a))
    norm_b = math.sqrt(sum(x * x for x in vec_b))
    if norm_a > 0 and norm_b > 0:
        magnitude_ratio = min(norm_a, norm_b) / max(norm_a, norm_b)
        if magnitude_ratio < 0.5:
            confidence *= 0.85

    if norm_a < 1e-6 or norm_b < 1e-6:
        confidence *= 0.7

    return _clamp(confidence)


def _build_drift_explanation(
    vec_a: list[float],
    vec_b: list[float],
    metric_result: Any,
    weights: Any | None,
    dimension_names: list[str] | None,
) -> DriftExplanation:
    """Build basic drift explanation."""
    diff = [abs(a - b) for a, b in zip(vec_a, vec_b)]

    if weights is not None:
        w = list(weights) if not isinstance(weights, list) else weights
        weighted_diff = [d * wt for d, wt in zip(diff, w)]
    else:
        weighted_diff = diff

    total_diff = sum(weighted_diff)
    contributions = (
        [d / total_diff for d in weighted_diff] if total_diff > 0 else [0.0] * len(diff)
    )

    if dimension_names and len(dimension_names) == len(contributions):
        contrib_dict: dict[str | int, float] = {
            name: c for name, c in zip(dimension_names, contributions)
        }
    else:
        contrib_dict = {i: c for i, c in enumerate(contributions)}

    sorted_contribs = sorted(contrib_dict.items(), key=lambda x: x[1], reverse=True)
    primary_dim = sorted_contribs[0][0] if sorted_contribs else 0
    top_contributors = sorted_contribs[:5]

    dim_name = primary_dim if isinstance(primary_dim, str) else f"dimension {primary_dim}"
    interpretation = f"Primary drift in {dim_name}."

    return DriftExplanation(
        primary_drift_dimension=primary_dim,
        dimension_contributions=contrib_dict,
        top_contributors=top_contributors,
        metric_used=metric_result.metric.value,
        interpretation=interpretation,
    )
