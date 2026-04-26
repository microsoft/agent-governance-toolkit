# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
CMVK Verification Module - Pure Mathematical Functions

This module provides pure functions for calculating drift/hallucination scores
between two outputs. These functions have no side effects and use only
numpy/scipy for mathematical operations.

Layer 1: The Primitive - Mathematical and adversarial verification.

Enhanced Features (v0.2.0):
    - Configurable distance metrics (cosine, euclidean, manhattan, etc.)
    - Dimensional weighting for importance-based drift calculation
    - Threshold profiles for domain-specific verification
    - Explainable drift with per-dimension contributions
    - Batch verification for efficiency
    - Audit trail integration
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any

import numpy as np
from numpy.typing import ArrayLike

try:
    from scipy import stats

    HAS_SCIPY = True
except ImportError:
    HAS_SCIPY = False

if TYPE_CHECKING:
    from .audit import AuditTrail


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
        explanation: Optional drift explanation with dimension contributions (CMVK-010)
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
    Detailed explanation of drift between two vectors (CMVK-010).

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


def verify(output_a: str, output_b: str) -> VerificationScore:
    """
    Calculate drift/hallucination score between two outputs.

    This is the primary verification function - a pure function with no side effects.
    Takes two outputs and returns a score indicating their divergence.

    Args:
        output_a: First output (typically from model A / generator)
        output_b: Second output (typically from model B / verifier)

    Returns:
        VerificationScore with drift score, confidence, and details

    Example:
        >>> score = verify("def add(a, b): return a + b", "def add(x, y): return x + y")
        >>> score.drift_score  # Low score - semantically similar
        0.15
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

    # Calculate multiple drift components
    lexical_drift = _lexical_drift(output_a, output_b)
    structural_drift = _structural_drift(output_a, output_b)
    numerical_drift = _numerical_drift(output_a, output_b)

    # Weighted combination
    weights = {"lexical": 0.3, "structural": 0.4, "numerical": 0.3}

    combined_drift = (
        weights["lexical"] * lexical_drift["score"]
        + weights["structural"] * structural_drift["score"]
        + weights["numerical"] * numerical_drift["score"]
    )

    # Determine primary drift type
    scores = {
        DriftType.LEXICAL: lexical_drift["score"],
        DriftType.STRUCTURAL: structural_drift["score"],
        DriftType.NUMERICAL: numerical_drift["score"],
    }
    primary_drift = max(scores, key=lambda k: scores[k])

    # Calculate confidence based on agreement between methods
    score_values = list(scores.values())
    confidence = 1.0 - np.std(score_values) if len(score_values) > 1 else 0.8

    return VerificationScore(
        drift_score=float(np.clip(combined_drift, 0.0, 1.0)),
        confidence=float(np.clip(confidence, 0.0, 1.0)),
        drift_type=primary_drift,
        details={
            "lexical": lexical_drift,
            "structural": structural_drift,
            "numerical": numerical_drift,
            "weights": weights,
        },
    )


def verify_embeddings(
    embedding_a: ArrayLike,
    embedding_b: ArrayLike,
    metric: str = "cosine",
    weights: ArrayLike | None = None,
    threshold_profile: str | None = None,
    explain: bool = False,
    dimension_names: list[str] | None = None,
    audit_trail: AuditTrail | None = None,
) -> VerificationScore:
    """
    Calculate drift score between two embedding vectors.

    Enhanced verification function with configurable metrics, weighting,
    threshold profiles, and explainability (CMVK-001 through CMVK-010).

    Args:
        embedding_a: Embedding vector for output A (e.g., claimed values)
        embedding_b: Embedding vector for output B (e.g., observed values)
        metric: Distance metric to use. Options:
            - "cosine": Cosine distance (default, normalizes vectors)
            - "euclidean": Euclidean distance (preserves magnitude - CMVK-001)
            - "manhattan": Manhattan/L1 distance
            - "chebyshev": Maximum absolute difference
            - "mahalanobis": Mahalanobis distance
        weights: Optional weights for each dimension (CMVK-008).
                Higher weights increase that dimension's contribution to drift.
        threshold_profile: Name of threshold profile to use (CMVK-005).
                         Options: "carbon", "financial", "medical", "general", "strict"
        explain: If True, include detailed drift explanation (CMVK-010)
        dimension_names: Optional names for dimensions (for explainability)
        audit_trail: Optional AuditTrail instance for logging (CMVK-006)

    Returns:
        VerificationScore with drift score, confidence, and optional explanation

    Example:
        >>> # Basic usage
        >>> score = verify_embeddings(claim_vec, obs_vec)

        >>> # With Euclidean distance for magnitude-sensitive comparison
        >>> score = verify_embeddings(
        ...     claim_vec, obs_vec,
        ...     metric="euclidean",
        ...     threshold_profile="carbon",
        ...     explain=True
        ... )

        >>> # With dimensional weighting
        >>> score = verify_embeddings(
        ...     claim_vec, obs_vec,
        ...     metric="euclidean",
        ...     weights=[0.6, 0.4],  # NDVI more important than carbon
        ...     explain=True,
        ...     dimension_names=["ndvi", "carbon_stock"]
        ... )
    """
    from .metrics import calculate_distance, calculate_weighted_distance

    vec_a = np.asarray(embedding_a, dtype=np.float64)
    vec_b = np.asarray(embedding_b, dtype=np.float64)

    # Load threshold profile if specified
    profile = None
    if threshold_profile:
        from .profiles import get_profile

        profile = get_profile(threshold_profile)
        # Use profile's default metric if none specified
        if metric == "cosine" and profile.default_metric != "cosine":
            metric = profile.default_metric

    # Shape validation
    if vec_a.shape != vec_b.shape:
        result = VerificationScore(
            drift_score=1.0,
            confidence=0.5,
            drift_type=DriftType.STRUCTURAL,
            details={"reason": "shape_mismatch", "shape_a": vec_a.shape, "shape_b": vec_b.shape},
        )
        if audit_trail:
            _log_to_audit(audit_trail, vec_a, vec_b, result, metric, threshold_profile)
        return result

    # Calculate distance with appropriate function
    if weights is not None:
        metric_result = calculate_weighted_distance(vec_a, vec_b, weights=weights, metric=metric)
    else:
        metric_result = calculate_distance(vec_a, vec_b, metric=metric)

    # Build drift score from normalized distance
    drift_score = float(np.clip(metric_result.normalized, 0.0, 1.0))

    # Calculate confidence based on vector properties
    confidence = _calculate_embedding_confidence(vec_a, vec_b)

    # Build explanation if requested
    explanation_dict = None
    if explain:
        explanation = _build_drift_explanation(
            vec_a, vec_b, metric_result, weights, dimension_names
        )
        explanation_dict = explanation.to_dict()

    # Build details
    details = {
        "metric": metric,
        "raw_distance": metric_result.distance,
        "normalized_distance": metric_result.normalized,
        **metric_result.details,
    }

    # Add profile info if used
    if profile:
        passed = profile.is_within_threshold(drift_score, confidence)
        severity = profile.get_severity(drift_score)
        details["profile"] = {
            "name": profile.name,
            "drift_threshold": profile.drift_threshold,
            "passed": passed,
            "severity": severity,
        }

    result = VerificationScore(
        drift_score=drift_score,
        confidence=confidence,
        drift_type=DriftType.SEMANTIC,
        details=details,
        explanation=explanation_dict,
    )

    # Log to audit trail if provided
    if audit_trail:
        _log_to_audit(audit_trail, vec_a, vec_b, result, metric, threshold_profile)

    return result


def verify_embeddings_batch(
    embeddings_a: Sequence[ArrayLike],
    embeddings_b: Sequence[ArrayLike],
    metric: str = "cosine",
    weights: ArrayLike | None = None,
    threshold_profile: str | None = None,
    explain: bool = False,
    dimension_names: list[str] | None = None,
    audit_trail: AuditTrail | None = None,
) -> list[VerificationScore]:
    """
    Verify multiple embedding pairs efficiently (CMVK-004).

    Processes all pairs with consistent settings and optional audit logging.

    Args:
        embeddings_a: Sequence of embedding vectors from source A
        embeddings_b: Sequence of embedding vectors from source B
        metric: Distance metric (applied to all pairs)
        weights: Dimensional weights (applied to all pairs)
        threshold_profile: Threshold profile name
        explain: Whether to include explanations
        dimension_names: Optional dimension names for explainability
        audit_trail: Optional AuditTrail for logging

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

    results = []
    for vec_a, vec_b in zip(embeddings_a, embeddings_b, strict=True):
        score = verify_embeddings(
            vec_a,
            vec_b,
            metric=metric,
            weights=weights,
            threshold_profile=threshold_profile,
            explain=explain,
            dimension_names=dimension_names,
            audit_trail=audit_trail,
        )
        results.append(score)

    return results


def aggregate_embedding_scores(
    scores: Sequence[VerificationScore],
    threshold_profile: str | None = None,
) -> dict[str, Any]:
    """
    Aggregate multiple embedding verification scores with profile context.

    Args:
        scores: Sequence of VerificationScore objects
        threshold_profile: Optional profile for pass/fail classification

    Returns:
        Dictionary with aggregate statistics and pass rates
    """
    if not scores:
        return {"count": 0}

    profile = None
    if threshold_profile:
        from .profiles import get_profile

        profile = get_profile(threshold_profile)

    drift_values = [s.drift_score for s in scores]
    confidence_values = [s.confidence for s in scores]

    # Calculate pass/fail if profile available
    if profile:
        passed_count = sum(
            1 for s in scores if profile.is_within_threshold(s.drift_score, s.confidence)
        )
        severity_counts: dict[str, int] = {
            "pass": 0,
            "warning": 0,
            "critical": 0,
            "severe": 0,
        }
        for s in scores:
            severity = profile.get_severity(s.drift_score)
            severity_counts[severity] += 1
    else:
        passed_count = sum(1 for s in scores if s.drift_score <= 0.3)
        severity_counts = {}

    result: dict[str, Any] = {
        "count": len(scores),
        "passed_count": passed_count,
        "failed_count": len(scores) - passed_count,
        "pass_rate": passed_count / len(scores),
        "mean_drift": float(np.mean(drift_values)),
        "std_drift": float(np.std(drift_values)),
        "min_drift": float(np.min(drift_values)),
        "max_drift": float(np.max(drift_values)),
        "median_drift": float(np.median(drift_values)),
        "mean_confidence": float(np.mean(confidence_values)),
        "p95_drift": float(np.percentile(drift_values, 95)),
    }

    if severity_counts and profile:
        result["severity_distribution"] = severity_counts
        result["profile_used"] = profile.name

    return result


# ============================================================================
# Explainability Functions (CMVK-010)
# ============================================================================


def _build_drift_explanation(
    vec_a: np.ndarray,
    vec_b: np.ndarray,
    metric_result: Any,
    weights: ArrayLike | None,
    dimension_names: list[str] | None,
) -> DriftExplanation:
    """Build detailed drift explanation."""
    diff = np.abs(vec_a - vec_b)

    # Apply weights if provided
    if weights is not None:
        weights_arr = np.asarray(weights, dtype=np.float64)
        weighted_diff = diff * weights_arr
    else:
        weighted_diff = diff

    # Calculate per-dimension contributions
    total_diff = np.sum(weighted_diff)
    contributions = weighted_diff / total_diff if total_diff > 0 else np.zeros_like(diff)

    # Map contributions to names or indices
    contrib_dict: dict[str | int, float]
    sorted_contribs: list[tuple[str | int, float]]
    primary_dim: str | int

    if dimension_names and len(dimension_names) == len(contributions):
        contrib_dict = {
            name: float(c) for name, c in zip(dimension_names, contributions, strict=False)
        }
        sorted_contribs = sorted(contrib_dict.items(), key=lambda x: x[1], reverse=True)
        primary_dim = sorted_contribs[0][0]
    else:
        contrib_dict = {i: float(c) for i, c in enumerate(contributions)}
        sorted_contribs = sorted(contrib_dict.items(), key=lambda x: x[1], reverse=True)
        primary_dim = sorted_contribs[0][0]

    # Top contributors (up to 5)
    top_contributors: list[tuple[str | int, float]] = sorted_contribs[:5]

    # Generate interpretation
    interpretation = _generate_interpretation(
        vec_a, vec_b, primary_dim, top_contributors, dimension_names
    )

    return DriftExplanation(
        primary_drift_dimension=primary_dim,
        dimension_contributions=contrib_dict,
        top_contributors=top_contributors,
        metric_used=metric_result.metric.value,
        interpretation=interpretation,
    )


def _generate_interpretation(
    vec_a: np.ndarray,
    vec_b: np.ndarray,
    primary_dim: str | int,
    top_contributors: list[tuple[str | int, float]],
    dimension_names: list[str] | None,
) -> str:
    """Generate human-readable interpretation of drift."""
    # Get primary dimension index
    if isinstance(primary_dim, str) and dimension_names:
        idx = dimension_names.index(primary_dim)
    else:
        idx = primary_dim if isinstance(primary_dim, int) else 0

    diff_value = abs(vec_a[idx] - vec_b[idx])
    pct_diff = (diff_value / abs(vec_a[idx])) * 100 if vec_a[idx] != 0 else float("inf")

    dim_name = primary_dim if isinstance(primary_dim, str) else f"dimension {primary_dim}"

    if len(top_contributors) > 1 and top_contributors[0][1] > 0.5:
        return (
            f"Drift primarily driven by {dim_name} "
            f"({top_contributors[0][1]*100:.1f}% of total drift). "
            f"Value changed from {vec_a[idx]:.4f} to {vec_b[idx]:.4f} "
            f"({pct_diff:.1f}% difference)."
        )
    elif len(top_contributors) > 1:
        top_names = [str(c[0]) for c, _ in zip(top_contributors[:3], range(3), strict=False)]
        return (
            f"Drift distributed across multiple dimensions. "
            f"Top contributors: {', '.join(top_names)}. "
            f"Largest single change in {dim_name}."
        )
    else:
        return f"Single dimension drift in {dim_name}."


def _calculate_embedding_confidence(
    vec_a: np.ndarray,
    vec_b: np.ndarray,
) -> float:
    """Calculate confidence score for embedding verification."""
    # Base confidence
    confidence = 0.9

    # Reduce confidence for very small vectors (less reliable)
    if len(vec_a) < 10:
        confidence *= 0.9

    # Reduce confidence if vectors have very different magnitudes
    norm_a = np.linalg.norm(vec_a)
    norm_b = np.linalg.norm(vec_b)
    if norm_a > 0 and norm_b > 0:
        magnitude_ratio = min(norm_a, norm_b) / max(norm_a, norm_b)
        if magnitude_ratio < 0.5:
            confidence *= 0.85

    # Reduce confidence for near-zero vectors
    if norm_a < 1e-6 or norm_b < 1e-6:
        confidence *= 0.7

    return float(np.clip(confidence, 0.0, 1.0))


def _log_to_audit(
    audit_trail: AuditTrail,
    vec_a: np.ndarray,
    vec_b: np.ndarray,
    result: VerificationScore,
    metric: str,
    profile_name: str | None,
) -> None:
    """Log verification to audit trail."""
    passed = result.details.get("profile", {}).get("passed", result.drift_score <= 0.3)

    audit_trail.log(
        operation="verify_embeddings",
        inputs={
            "embedding_a_shape": vec_a.shape,
            "embedding_b_shape": vec_b.shape,
            "embedding_a_norm": float(np.linalg.norm(vec_a)),
            "embedding_b_norm": float(np.linalg.norm(vec_b)),
        },
        drift_score=result.drift_score,
        confidence=result.confidence,
        metric_used=metric,
        profile_used=profile_name,
        passed=passed,
        result_details={
            "drift_type": result.drift_type.value,
            "raw_distance": result.details.get("raw_distance"),
        },
    )


def verify_distributions(dist_a: ArrayLike, dist_b: ArrayLike) -> VerificationScore:
    """
    Calculate drift between two probability distributions.

    Uses KL divergence and other statistical measures to compare distributions.

    Args:
        dist_a: First probability distribution
        dist_b: Second probability distribution

    Returns:
        VerificationScore with distribution-based drift score
    """
    p = np.asarray(dist_a, dtype=np.float64)
    q = np.asarray(dist_b, dtype=np.float64)

    # Normalize to valid probability distributions
    p = p / (p.sum() + 1e-10)
    q = q / (q.sum() + 1e-10)

    # Add small epsilon to avoid log(0)
    eps = 1e-10
    p = np.clip(p, eps, 1.0)
    q = np.clip(q, eps, 1.0)

    if HAS_SCIPY:
        # KL divergence
        kl_div = stats.entropy(p, q)
        # Jensen-Shannon divergence (symmetric, bounded [0, 1])
        m = 0.5 * (p + q)
        js_div = 0.5 * stats.entropy(p, m) + 0.5 * stats.entropy(q, m)
    else:
        # Fallback implementations
        kl_div = float(np.sum(p * np.log(p / q)))
        m = 0.5 * (p + q)
        js_div = 0.5 * np.sum(p * np.log(p / m)) + 0.5 * np.sum(q * np.log(q / m))

    # Total variation distance
    tv_dist = 0.5 * np.sum(np.abs(p - q))

    # Combined drift (JS divergence is bounded [0, ln(2)])
    drift_score = js_div / np.log(2)  # Normalize to [0, 1]

    return VerificationScore(
        drift_score=float(np.clip(drift_score, 0.0, 1.0)),
        confidence=0.9,
        drift_type=DriftType.NUMERICAL,
        details={
            "kl_divergence": float(kl_div),
            "js_divergence": float(js_div),
            "total_variation": float(tv_dist),
        },
    )


def verify_sequences(seq_a: Sequence[str], seq_b: Sequence[str]) -> VerificationScore:
    """
    Calculate drift between two sequences of tokens/items.

    Uses edit distance and sequence alignment metrics.

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

    # Levenshtein distance
    edit_dist = _levenshtein_distance(seq_a, seq_b)
    max_len = max(len(seq_a), len(seq_b))
    normalized_edit = edit_dist / max_len if max_len > 0 else 0.0

    # Jaccard similarity (set-based)
    set_a = set(seq_a)
    set_b = set(seq_b)
    intersection = len(set_a & set_b)
    union = len(set_a | set_b)
    jaccard = intersection / union if union > 0 else 1.0
    jaccard_drift = 1.0 - jaccard

    # Order-aware similarity (longest common subsequence)
    lcs_len = _lcs_length(seq_a, seq_b)
    lcs_ratio = 2 * lcs_len / (len(seq_a) + len(seq_b)) if (len(seq_a) + len(seq_b)) > 0 else 1.0
    lcs_drift = 1.0 - lcs_ratio

    # Combined
    drift_score = 0.4 * normalized_edit + 0.3 * jaccard_drift + 0.3 * lcs_drift

    return VerificationScore(
        drift_score=float(np.clip(drift_score, 0.0, 1.0)),
        confidence=0.85,
        drift_type=DriftType.STRUCTURAL,
        details={
            "edit_distance": edit_dist,
            "normalized_edit": float(normalized_edit),
            "jaccard_similarity": float(jaccard),
            "lcs_ratio": float(lcs_ratio),
        },
    )


# ============================================================================
# Internal pure functions
# ============================================================================


def _lexical_drift(text_a: str, text_b: str) -> dict:
    """
    Calculate lexical drift between two texts.

    Pure function - no side effects.
    """
    # Character-level comparison
    chars_a = set(text_a)
    chars_b = set(text_b)
    char_jaccard = len(chars_a & chars_b) / len(chars_a | chars_b) if (chars_a | chars_b) else 1.0

    # Word-level comparison
    words_a = set(text_a.split())
    words_b = set(text_b.split())
    word_jaccard = len(words_a & words_b) / len(words_a | words_b) if (words_a | words_b) else 1.0

    # Length ratio
    len_a, len_b = len(text_a), len(text_b)
    length_ratio = min(len_a, len_b) / max(len_a, len_b) if max(len_a, len_b) > 0 else 1.0

    # Combined score (lower similarity = higher drift)
    similarity = 0.3 * char_jaccard + 0.5 * word_jaccard + 0.2 * length_ratio
    drift = 1.0 - similarity

    return {
        "score": drift,
        "char_jaccard": char_jaccard,
        "word_jaccard": word_jaccard,
        "length_ratio": length_ratio,
    }


def _structural_drift(text_a: str, text_b: str) -> dict:
    """
    Calculate structural drift between two texts.

    Analyzes structure like line count, indentation, code patterns.
    Pure function - no side effects.
    """
    lines_a = text_a.split("\n")
    lines_b = text_b.split("\n")

    # Line count difference
    line_count_a, line_count_b = len(lines_a), len(lines_b)
    line_ratio = (
        min(line_count_a, line_count_b) / max(line_count_a, line_count_b)
        if max(line_count_a, line_count_b) > 0
        else 1.0
    )

    # Indentation pattern
    indent_a = [len(line) - len(line.lstrip()) for line in lines_a if line.strip()]
    indent_b = [len(line) - len(line.lstrip()) for line in lines_b if line.strip()]

    if indent_a and indent_b:
        avg_indent_a = np.mean(indent_a)
        avg_indent_b = np.mean(indent_b)
        max_indent = max(avg_indent_a, avg_indent_b, 1)
        indent_similarity = 1.0 - abs(avg_indent_a - avg_indent_b) / max_indent
    else:
        indent_similarity = 1.0 if (not indent_a and not indent_b) else 0.5

    # Code pattern markers (for code comparison)
    patterns = ["def ", "class ", "import ", "return ", "if ", "for ", "while ", "try:", "except"]
    pattern_a = {p for p in patterns if p in text_a}
    pattern_b = {p for p in patterns if p in text_b}
    pattern_jaccard = (
        len(pattern_a & pattern_b) / len(pattern_a | pattern_b) if (pattern_a | pattern_b) else 1.0
    )

    # Combined
    similarity = 0.3 * line_ratio + 0.3 * indent_similarity + 0.4 * pattern_jaccard
    drift = 1.0 - similarity

    return {
        "score": drift,
        "line_ratio": line_ratio,
        "indent_similarity": indent_similarity,
        "pattern_jaccard": pattern_jaccard,
    }


def _numerical_drift(text_a: str, text_b: str) -> dict:
    """
    Calculate numerical drift by extracting and comparing numbers.

    Pure function - no side effects.
    """
    import re

    # Extract numbers from both texts
    number_pattern = r"-?\d+\.?\d*"
    numbers_a = [float(n) for n in re.findall(number_pattern, text_a)]
    numbers_b = [float(n) for n in re.findall(number_pattern, text_b)]

    if not numbers_a and not numbers_b:
        return {"score": 0.0, "reason": "no_numbers"}

    if not numbers_a or not numbers_b:
        return {"score": 0.5, "reason": "numbers_only_in_one"}

    # Compare statistics
    mean_a, mean_b = np.mean(numbers_a), np.mean(numbers_b)
    std_a, std_b = np.std(numbers_a), np.std(numbers_b)

    # Relative difference in means
    max_mean = max(abs(mean_a), abs(mean_b), 1e-10)
    mean_diff = abs(mean_a - mean_b) / max_mean

    # Relative difference in stds
    max_std = max(std_a, std_b, 1e-10)
    std_diff = abs(std_a - std_b) / max_std if max_std > 1e-10 else 0.0

    # Count difference
    count_ratio = min(len(numbers_a), len(numbers_b)) / max(len(numbers_a), len(numbers_b))

    # Combined
    drift = 0.4 * min(mean_diff, 1.0) + 0.3 * min(std_diff, 1.0) + 0.3 * (1.0 - count_ratio)

    return {
        "score": drift,
        "mean_a": mean_a,
        "mean_b": mean_b,
        "std_a": std_a,
        "std_b": std_b,
        "count_a": len(numbers_a),
        "count_b": len(numbers_b),
    }


def _levenshtein_distance(seq_a: Sequence, seq_b: Sequence) -> int:
    """
    Calculate Levenshtein edit distance between two sequences.

    Pure function using dynamic programming.
    """
    m, n = len(seq_a), len(seq_b)

    if m == 0:
        return n
    if n == 0:
        return m

    # Use numpy for efficiency
    dp = np.zeros((m + 1, n + 1), dtype=np.int32)
    dp[:, 0] = np.arange(m + 1)
    dp[0, :] = np.arange(n + 1)

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            cost = 0 if seq_a[i - 1] == seq_b[j - 1] else 1
            dp[i, j] = min(
                dp[i - 1, j] + 1,  # deletion
                dp[i, j - 1] + 1,  # insertion
                dp[i - 1, j - 1] + cost,  # substitution
            )

    return int(dp[m, n])


def _lcs_length(seq_a: Sequence, seq_b: Sequence) -> int:
    """
    Calculate length of Longest Common Subsequence.

    Pure function using dynamic programming.
    """
    m, n = len(seq_a), len(seq_b)

    if m == 0 or n == 0:
        return 0

    dp = np.zeros((m + 1, n + 1), dtype=np.int32)

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if seq_a[i - 1] == seq_b[j - 1]:
                dp[i, j] = dp[i - 1, j - 1] + 1
            else:
                dp[i, j] = max(dp[i - 1, j], dp[i, j - 1])

    return int(dp[m, n])


# ============================================================================
# Batch verification functions
# ============================================================================


def verify_batch(outputs_a: Sequence[str], outputs_b: Sequence[str]) -> list[VerificationScore]:
    """
    Verify multiple output pairs.

    Pure function that processes pairs in sequence.

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

    return [verify(a, b) for a, b in zip(outputs_a, outputs_b, strict=False)]


def aggregate_scores(scores: Sequence[VerificationScore]) -> dict:
    """
    Aggregate multiple verification scores into summary statistics.

    Pure function.

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
        "mean_drift": float(np.mean(drift_values)),
        "std_drift": float(np.std(drift_values)),
        "min_drift": float(np.min(drift_values)),
        "max_drift": float(np.max(drift_values)),
        "median_drift": float(np.median(drift_values)),
        "mean_confidence": float(np.mean(confidence_values)),
        "drift_type_distribution": drift_types,
    }
