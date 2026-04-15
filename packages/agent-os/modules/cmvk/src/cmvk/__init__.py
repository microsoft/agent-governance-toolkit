# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
CMVK - Cross-Model Verification Kernel
======================================

A mathematical and adversarial verification library for calculating
drift/hallucination scores between outputs.

Layer 1: The Primitive
Publication Target: PyPI (pip install cmvk)

This library provides pure functions for verification:

- :func:`verify` - Compare two text outputs for semantic drift
- :func:`verify_embeddings` - Compare embedding vectors with configurable metrics
- :func:`verify_distributions` - Compare probability distributions (KL divergence)
- :func:`verify_sequences` - Compare sequences with alignment

All functions are pure (no side effects) and use only numpy/scipy.

Version 0.2.0 Features
----------------------

- **Configurable Distance Metrics** (CMVK-001/002): Support for cosine, euclidean,
  manhattan, chebyshev, and mahalanobis distances
- **Metric Selection API** (CMVK-003): `verify_embeddings(metric="euclidean")`
- **Batch Verification** (CMVK-004): `verify_embeddings_batch()` for efficiency
- **Threshold Profiles** (CMVK-005): Pre-configured thresholds for carbon, financial, medical
- **Audit Trail** (CMVK-006): Immutable logging with timestamps
- **Dimensional Weighting** (CMVK-008): Weight certain dimensions higher
- **Explainable Drift** (CMVK-010): Per-dimension contribution analysis

Example Usage
-------------

Basic text verification::

    import cmvk

    score = cmvk.verify(
        output_a="def add(a, b): return a + b",
        output_b="def add(x, y): return x + y"
    )
    print(f"Drift: {score.drift_score:.2f}")  # ~0.15 (low = similar)

Enhanced embedding comparison with Euclidean distance::

    import cmvk
    import numpy as np

    # Euclidean distance preserves magnitude - critical for fraud detection
    claim_vec = np.array([0.82, 150.0])   # Claimed NDVI, carbon
    obs_vec = np.array([0.316, 95.0])     # Observed values

    score = cmvk.verify_embeddings(
        claim_vec, obs_vec,
        metric="euclidean",           # Preserves magnitude (CMVK-001)
        weights=[0.6, 0.4],           # NDVI weighted higher (CMVK-008)
        threshold_profile="carbon",   # Domain-specific thresholds (CMVK-005)
        explain=True                  # Show dimension contributions (CMVK-010)
    )

    print(f"Drift: {score.drift_score:.2f}")
    print(f"Explanation: {score.explanation}")

Batch verification::

    scores = cmvk.verify_embeddings_batch(
        claims_vectors,
        observations_vectors,
        metric="euclidean",
        threshold_profile="carbon"
    )
    summary = cmvk.aggregate_embedding_scores(scores, threshold_profile="carbon")
    print(f"Pass rate: {summary['pass_rate']:.1%}")

For Hugging Face Hub integration, see :mod:`cmvk.hf_utils`.
"""

from __future__ import annotations

from typing import Any

__version__ = "3.1.0"
__author__ = "Microsoft Corporation"
__email__ = "agentgovtoolkit@microsoft.com"
__license__ = "MIT"

# Audit trail
from .audit import AuditEntry, AuditTrail, configure_audit_trail, get_audit_trail

# Distance metrics module
from .metrics import (
    DistanceMetric,
    MetricResult,
    calculate_distance,
    calculate_weighted_distance,
    get_available_metrics,
)

# Threshold profiles
from .profiles import (
    ProfileName,
    ThresholdProfile,
    create_profile,
    get_profile,
    list_profiles,
    register_profile,
)
from .types import DriftType, VerificationScore
from .verification import (
    DriftExplanation,
    aggregate_embedding_scores,
    aggregate_scores,
    verify,
    verify_batch,
    verify_distributions,
    verify_embeddings,
    verify_embeddings_batch,
    verify_sequences,
)

# Constitutional Validator (CMVK-011)
from .constitutional import (
    ConstitutionalValidator,
    Principle,
    PrincipleSet,
    Severity,
    Violation,
    ValidationResult,
    PrincipleEvaluator,
    RuleBasedEvaluator,
    LLMEvaluator,
    SAFETY_PRINCIPLES,
    MEDICAL_PRINCIPLES,
    FINANCIAL_PRINCIPLES,
    validate_safety,
    validate_medical,
    validate_financial,
)

__all__ = [
    # Metadata
    "__version__",
    "__author__",
    "__email__",
    "__license__",
    # Types (exported for type annotations)
    "DriftType",
    "VerificationScore",
    "DriftExplanation",
    # Core verification functions
    "verify",
    "verify_embeddings",
    "verify_distributions",
    "verify_sequences",
    # Batch operations (CMVK-004)
    "verify_batch",
    "verify_embeddings_batch",
    "aggregate_scores",
    "aggregate_embedding_scores",
    # Distance metrics (CMVK-001/002/003)
    "DistanceMetric",
    "MetricResult",
    "calculate_distance",
    "calculate_weighted_distance",
    "get_available_metrics",
    # Threshold profiles (CMVK-005)
    "ProfileName",
    "ThresholdProfile",
    "get_profile",
    "list_profiles",
    "create_profile",
    "register_profile",
    # Audit trail (CMVK-006)
    "AuditEntry",
    "AuditTrail",
    "get_audit_trail",
    "configure_audit_trail",
    # Constitutional Validator (CMVK-011)
    "ConstitutionalValidator",
    "Principle",
    "PrincipleSet",
    "Severity",
    "Violation",
    "ValidationResult",
    "PrincipleEvaluator",
    "RuleBasedEvaluator",
    "LLMEvaluator",
    "SAFETY_PRINCIPLES",
    "MEDICAL_PRINCIPLES",
    "FINANCIAL_PRINCIPLES",
    "validate_safety",
    "validate_medical",
    "validate_financial",
]


def __getattr__(name: str) -> Any:
    """Lazy loading for optional submodules."""
    if name == "hf_utils":
        from . import hf_utils

        return hf_utils
    if name == "metrics":
        from . import metrics

        return metrics
    if name == "profiles":
        from . import profiles

        return profiles
    if name == "audit":
        from . import audit

        return audit
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
