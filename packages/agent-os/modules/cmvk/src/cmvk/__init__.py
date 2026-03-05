# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Community Edition — basic single-model verification
"""
CMVK — Verification Kernel (Community Edition)
==========================================================

A basic verification library for calculating drift/hallucination scores
between outputs using Python stdlib.

Layer 1: The Primitive
Publication Target: PyPI (pip install cmvk)

This library provides pure functions for verification:

- :func:`verify` - Compare two text outputs for semantic drift
- :func:`verify_embeddings` - Compare embedding vectors with configurable metrics
- :func:`verify_distributions` - Compare probability distributions (KL divergence)
- :func:`verify_sequences` - Compare sequences with alignment

All functions are pure (no side effects) and use only Python stdlib.

Example Usage
-------------

Basic text verification::

    import cmvk

    score = cmvk.verify(
        output_a="def add(a, b): return a + b",
        output_b="def add(x, y): return x + y"
    )
    print(f"Drift: {score.drift_score:.2f}")

For Hugging Face Hub integration, see :mod:`cmvk.hf_utils`.
"""

from __future__ import annotations

from typing import Any

__version__ = "0.3.0"
__author__ = "Imran Siddique"
__email__ = "agt@microsoft.com"
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
    # Batch operations
    "verify_batch",
    "verify_embeddings_batch",
    "aggregate_scores",
    "aggregate_embedding_scores",
    # Distance metrics
    "DistanceMetric",
    "MetricResult",
    "calculate_distance",
    "calculate_weighted_distance",
    "get_available_metrics",
    # Audit trail
    "AuditEntry",
    "AuditTrail",
    "get_audit_trail",
    "configure_audit_trail",
]


def __getattr__(name: str) -> Any:
    """Lazy loading for optional submodules."""
    if name == "hf_utils":
        from . import hf_utils

        return hf_utils
    if name == "metrics":
        from . import metrics

        return metrics
    if name == "audit":
        from . import audit

        return audit
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
