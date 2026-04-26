# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic context/memory management
"""
Simple TTL-based decay for document relevance scoring.

Returns 1.0 if within TTL, 0.0 if expired, with linear interpolation between.
"""

from datetime import datetime, timezone
from typing import Optional

# Default TTL in days
_DEFAULT_TTL_DAYS = 30.0


def calculate_decay_factor(
    ingestion_timestamp: Optional[str],
    reference_time: Optional[datetime] = None,
    decay_rate: float = 1.0,
) -> float:
    """
    Calculate a simple TTL-based decay factor.

    Returns 1.0 when the document is brand-new and linearly decays to 0.0
    at ``_DEFAULT_TTL_DAYS / decay_rate`` days old.

    Args:
        ingestion_timestamp: ISO-format timestamp of document ingestion.
        reference_time: Time to measure from (defaults to now).
        decay_rate: Higher values shorten the effective TTL.

    Returns:
        Decay factor between 0.0 and 1.0.
    """
    if not ingestion_timestamp:
        return 0.0

    try:
        ingestion_dt = datetime.fromisoformat(
            ingestion_timestamp.replace("Z", "+00:00")
        )
        if reference_time is None:
            reference_time = datetime.now(timezone.utc)

        days_elapsed = max(
            0.0, (reference_time - ingestion_dt).total_seconds() / 86400.0
        )
        ttl = _DEFAULT_TTL_DAYS / max(decay_rate, 0.001)
        if days_elapsed >= ttl:
            return 0.0
        return 1.0 - (days_elapsed / ttl)
    except (ValueError, AttributeError, TypeError):
        return 0.0


def apply_decay_to_score(base_score: float, decay_factor: float) -> float:
    """Apply *decay_factor* to *base_score*."""
    return base_score * decay_factor


def get_time_weighted_score(
    base_score: float,
    ingestion_timestamp: Optional[str],
    reference_time: Optional[datetime] = None,
    decay_rate: float = 1.0,
) -> float:
    """Convenience: compute time-weighted score in one call."""
    return apply_decay_to_score(
        base_score,
        calculate_decay_factor(ingestion_timestamp, reference_time, decay_rate),
    )
