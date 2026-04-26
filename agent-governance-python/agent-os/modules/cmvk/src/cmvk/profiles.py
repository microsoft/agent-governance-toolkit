# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
CMVK Threshold Profiles Module

Pre-configured threshold profiles for different verification domains.
Each profile defines appropriate thresholds and metric defaults for specific use cases.

Domains:
    - carbon: Carbon credit and environmental verification
    - financial: Financial transaction and fraud detection
    - medical: Medical claims and health data verification
    - general: Default profile for general use
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ProfileName(Enum):
    """Available threshold profile names."""

    GENERAL = "general"
    CARBON = "carbon"
    FINANCIAL = "financial"
    MEDICAL = "medical"
    STRICT = "strict"
    LENIENT = "lenient"


@dataclass(frozen=True)
class ThresholdProfile:
    """
    Configuration profile for verification thresholds.

    Attributes:
        name: Profile identifier
        description: Human-readable description
        drift_threshold: Maximum acceptable drift score (0.0-1.0)
        confidence_threshold: Minimum required confidence (0.0-1.0)
        default_metric: Recommended distance metric for this domain
        dimension_weights: Optional default weights for dimensions
        anomaly_sigma: Standard deviations for anomaly detection
        flags: Additional domain-specific flags
    """

    name: str
    description: str
    drift_threshold: float
    confidence_threshold: float
    default_metric: str = "euclidean"
    dimension_weights: dict[str, float] | None = None
    anomaly_sigma: float = 3.0
    flags: dict[str, Any] = field(default_factory=dict)

    def is_within_threshold(self, drift_score: float, confidence: float) -> bool:
        """Check if verification result passes this profile's thresholds."""
        return drift_score <= self.drift_threshold and confidence >= self.confidence_threshold

    def get_severity(self, drift_score: float) -> str:
        """
        Classify drift severity based on profile thresholds.

        Returns:
            "pass": Within threshold
            "warning": 1-1.5x threshold
            "critical": 1.5-2x threshold
            "severe": >2x threshold
        """
        ratio = drift_score / self.drift_threshold if self.drift_threshold > 0 else float("inf")

        if ratio <= 1.0:
            return "pass"
        elif ratio <= 1.5:
            return "warning"
        elif ratio <= 2.0:
            return "critical"
        else:
            return "severe"


# ============================================================================
# Pre-defined Profiles
# ============================================================================

GENERAL_PROFILE = ThresholdProfile(
    name="general",
    description="Default profile for general-purpose verification",
    drift_threshold=0.3,
    confidence_threshold=0.7,
    default_metric="cosine",
    anomaly_sigma=3.0,
    flags={
        "require_explanation": False,
        "strict_shape_match": True,
    },
)

CARBON_PROFILE = ThresholdProfile(
    name="carbon",
    description="Profile for carbon credit and environmental data verification. "
    "Uses Euclidean distance to preserve magnitude information critical "
    "for detecting discrepancies in NDVI, carbon stock, and sequestration values.",
    drift_threshold=0.15,
    confidence_threshold=0.85,
    default_metric="euclidean",
    dimension_weights={
        "ndvi": 0.35,
        "carbon_stock": 0.30,
        "sequestration_rate": 0.20,
        "area": 0.15,
    },
    anomaly_sigma=2.5,
    flags={
        "require_explanation": True,
        "fraud_detection_mode": True,
        "magnitude_sensitive": True,
        "min_sample_size": 10,
    },
)

FINANCIAL_PROFILE = ThresholdProfile(
    name="financial",
    description="Profile for financial transaction and fraud detection. "
    "Very strict thresholds with Chebyshev metric to catch "
    "single-dimension anomalies (e.g., one suspicious transaction).",
    drift_threshold=0.10,
    confidence_threshold=0.90,
    default_metric="chebyshev",
    dimension_weights={
        "amount": 0.40,
        "frequency": 0.25,
        "location": 0.20,
        "timing": 0.15,
    },
    anomaly_sigma=2.0,
    flags={
        "require_explanation": True,
        "fraud_detection_mode": True,
        "audit_required": True,
        "real_time_alerting": True,
    },
)

MEDICAL_PROFILE = ThresholdProfile(
    name="medical",
    description="Profile for medical claims and health data verification. "
    "Balanced thresholds with Manhattan distance for robustness to outliers.",
    drift_threshold=0.20,
    confidence_threshold=0.85,
    default_metric="manhattan",
    dimension_weights={
        "diagnosis": 0.35,
        "treatment": 0.30,
        "outcome": 0.25,
        "cost": 0.10,
    },
    anomaly_sigma=2.5,
    flags={
        "require_explanation": True,
        "hipaa_compliant": True,
        "audit_required": True,
        "sensitive_data": True,
    },
)

STRICT_PROFILE = ThresholdProfile(
    name="strict",
    description="Strict verification profile with minimal tolerance for drift. "
    "Use for high-stakes verification where any discrepancy is significant.",
    drift_threshold=0.05,
    confidence_threshold=0.95,
    default_metric="euclidean",
    anomaly_sigma=2.0,
    flags={
        "require_explanation": True,
        "zero_tolerance_mode": True,
    },
)

LENIENT_PROFILE = ThresholdProfile(
    name="lenient",
    description="Lenient profile for exploratory analysis or when some drift "
    "is acceptable. Higher thresholds allow more variation.",
    drift_threshold=0.5,
    confidence_threshold=0.5,
    default_metric="cosine",
    anomaly_sigma=4.0,
    flags={
        "require_explanation": False,
        "exploratory_mode": True,
    },
)

# Registry of all profiles
PROFILES: dict[str, ThresholdProfile] = {
    "general": GENERAL_PROFILE,
    "carbon": CARBON_PROFILE,
    "financial": FINANCIAL_PROFILE,
    "medical": MEDICAL_PROFILE,
    "strict": STRICT_PROFILE,
    "lenient": LENIENT_PROFILE,
}


def get_profile(name: str | ProfileName) -> ThresholdProfile:
    """
    Get a threshold profile by name.

    Args:
        name: Profile name (string or ProfileName enum)

    Returns:
        ThresholdProfile configuration

    Raises:
        ValueError: If profile name is not found
    """
    if isinstance(name, ProfileName):
        name = name.value

    name = name.lower()
    if name not in PROFILES:
        available = list(PROFILES.keys())
        raise ValueError(f"Unknown profile '{name}'. Available profiles: {available}")

    return PROFILES[name]


def list_profiles() -> list[str]:
    """Return list of available profile names."""
    return list(PROFILES.keys())


def register_profile(profile: ThresholdProfile) -> None:
    """
    Register a custom threshold profile.

    Args:
        profile: ThresholdProfile to register

    Raises:
        ValueError: If profile name already exists (use update_profile instead)
    """
    if profile.name in PROFILES:
        raise ValueError(
            f"Profile '{profile.name}' already exists. Use update_profile() to modify."
        )
    PROFILES[profile.name] = profile


def update_profile(profile: ThresholdProfile) -> None:
    """
    Update an existing profile or add a new one.

    Args:
        profile: ThresholdProfile to register/update
    """
    PROFILES[profile.name] = profile


def create_profile(
    name: str,
    drift_threshold: float,
    confidence_threshold: float,
    description: str = "",
    default_metric: str = "euclidean",
    dimension_weights: dict[str, float] | None = None,
    anomaly_sigma: float = 3.0,
    flags: dict[str, Any] | None = None,
) -> ThresholdProfile:
    """
    Create a new threshold profile.

    Args:
        name: Unique profile identifier
        drift_threshold: Maximum acceptable drift score
        confidence_threshold: Minimum required confidence
        description: Human-readable description
        default_metric: Recommended distance metric
        dimension_weights: Optional default weights
        anomaly_sigma: Standard deviations for anomaly detection
        flags: Additional domain-specific flags

    Returns:
        New ThresholdProfile instance
    """
    return ThresholdProfile(
        name=name,
        description=description,
        drift_threshold=drift_threshold,
        confidence_threshold=confidence_threshold,
        default_metric=default_metric,
        dimension_weights=dimension_weights,
        anomaly_sigma=anomaly_sigma,
        flags=flags or {},
    )
