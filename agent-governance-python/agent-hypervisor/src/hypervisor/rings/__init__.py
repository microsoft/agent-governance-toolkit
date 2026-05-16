# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Execution rings subpackage — enforcement, classification, elevation, breach detection."""

from hypervisor.rings.breach_detector import BreachEvent, BreachSeverity, RingBreachDetector
from hypervisor.rings.elevation import (
    ChildRegistration,
    ElevationDenialReason,
    ELEVATION_TRUST_THRESHOLDS,
    RingElevation,
    RingElevationError,
    RingElevationManager,
)
from hypervisor.rings.enforcer import (
    ResourceConstraints,
    ResourceType,
    RING_CONSTRAINTS,
    RingCheckResult,
    RingEnforcer,
)

__all__ = [
    "ChildRegistration",
    "ElevationDenialReason",
    "ELEVATION_TRUST_THRESHOLDS",
    "ResourceConstraints",
    "ResourceType",
    "RING_CONSTRAINTS",
    "RingBreachDetector",
    "RingCheckResult",
    "RingElevation",
    "RingElevationError",
    "RingElevationManager",
    "RingEnforcer",
    "BreachEvent",
    "BreachSeverity",
]
