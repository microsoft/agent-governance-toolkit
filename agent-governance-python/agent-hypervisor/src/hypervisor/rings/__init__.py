# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Execution rings subpackage — enforcement, classification, elevation, breach detection."""

from hypervisor.rings.breach_detector import BreachEvent, BreachSeverity, RingBreachDetector
from hypervisor.rings.elevation import (
    ELEVATION_TRUST_THRESHOLDS,
    ChildRegistration,
    ElevationDenialReason,
    RingElevation,
    RingElevationError,
    RingElevationManager,
)
from hypervisor.rings.enforcer import (
    RING_CONSTRAINTS,
    CommandCheckResult,
    ResourceConstraints,
    ResourceType,
    RingCheckResult,
    RingEnforcer,
)

__all__ = [
    "ChildRegistration",
    "CommandCheckResult",
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
