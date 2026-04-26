# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Execution rings subpackage — enforcement, classification, elevation, breach detection."""

from hypervisor.rings.breach_detector import BreachEvent, BreachSeverity, RingBreachDetector
from hypervisor.rings.elevation import (
    ElevationDenialReason,
    RingElevation,
    RingElevationError,
    RingElevationManager,
)

__all__ = [
    "RingElevationManager",
    "RingElevation",
    "RingElevationError",
    "ElevationDenialReason",
    "RingBreachDetector",
    "BreachEvent",
    "BreachSeverity",
]
