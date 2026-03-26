# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Layer 5: Listener Agent - Reference Implementation

This module provides the Listener Agent, a passive observer that monitors
graph states and only intervenes when configured thresholds are exceeded.

The Listener consolidates the full stack:
- agent-control-plane (base orchestration)
- scak (intelligence/knowledge)
- iatp (security/trust)
- caas (context awareness)

This is pure wiring - no logic that belongs in lower layers is redefined here.
"""

from .listener import InterventionEvent, ListenerAgent, ListenerConfig, ListenerState
from .state_observer import ObservationResult, StateObserver
from .threshold_config import (
    DEFAULT_THRESHOLDS,
    InterventionLevel,
    ThresholdConfig,
    ThresholdRule,
    ThresholdType,
)

__all__ = [
    # Core Listener
    "ListenerAgent",
    "ListenerState",
    "InterventionEvent",
    "ListenerConfig",
    # Configuration
    "ThresholdConfig",
    "ThresholdType",
    "InterventionLevel",
    "ThresholdRule",
    "DEFAULT_THRESHOLDS",
    # Observer
    "StateObserver",
    "ObservationResult",
]
