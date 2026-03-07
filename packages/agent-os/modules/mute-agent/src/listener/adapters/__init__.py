# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Adapters for Layer 5 Integration

These adapters provide clean interfaces to the lower-layer dependencies:
- agent-control-plane: Base orchestration
- scak: Intelligence/Knowledge layer
- iatp: Security/Trust layer
- caas: Context-as-a-Service layer

The Listener Agent uses these adapters to wire together the full stack
without reimplementing any lower-layer logic.
"""

from .base_adapter import BaseLayerAdapter, AdapterProtocol
from .scak_adapter import IntelligenceAdapter
from .iatp_adapter import SecurityAdapter
from .caas_adapter import ContextAdapter
from .control_plane_adapter import ControlPlaneAdapter

__all__ = [
    # Base
    "BaseLayerAdapter",
    "AdapterProtocol",
    # Layer adapters
    "IntelligenceAdapter",
    "SecurityAdapter",
    "ContextAdapter",
    "ControlPlaneAdapter",
]
