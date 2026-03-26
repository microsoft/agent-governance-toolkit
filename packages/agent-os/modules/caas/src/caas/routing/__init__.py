# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Heuristic routing for fast query classification without model overhead.
"""

from caas.models import ModelTier, RoutingDecision
from caas.routing.heuristic_router import HeuristicRouter

__all__ = ["HeuristicRouter", "ModelTier", "RoutingDecision"]
