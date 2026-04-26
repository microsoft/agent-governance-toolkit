# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Heuristic routing for fast query classification without model overhead.
"""

from caas.routing.heuristic_router import HeuristicRouter
from caas.models import ModelTier, RoutingDecision

__all__ = ['HeuristicRouter', 'ModelTier', 'RoutingDecision']
