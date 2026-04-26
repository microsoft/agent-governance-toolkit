# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agents Module

Contains all specialized agents for the Carbon Auditor Swarm.
Uses amb-core for messaging and agent-tool-registry for tools.
"""

from .claims_agent import ClaimsAgent
from .geo_agent import GeoAgent
from .auditor_agent import AuditorAgent

__all__ = [
    "ClaimsAgent",
    "GeoAgent", 
    "AuditorAgent",
]
