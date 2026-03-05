# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
AgentMesh CLI

Command-line interface for AgentMesh.
Single CLI command: agentmesh init — scaffolds a governed agent in 30 seconds.
"""

from .main import app, main

__all__ = ["app", "main"]
