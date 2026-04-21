# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
MCP Trust Server for AgentMesh
==============================

Exposes AgentMesh trust management as MCP tools compatible with
Claude, GPT, and other AI agents via the Model Context Protocol.

Tools:
- check_trust: Check if an agent is trusted
- get_trust_score: Get detailed trust score with all 5 dimensions
- establish_handshake: Initiate trust handshake with a peer agent
- verify_delegation: Verify a scope chain is valid
- record_interaction: Record an interaction outcome to update trust
- get_identity: Get this agent's identity info
"""

__version__ = "3.1.1"
