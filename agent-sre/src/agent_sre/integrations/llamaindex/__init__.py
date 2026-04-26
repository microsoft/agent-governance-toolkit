# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
LlamaIndex SRE Callbacks — auto-record Agent-SRE SLIs from LlamaIndex execution.

Usage:
    from agent_sre.integrations.llamaindex import AgentSRELlamaIndexHandler

    handler = AgentSRELlamaIndexHandler()
    # Use with LlamaIndex callback manager
    # After execution:
    handler.task_success_rate  # 0.95
"""

from agent_sre.integrations.llamaindex.handler import AgentSRELlamaIndexHandler

__all__ = ["AgentSRELlamaIndexHandler"]
