# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""OpenTelemetry semantic conventions for AI agents.

Defines custom attribute names and span kind constants following
the agent-sre convention of ``agent.*`` namespaced attributes.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Custom agent attributes
# ---------------------------------------------------------------------------

AGENT_DID = "agent.did"
AGENT_TRUST_SCORE = "agent.trust_score"
AGENT_TASK_SUCCESS = "agent.task.success"
AGENT_TASK_NAME = "agent.task.name"
AGENT_TOOL_NAME = "agent.tool.name"
AGENT_TOOL_RESULT = "agent.tool.result"
AGENT_MODEL_NAME = "agent.model.name"
AGENT_MODEL_PROVIDER = "agent.model.provider"
AGENT_DELEGATION_FROM = "agent.delegation.from"
AGENT_DELEGATION_TO = "agent.delegation.to"
AGENT_POLICY_NAME = "agent.policy.name"
AGENT_POLICY_DECISION = "agent.policy.decision"

# ---------------------------------------------------------------------------
# Span kind constants (logical span types for agent operations)
# ---------------------------------------------------------------------------

AGENT_TASK = "AGENT_TASK"
TOOL_CALL = "TOOL_CALL"
LLM_INFERENCE = "LLM_INFERENCE"
DELEGATION = "DELEGATION"
POLICY_CHECK = "POLICY_CHECK"
