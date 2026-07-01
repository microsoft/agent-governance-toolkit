# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Extract current governance context from AGT runtime for continuity verification.

**EXPERIMENTAL:** This module is a stub that must be wired to the live AGT runtime.
It currently returns mock data and is intended for evaluation and testing only.
Operators must replace this with real state readers (AgentMesh identity, PolicyEngine, etc.)
before enabling continuity verification in production.
"""
import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)

_CONTEXT_OVERRIDE = None

def set_test_execution_context(context: Dict[str, Any]) -> None:
    global _CONTEXT_OVERRIDE
    _CONTEXT_OVERRIDE = context

def get_execution_context() -> Dict[str, Any]:
    if _CONTEXT_OVERRIDE is not None:
        return _CONTEXT_OVERRIDE

    logger.warning(
        "continuity_helpers.get_execution_context() is a stub returning mock data. "
        "Continuity verification will not detect actual drift in production until "
        "this function is wired to the AGT runtime."
    )
    return {
        "agent_id": "test-agent",
        "session_id": "test-session",
        "memory_state": {},
        "policy_version": "v1",
        "delegation_chain": ["root"],
        "evidence_state": {"fresh": True},
    }