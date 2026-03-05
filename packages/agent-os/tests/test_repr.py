# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for __repr__ methods on dataclasses.

Ensures readable, debug-friendly representations that show
key fields only (no secrets or large data).

Run with: python -m pytest tests/test_repr.py -v
"""

from datetime import datetime

import pytest

from agent_os.base_agent import AgentConfig, AuditEntry, PolicyDecision
from agent_os.integrations.base import (
    ExecutionContext,
    GovernancePolicy,
    ToolCallRequest,
    ToolCallResult,
)


# =============================================================================
# AgentConfig
# =============================================================================


class TestAgentConfigRepr:
    def test_default(self):
        cfg = AgentConfig(agent_id="agent-1")
        assert repr(cfg) == "AgentConfig(agent_id='agent-1', policies=[])"

    def test_with_policies(self):
        cfg = AgentConfig(agent_id="agent-2", policies=["read_only", "no_pii"])
        assert repr(cfg) == "AgentConfig(agent_id='agent-2', policies=['read_only', 'no_pii'])"

    def test_metadata_omitted(self):
        cfg = AgentConfig(agent_id="agent-3", metadata={"secret": "key123"})
        assert "secret" not in repr(cfg)
        assert "key123" not in repr(cfg)


# =============================================================================
# AuditEntry
# =============================================================================


class TestAuditEntryRepr:
    def test_repr(self):
        entry = AuditEntry(
            timestamp=datetime(2026, 1, 1),
            agent_id="agent-1",
            request_id="req-abc",
            action="read_file",
            params={"path": "/etc/passwd"},
            decision=PolicyDecision.ALLOW,
        )
        r = repr(entry)
        assert "AuditEntry(" in r
        assert "agent_id='agent-1'" in r
        assert "action='read_file'" in r
        assert "decision=<PolicyDecision.ALLOW: 'allow'>" in r
        # Sensitive params should not appear
        assert "/etc/passwd" not in r


# =============================================================================
# GovernancePolicy
# =============================================================================


class TestGovernancePolicyRepr:
    def test_default(self):
        policy = GovernancePolicy()
        r = repr(policy)
        assert "GovernancePolicy(" in r
        assert "max_tokens=4096" in r
        assert "max_tool_calls=10" in r
        assert "require_human_approval=False" in r

    def test_custom_values(self):
        policy = GovernancePolicy(max_tokens=2048, require_human_approval=True)
        r = repr(policy)
        assert "max_tokens=2048" in r
        assert "require_human_approval=True" in r

    def test_omits_internal_fields(self):
        policy = GovernancePolicy(blocked_patterns=["password", "ssn"])
        r = repr(policy)
        assert "blocked_patterns" not in r


# =============================================================================
# ExecutionContext
# =============================================================================


class TestExecutionContextRepr:
    def test_repr(self):
        ctx = ExecutionContext(
            agent_id="agent-1",
            session_id="sess-abc",
            policy=GovernancePolicy(),
        )
        r = repr(ctx)
        assert "ExecutionContext(" in r
        assert "agent_id='agent-1'" in r
        assert "session_id='sess-abc'" in r


# =============================================================================
# ToolCallRequest
# =============================================================================


class TestToolCallRequestRepr:
    def test_repr(self):
        req = ToolCallRequest(tool_name="read_file", arguments={"path": "/secret"}, call_id="c-1")
        r = repr(req)
        assert "ToolCallRequest(" in r
        assert "tool_name='read_file'" in r
        assert "call_id='c-1'" in r
        # Arguments should not leak
        assert "/secret" not in r


# =============================================================================
# ToolCallResult
# =============================================================================


class TestToolCallResultRepr:
    def test_allowed(self):
        res = ToolCallResult(allowed=True)
        assert repr(res) == "ToolCallResult(allowed=True, reason=None)"

    def test_denied(self):
        res = ToolCallResult(allowed=False, reason="blocked")
        assert repr(res) == "ToolCallResult(allowed=False, reason='blocked')"
