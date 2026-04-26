# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Safety-critical tests for Agent OS governance primitives.

Covers:
- ToolCallInterceptor (PolicyInterceptor, CompositeInterceptor)
- BoundedSemaphore concurrency control
- StatelessKernel policy enforcement edge cases

Run with: python -m pytest tests/test_safety_critical.py -v
"""

import pytest

from agent_os.integrations.base import (
    GovernancePolicy,
    ExecutionContext,
    ToolCallRequest,
    ToolCallResult,
    PolicyInterceptor,
    CompositeInterceptor,
    BoundedSemaphore,
)
from agent_os.stateless import StatelessKernel, ExecutionContext as StatelessContext


# =============================================================================
# ToolCallRequest / ToolCallResult data structures
# =============================================================================


class TestToolCallDataStructures:
    def test_request_defaults(self):
        req = ToolCallRequest(tool_name="search", arguments={"q": "hello"})
        assert req.tool_name == "search"
        assert req.arguments == {"q": "hello"}
        assert req.call_id == ""
        assert req.agent_id == ""
        assert req.metadata == {}

    def test_request_with_all_fields(self):
        req = ToolCallRequest(
            tool_name="db_query",
            arguments={"sql": "SELECT 1"},
            call_id="c1",
            agent_id="a1",
            metadata={"source": "test"},
        )
        assert req.call_id == "c1"
        assert req.agent_id == "a1"
        assert req.metadata["source"] == "test"

    def test_result_allowed(self):
        res = ToolCallResult(allowed=True)
        assert res.allowed is True
        assert res.reason is None
        assert res.modified_arguments is None
        assert res.audit_entry is None

    def test_result_denied_with_reason(self):
        res = ToolCallResult(allowed=False, reason="blocked")
        assert res.allowed is False
        assert res.reason == "blocked"

    def test_result_with_modified_arguments(self):
        res = ToolCallResult(allowed=True, modified_arguments={"sanitized": True})
        assert res.modified_arguments == {"sanitized": True}

    def test_result_with_audit_entry(self):
        res = ToolCallResult(allowed=True, audit_entry={"event": "tool_call"})
        assert res.audit_entry["event"] == "tool_call"


# =============================================================================
# PolicyInterceptor tests
# =============================================================================


class TestPolicyInterceptor:
    def test_allows_when_no_restrictions(self):
        policy = GovernancePolicy()
        interceptor = PolicyInterceptor(policy)
        req = ToolCallRequest(tool_name="anything", arguments={})
        result = interceptor.intercept(req)
        assert result.allowed is True

    def test_allowed_tools_enforcement_pass(self):
        policy = GovernancePolicy(allowed_tools=["search", "read_file"])
        interceptor = PolicyInterceptor(policy)
        req = ToolCallRequest(tool_name="search", arguments={})
        result = interceptor.intercept(req)
        assert result.allowed is True

    def test_allowed_tools_enforcement_block(self):
        policy = GovernancePolicy(allowed_tools=["search", "read_file"])
        interceptor = PolicyInterceptor(policy)
        req = ToolCallRequest(tool_name="delete_file", arguments={})
        result = interceptor.intercept(req)
        assert result.allowed is False
        assert "delete_file" in result.reason
        assert "not in allowed list" in result.reason

    def test_empty_allowed_tools_permits_all(self):
        policy = GovernancePolicy(allowed_tools=[])
        interceptor = PolicyInterceptor(policy)
        req = ToolCallRequest(tool_name="any_tool", arguments={})
        result = interceptor.intercept(req)
        assert result.allowed is True

    def test_blocked_patterns_detected(self):
        policy = GovernancePolicy(blocked_patterns=["password", "ssn"])
        interceptor = PolicyInterceptor(policy)
        req = ToolCallRequest(tool_name="query", arguments={"q": "get password"})
        result = interceptor.intercept(req)
        assert result.allowed is False
        assert "password" in result.reason

    def test_blocked_patterns_case_insensitive(self):
        policy = GovernancePolicy(blocked_patterns=["SECRET"])
        interceptor = PolicyInterceptor(policy)
        req = ToolCallRequest(tool_name="query", arguments={"data": "my secret key"})
        result = interceptor.intercept(req)
        assert result.allowed is False

    def test_no_blocked_pattern_match_allows(self):
        policy = GovernancePolicy(blocked_patterns=["password"])
        interceptor = PolicyInterceptor(policy)
        req = ToolCallRequest(tool_name="query", arguments={"q": "hello world"})
        result = interceptor.intercept(req)
        assert result.allowed is True

    def test_call_count_limit_blocks(self):
        policy = GovernancePolicy(max_tool_calls=3)
        ctx = ExecutionContext(
            agent_id="a1", session_id="s1", policy=policy, call_count=3
        )
        interceptor = PolicyInterceptor(policy, context=ctx)
        req = ToolCallRequest(tool_name="search", arguments={})
        result = interceptor.intercept(req)
        assert result.allowed is False
        assert "Max tool calls exceeded" in result.reason

    def test_call_count_under_limit_allows(self):
        policy = GovernancePolicy(max_tool_calls=5)
        ctx = ExecutionContext(
            agent_id="a1", session_id="s1", policy=policy, call_count=4
        )
        interceptor = PolicyInterceptor(policy, context=ctx)
        req = ToolCallRequest(tool_name="search", arguments={})
        result = interceptor.intercept(req)
        assert result.allowed is True

    def test_call_count_without_context_allows(self):
        """No context means call count is not checked."""
        policy = GovernancePolicy(max_tool_calls=0)
        interceptor = PolicyInterceptor(policy, context=None)
        req = ToolCallRequest(tool_name="search", arguments={})
        result = interceptor.intercept(req)
        assert result.allowed is True


# =============================================================================
# CompositeInterceptor tests
# =============================================================================


class TestCompositeInterceptor:
    def test_empty_chain_allows(self):
        composite = CompositeInterceptor([])
        req = ToolCallRequest(tool_name="anything", arguments={})
        result = composite.intercept(req)
        assert result.allowed is True

    def test_all_must_allow(self):
        """If any interceptor denies, the composite denies."""
        allow_policy = GovernancePolicy(allowed_tools=[])
        block_policy = GovernancePolicy(allowed_tools=["only_this"])

        composite = CompositeInterceptor([
            PolicyInterceptor(allow_policy),
            PolicyInterceptor(block_policy),
        ])
        req = ToolCallRequest(tool_name="other_tool", arguments={})
        result = composite.intercept(req)
        assert result.allowed is False

    def test_all_allow_passes(self):
        policy1 = GovernancePolicy(allowed_tools=["search"])
        policy2 = GovernancePolicy(blocked_patterns=["password"])

        composite = CompositeInterceptor([
            PolicyInterceptor(policy1),
            PolicyInterceptor(policy2),
        ])
        req = ToolCallRequest(tool_name="search", arguments={"q": "hello"})
        result = composite.intercept(req)
        assert result.allowed is True

    def test_ordering_first_deny_wins(self):
        """First interceptor to deny short-circuits the chain."""
        deny_policy = GovernancePolicy(allowed_tools=["x"])
        allow_policy = GovernancePolicy()

        composite = CompositeInterceptor([
            PolicyInterceptor(deny_policy),
            PolicyInterceptor(allow_policy),
        ])
        req = ToolCallRequest(tool_name="y", arguments={})
        result = composite.intercept(req)
        assert result.allowed is False
        assert "not in allowed list" in result.reason

    def test_add_returns_self(self):
        composite = CompositeInterceptor()
        result = composite.add(PolicyInterceptor(GovernancePolicy()))
        assert result is composite
        assert len(composite.interceptors) == 1

    def test_add_chaining(self):
        composite = (
            CompositeInterceptor()
            .add(PolicyInterceptor(GovernancePolicy()))
            .add(PolicyInterceptor(GovernancePolicy()))
        )
        assert len(composite.interceptors) == 2


# =============================================================================
# BoundedSemaphore tests
# =============================================================================


class TestBoundedSemaphore:
    def test_acquire_release_cycle(self):
        sem = BoundedSemaphore(max_concurrent=2)
        acquired, reason = sem.try_acquire()
        assert acquired is True
        assert reason is None
        assert sem.active == 1
        sem.release()
        assert sem.active == 0

    def test_max_concurrent_enforcement(self):
        sem = BoundedSemaphore(max_concurrent=2)
        sem.try_acquire()
        sem.try_acquire()
        acquired, reason = sem.try_acquire()
        assert acquired is False
        assert "Max concurrency" in reason

    def test_release_then_acquire_again(self):
        sem = BoundedSemaphore(max_concurrent=1)
        sem.try_acquire()
        acquired, _ = sem.try_acquire()
        assert acquired is False
        sem.release()
        acquired, _ = sem.try_acquire()
        assert acquired is True

    def test_backpressure_detection_under_threshold(self):
        sem = BoundedSemaphore(max_concurrent=10, backpressure_threshold=8)
        for _ in range(7):
            sem.try_acquire()
        assert sem.is_under_pressure is False

    def test_backpressure_detection_at_threshold(self):
        sem = BoundedSemaphore(max_concurrent=10, backpressure_threshold=8)
        for _ in range(8):
            sem.try_acquire()
        assert sem.is_under_pressure is True

    def test_stats_tracking(self):
        sem = BoundedSemaphore(max_concurrent=2, backpressure_threshold=1)
        sem.try_acquire()
        sem.try_acquire()
        sem.try_acquire()  # rejected

        stats = sem.stats()
        assert stats["total_acquired"] == 2
        assert stats["total_rejected"] == 1
        assert stats["active"] == 2
        assert stats["available"] == 0
        assert stats["max_concurrent"] == 2
        assert stats["under_pressure"] is True

    def test_stats_after_release(self):
        sem = BoundedSemaphore(max_concurrent=3)
        sem.try_acquire()
        sem.try_acquire()
        sem.release()
        stats = sem.stats()
        assert stats["active"] == 1
        assert stats["available"] == 2
        assert stats["total_acquired"] == 2

    def test_double_release_safety(self):
        """Releasing more than acquired should not go below zero."""
        sem = BoundedSemaphore(max_concurrent=5)
        sem.try_acquire()
        sem.release()
        sem.release()  # extra release
        assert sem.active == 0
        assert sem.available == 5

    def test_available_property(self):
        sem = BoundedSemaphore(max_concurrent=3)
        assert sem.available == 3
        sem.try_acquire()
        assert sem.available == 2


# =============================================================================
# StatelessKernel policy enforcement edge cases
# =============================================================================


class TestPolicyEdgeCases:
    @pytest.mark.asyncio
    async def test_empty_policies_list_allows(self):
        kernel = StatelessKernel()
        ctx = StatelessContext(agent_id="a1", policies=[])
        result = await kernel.execute(
            action="file_write", params={"path": "/tmp/x"}, context=ctx
        )
        assert result.success is True

    @pytest.mark.asyncio
    async def test_unknown_policy_name_gracefully_ignored(self):
        kernel = StatelessKernel()
        ctx = StatelessContext(agent_id="a1", policies=["nonexistent_policy"])
        result = await kernel.execute(
            action="database_query", params={"q": "SELECT 1"}, context=ctx
        )
        assert result.success is True

    @pytest.mark.asyncio
    async def test_multiple_policies_applied_in_sequence(self):
        """read_only blocks file_write before no_pii is even checked."""
        kernel = StatelessKernel()
        ctx = StatelessContext(agent_id="a1", policies=["read_only", "no_pii"])
        result = await kernel.execute(
            action="file_write", params={"path": "/data"}, context=ctx
        )
        assert result.success is False
        assert "read_only" in result.error

    @pytest.mark.asyncio
    async def test_second_policy_catches_what_first_misses(self):
        """read_only allows database_query, but no_pii blocks ssn in params."""
        kernel = StatelessKernel()
        ctx = StatelessContext(agent_id="a1", policies=["read_only", "no_pii"])
        result = await kernel.execute(
            action="database_query",
            params={"query": "SELECT ssn FROM users"},
            context=ctx,
        )
        assert result.success is False
        assert "ssn" in result.error.lower()

    @pytest.mark.asyncio
    async def test_approval_workflow_blocks_without_approval(self):
        kernel = StatelessKernel()
        ctx = StatelessContext(agent_id="a1", policies=["strict"])
        result = await kernel.execute(
            action="send_email",
            params={"to": "user@example.com"},
            context=ctx,
        )
        assert result.success is False
        assert "requires approval" in result.error.lower()

    @pytest.mark.asyncio
    async def test_approval_workflow_passes_with_approved_true(self):
        kernel = StatelessKernel()
        ctx = StatelessContext(agent_id="a1", policies=["strict"])
        result = await kernel.execute(
            action="send_email",
            params={"to": "user@example.com", "approved": True},
            context=ctx,
        )
        assert result.success is True

    @pytest.mark.asyncio
    async def test_error_message_contains_suggestion_blocked_action(self):
        kernel = StatelessKernel()
        ctx = StatelessContext(agent_id="a1", policies=["read_only"])
        result = await kernel.execute(
            action="file_write", params={}, context=ctx
        )
        assert result.success is False
        assert "Try" in result.error or "instead" in result.error

    @pytest.mark.asyncio
    async def test_error_message_contains_suggestion_blocked_pattern(self):
        kernel = StatelessKernel()
        ctx = StatelessContext(agent_id="a1", policies=["no_pii"])
        result = await kernel.execute(
            action="query",
            params={"data": "password reset"},
            context=ctx,
        )
        assert result.success is False
        assert "Remove" in result.error or "retry" in result.error.lower()

    @pytest.mark.asyncio
    async def test_error_message_contains_suggestion_approval_needed(self):
        kernel = StatelessKernel()
        ctx = StatelessContext(agent_id="a1", policies=["strict"])
        result = await kernel.execute(
            action="code_execution", params={"code": "print(1)"}, context=ctx
        )
        assert result.success is False
        assert "approved=True" in result.error or "authorization" in result.error.lower()
