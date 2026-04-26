# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for Ona/Veto security gap hardening features.

Covers:
  1. Tool content hashing and integrity verification (ToolRegistry)
  2. PolicyEngine freeze / immutability
  3. Approval quorum (M-of-N) and fatigue detection (EscalationHandler)
"""

import time

import pytest

from agent_os.integrations.base import (
    ContentHashInterceptor,
    GovernancePolicy,
    PolicyInterceptor,
    ToolCallRequest,
    ToolCallResult,
)
from agent_os.integrations.escalation import (
    DefaultTimeoutAction,
    EscalationDecision,
    EscalationHandler,
    InMemoryApprovalQueue,
    QuorumConfig,
)


# ── Helpers ─────────────────────────────────────────────────────


def _sample_tool(query: str) -> str:
    """A simple search tool for testing."""
    return f"results for {query}"


def _another_tool(x: int) -> int:
    """Another tool with a different implementation."""
    return x * 2


# ══════════════════════════════════════════════════════════════════
# 1. CONTENT HASH INTERCEPTOR
# ══════════════════════════════════════════════════════════════════


class TestContentHashInterceptor:
    """Tests for the ContentHashInterceptor."""

    def test_allow_when_hash_matches(self):
        interceptor = ContentHashInterceptor(
            tool_hashes={"search": "abc123"},
            strict=True,
        )
        request = ToolCallRequest(
            tool_name="search",
            arguments={"q": "test"},
            metadata={"content_hash": "abc123"},
        )
        result = interceptor.intercept(request)
        assert result.allowed is True

    def test_deny_when_hash_mismatch(self):
        interceptor = ContentHashInterceptor(
            tool_hashes={"search": "abc123"},
            strict=True,
        )
        request = ToolCallRequest(
            tool_name="search",
            arguments={"q": "test"},
            metadata={"content_hash": "TAMPERED"},
        )
        result = interceptor.intercept(request)
        assert result.allowed is False
        assert "mismatch" in result.reason

    def test_deny_when_no_hash_in_metadata(self):
        interceptor = ContentHashInterceptor(
            tool_hashes={"search": "abc123"},
            strict=True,
        )
        request = ToolCallRequest(
            tool_name="search",
            arguments={"q": "test"},
            metadata={},
        )
        result = interceptor.intercept(request)
        assert result.allowed is False
        assert "missing content_hash" in result.reason

    def test_strict_denies_unknown_tool(self):
        interceptor = ContentHashInterceptor(
            tool_hashes={"search": "abc123"},
            strict=True,
        )
        request = ToolCallRequest(
            tool_name="unknown_wrapper",
            arguments={},
            metadata={"content_hash": "anything"},
        )
        result = interceptor.intercept(request)
        assert result.allowed is False
        assert "no registered content hash" in result.reason

    def test_nonstrict_allows_unknown_tool(self):
        interceptor = ContentHashInterceptor(
            tool_hashes={"search": "abc123"},
            strict=False,
        )
        request = ToolCallRequest(
            tool_name="unknown_wrapper",
            arguments={},
            metadata={},
        )
        result = interceptor.intercept(request)
        assert result.allowed is True

    def test_register_hash_dynamically(self):
        interceptor = ContentHashInterceptor(strict=True)
        interceptor.register_hash("my_tool", "hash_value")
        request = ToolCallRequest(
            tool_name="my_tool",
            arguments={},
            metadata={"content_hash": "hash_value"},
        )
        result = interceptor.intercept(request)
        assert result.allowed is True


# ══════════════════════════════════════════════════════════════════
# 2. TOOL REGISTRY CONTENT HASHING
# ══════════════════════════════════════════════════════════════════


class TestToolRegistryContentHash:
    """Tests for content hashing in ToolRegistry."""

    def _make_registry(self):
        from agent_control_plane.tool_registry import ToolRegistry, ToolType
        return ToolRegistry, ToolType

    def test_register_tool_stores_content_hash(self):
        ToolRegistry, ToolType = self._make_registry()
        registry = ToolRegistry()
        tool_id = registry.register_tool(
            name="search",
            description="Search tool",
            tool_type=ToolType.SEARCH,
            handler=_sample_tool,
        )
        tool = registry.get_tool(tool_id)
        assert tool.content_hash != ""
        assert len(tool.content_hash) == 64  # SHA-256 hex

    def test_verify_integrity_passes_for_unmodified_tool(self):
        ToolRegistry, ToolType = self._make_registry()
        registry = ToolRegistry()
        tool_id = registry.register_tool(
            name="search",
            description="Search tool",
            tool_type=ToolType.SEARCH,
            handler=_sample_tool,
        )
        result = registry.verify_tool_integrity(tool_id)
        assert result["verified"] is True
        assert result["reason"] == ""

    def test_verify_integrity_by_name(self):
        ToolRegistry, ToolType = self._make_registry()
        registry = ToolRegistry()
        registry.register_tool(
            name="search",
            description="Search tool",
            tool_type=ToolType.SEARCH,
            handler=_sample_tool,
        )
        result = registry.verify_tool_integrity("search")
        assert result["verified"] is True

    def test_verify_integrity_nonexistent_tool(self):
        ToolRegistry, ToolType = self._make_registry()
        registry = ToolRegistry()
        result = registry.verify_tool_integrity("nonexistent")
        assert result["verified"] is False
        assert "not found" in result["reason"]

    def test_different_handlers_have_different_hashes(self):
        ToolRegistry, ToolType = self._make_registry()
        registry = ToolRegistry()
        id1 = registry.register_tool(
            name="tool_a",
            description="A",
            tool_type=ToolType.SEARCH,
            handler=_sample_tool,
        )
        id2 = registry.register_tool(
            name="tool_b",
            description="B",
            tool_type=ToolType.CUSTOM,
            handler=_another_tool,
        )
        t1 = registry.get_tool(id1)
        t2 = registry.get_tool(id2)
        assert t1.content_hash != t2.content_hash

    def test_execute_tool_blocks_on_integrity_failure(self):
        ToolRegistry, ToolType = self._make_registry()
        registry = ToolRegistry()
        tool_id = registry.register_tool(
            name="search",
            description="Search tool",
            tool_type=ToolType.SEARCH,
            handler=_sample_tool,
        )
        # Tamper: overwrite the stored hash
        tool = registry.get_tool(tool_id)
        tool.content_hash = "tampered_hash"
        result = registry.execute_tool("search", {"query": "test"})
        assert result["success"] is False
        assert "integrity" in result["error"].lower()

    def test_integrity_violations_logged(self):
        ToolRegistry, ToolType = self._make_registry()
        registry = ToolRegistry()
        tool_id = registry.register_tool(
            name="search",
            description="Search",
            tool_type=ToolType.SEARCH,
            handler=_sample_tool,
        )
        tool = registry.get_tool(tool_id)
        tool.content_hash = "bad_hash"
        registry.execute_tool("search", {"query": "x"})
        violations = registry.get_integrity_violations()
        assert len(violations) == 1
        assert violations[0]["tool_name"] == "search"


# ══════════════════════════════════════════════════════════════════
# 3. POLICY ENGINE FREEZE / IMMUTABILITY
# ══════════════════════════════════════════════════════════════════


class TestPolicyEngineFreeze:
    """Tests for PolicyEngine freeze() immutability."""

    def _make_engine(self):
        import sys
        import os
        cp_path = os.path.join(
            os.path.dirname(__file__),
            "..", "modules", "control-plane", "src",
        )
        if cp_path not in sys.path:
            sys.path.insert(0, os.path.abspath(cp_path))
        from agent_control_plane.policy_engine import PolicyEngine
        return PolicyEngine()

    def test_add_constraint_before_freeze(self):
        engine = self._make_engine()
        engine.add_constraint("finance", ["read", "calculate"])
        assert "finance" in engine.state_permissions

    def test_freeze_blocks_add_constraint(self):
        engine = self._make_engine()
        engine.add_constraint("finance", ["read"])
        engine.freeze()
        with pytest.raises(RuntimeError, match="frozen"):
            engine.add_constraint("finance", ["read", "write"])

    def test_freeze_blocks_set_agent_context(self):
        engine = self._make_engine()
        engine.freeze()
        with pytest.raises(RuntimeError, match="frozen"):
            engine.set_agent_context("agent-1", {"status": "admin"})

    def test_freeze_blocks_update_agent_context(self):
        engine = self._make_engine()
        engine.set_agent_context("agent-1", {"status": "user"})
        engine.freeze()
        with pytest.raises(RuntimeError, match="frozen"):
            engine.update_agent_context("agent-1", {"status": "admin"})

    def test_freeze_blocks_add_conditional_permission(self):
        from agent_control_plane.policy_engine import (
            Condition,
            ConditionalPermission,
        )
        engine = self._make_engine()
        engine.freeze()
        perm = ConditionalPermission(
            tool_name="refund",
            conditions=[Condition("user_status", "eq", "verified")],
        )
        with pytest.raises(RuntimeError, match="frozen"):
            engine.add_conditional_permission("finance", perm)

    def test_is_frozen_property(self):
        engine = self._make_engine()
        assert engine.is_frozen is False
        engine.freeze()
        assert engine.is_frozen is True

    def test_check_violation_still_works_after_freeze(self):
        engine = self._make_engine()
        engine.add_constraint("finance", ["read"])
        engine.freeze()
        # Read operations should still work
        violation = engine.check_violation("finance", "read", {})
        assert violation is None
        violation = engine.check_violation("finance", "write", {})
        assert violation is not None

    def test_mutation_log_records_operations(self):
        engine = self._make_engine()
        engine.add_constraint("finance", ["read"])
        engine.set_agent_context("a1", {"x": 1})
        engine.freeze()
        log = engine.mutation_log
        ops = [entry["operation"] for entry in log]
        assert "add_constraint" in ops
        assert "set_agent_context" in ops
        assert "freeze" in ops

    def test_mutation_log_records_blocked_attempts(self):
        engine = self._make_engine()
        engine.freeze()
        with pytest.raises(RuntimeError):
            engine.add_constraint("x", ["y"])
        log = engine.mutation_log
        blocked = [e for e in log if e["blocked"]]
        assert len(blocked) == 1
        assert blocked[0]["operation"] == "add_constraint"

    def test_frozen_dicts_are_immutable_proxies(self):
        """After freeze(), direct dict mutation raises TypeError."""
        engine = self._make_engine()
        engine.add_constraint("finance", ["read"])
        engine.set_agent_context("a1", {"status": "user"})
        engine.freeze()
        # Direct dict assignment should fail
        with pytest.raises(TypeError):
            engine.state_permissions["hacker"] = frozenset(["everything"])
        with pytest.raises(TypeError):
            engine.agent_contexts["hacker"] = {"admin": True}
        with pytest.raises(TypeError):
            engine.conditional_permissions["hacker"] = []

    def test_frozen_permissions_are_frozensets(self):
        engine = self._make_engine()
        engine.add_constraint("finance", ["read", "calculate"])
        engine.freeze()
        perms = engine.state_permissions.get("finance")
        assert isinstance(perms, frozenset)
        assert perms == frozenset(["read", "calculate"])


# ══════════════════════════════════════════════════════════════════
# 4. QUORUM CONFIG VALIDATION
# ══════════════════════════════════════════════════════════════════


class TestQuorumConfig:
    def test_valid_quorum(self):
        q = QuorumConfig(required_approvals=2, total_approvers=3)
        assert q.required_approvals == 2

    def test_invalid_required_approvals(self):
        with pytest.raises(ValueError, match="required_approvals"):
            QuorumConfig(required_approvals=0)

    def test_invalid_required_denials(self):
        with pytest.raises(ValueError, match="required_denials"):
            QuorumConfig(required_denials=0)


# ══════════════════════════════════════════════════════════════════
# 5. ESCALATION FATIGUE DETECTION
# ══════════════════════════════════════════════════════════════════


class TestEscalationFatigue:
    def test_fatigue_auto_denies_rapid_escalations(self):
        handler = EscalationHandler(
            timeout_seconds=0.1,
            fatigue_threshold=3,
            fatigue_window_seconds=60,
        )
        # First 3 escalations should be PENDING (normal)
        for i in range(3):
            req = handler.escalate(f"agent-1", f"action-{i}", "reason")
            assert req.decision == EscalationDecision.PENDING

        # 4th escalation should be auto-DENY (fatigue)
        req = handler.escalate("agent-1", "action-4", "reason")
        assert req.decision == EscalationDecision.DENY
        assert "fatigue" in req.reason.lower()
        assert req.resolved_by == "system:fatigue_detector"

    def test_fatigue_per_agent(self):
        handler = EscalationHandler(
            timeout_seconds=0.1,
            fatigue_threshold=2,
            fatigue_window_seconds=60,
        )
        # Agent-1 hits threshold
        handler.escalate("agent-1", "a1", "r")
        handler.escalate("agent-1", "a2", "r")
        req = handler.escalate("agent-1", "a3", "r")
        assert req.decision == EscalationDecision.DENY

        # Agent-2 is still under threshold
        req = handler.escalate("agent-2", "b1", "r")
        assert req.decision == EscalationDecision.PENDING

    def test_no_fatigue_when_disabled(self):
        handler = EscalationHandler(
            timeout_seconds=0.1,
            fatigue_threshold=None,
        )
        # Should never fatigue
        for i in range(20):
            req = handler.escalate("agent-1", f"action-{i}", "reason")
            assert req.decision == EscalationDecision.PENDING

    def test_fatigue_callback_not_fired_on_auto_deny(self):
        captured = []
        handler = EscalationHandler(
            timeout_seconds=0.1,
            fatigue_threshold=1,
            on_escalate=lambda req: captured.append(req),
        )
        # First: normal, callback fires
        handler.escalate("agent-1", "a1", "r")
        assert len(captured) == 1
        # Second: fatigued, callback should NOT fire
        handler.escalate("agent-1", "a2", "r")
        assert len(captured) == 1  # Still 1


# ══════════════════════════════════════════════════════════════════
# 6. QUORUM APPROVAL
# ══════════════════════════════════════════════════════════════════


class TestQuorumApproval:
    def test_single_approval_insufficient_for_quorum(self):
        queue = InMemoryApprovalQueue()
        handler = EscalationHandler(
            backend=queue,
            timeout_seconds=0.2,
            default_action=DefaultTimeoutAction.DENY,
            quorum=QuorumConfig(required_approvals=2, required_denials=1),
        )
        request = handler.escalate("agent-1", "deploy", "needs review")
        # One approval — not enough for quorum of 2
        queue.approve(request.request_id, approver="admin1")
        # Manually add vote tracking
        req = queue.get_decision(request.request_id)
        req.votes.append(("admin1", "ALLOW", req.resolved_at))
        decision = handler.resolve(request.request_id)
        # With only 1 vote and quorum=2, should timeout-deny
        assert decision == EscalationDecision.DENY

    def test_quorum_met_with_enough_approvals(self):
        queue = InMemoryApprovalQueue()
        handler = EscalationHandler(
            backend=queue,
            timeout_seconds=0.5,
            default_action=DefaultTimeoutAction.DENY,
            quorum=QuorumConfig(required_approvals=2, required_denials=2),
        )
        request = handler.escalate("agent-1", "deploy", "needs review")
        queue.approve(request.request_id, approver="admin1")
        req = queue.get_decision(request.request_id)
        req.votes.append(("admin1", "ALLOW", req.resolved_at))
        req.votes.append(("admin2", "ALLOW", req.resolved_at))
        decision = handler.resolve(request.request_id)
        assert decision == EscalationDecision.ALLOW

    def test_quorum_deny_on_single_denial(self):
        queue = InMemoryApprovalQueue()
        handler = EscalationHandler(
            backend=queue,
            timeout_seconds=0.5,
            default_action=DefaultTimeoutAction.ALLOW,
            quorum=QuorumConfig(required_approvals=2, required_denials=1),
        )
        request = handler.escalate("agent-1", "deploy", "needs review")
        queue.deny(request.request_id, approver="sec-team")
        req = queue.get_decision(request.request_id)
        req.votes.append(("sec-team", "DENY", req.resolved_at))
        decision = handler.resolve(request.request_id)
        assert decision == EscalationDecision.DENY

    def test_no_quorum_preserves_existing_behavior(self):
        queue = InMemoryApprovalQueue()
        handler = EscalationHandler(
            backend=queue,
            timeout_seconds=5,
            quorum=None,  # No quorum — existing behavior
        )
        import threading

        request = handler.escalate("agent-1", "action", "reason")

        def approve():
            time.sleep(0.1)
            queue.approve(request.request_id, approver="admin")

        t = threading.Thread(target=approve)
        t.start()
        decision = handler.resolve(request.request_id)
        t.join()
        assert decision == EscalationDecision.ALLOW
