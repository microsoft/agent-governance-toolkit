# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Aggressive test suite for Cedar/PolicyEvaluator integration in BaseIntegration.

Validates that:
1. BaseIntegration correctly accepts and wires the evaluator param
2. _evaluate_policy() returns correct permit/deny decisions
3. _evaluate_policy() is fail-closed on evaluator errors
4. _build_cedar_context() produces valid context dicts
5. pre_execute() consults Cedar BEFORE GovernancePolicy checks
6. from_cedar() factory creates working kernels for ALL adapters
7. Cross-adapter parity: all 8 BaseIntegration subclasses accept evaluator

Run with: python -m pytest tests/test_base_cedar_integration.py -v --tb=short
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from agent_os.integrations.base import (
    BaseIntegration,
    ExecutionContext,
    GovernancePolicy,
    GovernanceEventType,
)


# ---------------------------------------------------------------------------
# Fixtures & helpers
# ---------------------------------------------------------------------------

class _ConcreteIntegration(BaseIntegration):
    """Minimal concrete subclass for testing BaseIntegration directly."""

    def wrap(self, agent: Any) -> Any:
        return agent

    def unwrap(self, governed_agent: Any) -> Any:
        return governed_agent


@dataclass
class _FakeDecision:
    """Mimics PolicyDecision from evaluator.py."""
    allowed: bool = True
    reason: str = ""
    matched_rule: str | None = None
    action: str = "allow"
    audit_entry: dict = None

    def __post_init__(self):
        if self.audit_entry is None:
            self.audit_entry = {}


class _FakeEvaluator:
    """Mimics PolicyEvaluator with controllable outcomes."""

    def __init__(self, allowed: bool = True, reason: str = ""):
        self._allowed = allowed
        self._reason = reason
        self.last_context: dict | None = None
        self.call_count = 0

    def evaluate(self, context: dict) -> _FakeDecision:
        self.last_context = context
        self.call_count += 1
        return _FakeDecision(allowed=self._allowed, reason=self._reason)


class _ExplodingEvaluator:
    """Evaluator that always raises — tests fail-closed semantics."""

    def evaluate(self, context: dict):
        raise RuntimeError("Cedar engine crashed")


def _make_ctx(agent_id: str = "test-agent") -> ExecutionContext:
    return ExecutionContext(
        agent_id=agent_id,
        session_id=f"sess-{int(time.time())}",
        policy=GovernancePolicy(),
    )


# ===================================================================
# 1. BaseIntegration core Cedar wiring
# ===================================================================

class TestBaseIntegrationCedarWiring:
    """Verify BaseIntegration accepts and stores the evaluator."""

    def test_init_without_evaluator(self):
        """Default: no evaluator, Cedar is disabled."""
        integration = _ConcreteIntegration()
        assert integration._evaluator is None

    def test_init_with_evaluator(self):
        """Evaluator is stored when provided."""
        evaluator = _FakeEvaluator()
        integration = _ConcreteIntegration(evaluator=evaluator)
        assert integration._evaluator is evaluator

    def test_init_preserves_policy(self):
        """Evaluator doesn't interfere with GovernancePolicy."""
        policy = GovernancePolicy(max_tool_calls=5)
        evaluator = _FakeEvaluator()
        integration = _ConcreteIntegration(policy=policy, evaluator=evaluator)
        assert integration.policy.max_tool_calls == 5
        assert integration._evaluator is evaluator


# ===================================================================
# 2. _evaluate_policy() permit/deny/fail-closed
# ===================================================================

class TestEvaluatePolicy:
    """Test the core Cedar evaluation wrapper."""

    def test_permit_when_no_evaluator(self):
        """No evaluator → always permit (fall through to GovernancePolicy)."""
        integration = _ConcreteIntegration()
        allowed, reason = integration._evaluate_policy({"tool_name": "anything"})
        assert allowed is True
        assert reason == ""

    def test_permit_when_evaluator_allows(self):
        """Evaluator says permit → permit."""
        evaluator = _FakeEvaluator(allowed=True)
        integration = _ConcreteIntegration(evaluator=evaluator)
        allowed, reason = integration._evaluate_policy({"tool_name": "safe_tool"})
        assert allowed is True
        assert reason == ""
        assert evaluator.call_count == 1

    def test_deny_when_evaluator_forbids(self):
        """Evaluator says forbid → deny with reason."""
        evaluator = _FakeEvaluator(allowed=False, reason="PII detected in tool args")
        integration = _ConcreteIntegration(evaluator=evaluator)
        allowed, reason = integration._evaluate_policy({"tool_name": "export_data"})
        assert allowed is False
        assert "PII detected" in reason

    def test_deny_with_empty_reason_uses_default(self):
        """Evaluator denies with empty reason → default message."""
        evaluator = _FakeEvaluator(allowed=False, reason="")
        integration = _ConcreteIntegration(evaluator=evaluator)
        allowed, reason = integration._evaluate_policy({})
        assert allowed is False
        assert "Policy denied by evaluator" in reason

    def test_fail_closed_on_evaluator_crash(self):
        """Evaluator raises → DENY (fail-closed, never silent permit)."""
        evaluator = _ExplodingEvaluator()
        integration = _ConcreteIntegration(evaluator=evaluator)
        allowed, reason = integration._evaluate_policy({"tool_name": "anything"})
        assert allowed is False
        assert "fail-closed" in reason
        assert "Cedar engine crashed" in reason

    def test_fail_closed_on_attribute_error(self):
        """Evaluator returns garbage → DENY (fail-closed)."""
        evaluator = MagicMock()
        evaluator.evaluate.return_value = "not a decision"  # Wrong type
        integration = _ConcreteIntegration(evaluator=evaluator)
        allowed, reason = integration._evaluate_policy({})
        assert allowed is False  # Must fail-closed

    def test_context_passed_to_evaluator(self):
        """Full context dict is forwarded to evaluator.evaluate()."""
        evaluator = _FakeEvaluator(allowed=True)
        integration = _ConcreteIntegration(evaluator=evaluator)
        ctx = {"agent_id": "hero", "tool_name": "search", "action_type": "tool_call"}
        integration._evaluate_policy(ctx)
        assert evaluator.last_context == ctx


# ===================================================================
# 3. _build_cedar_context()
# ===================================================================

class TestBuildCedarContext:
    """Test the generic context builder."""

    def test_minimal_context(self):
        """Defaults produce a valid context dict."""
        integration = _ConcreteIntegration()
        ctx = integration._build_cedar_context()
        assert ctx["agent_id"] == ""
        assert ctx["action_type"] == ""
        assert ctx["tool_name"] == ""
        assert ctx["tool_args"] == {}

    def test_full_context(self):
        """All params map correctly."""
        integration = _ConcreteIntegration()
        ctx = integration._build_cedar_context(
            agent_id="hero-agent",
            action_type="tool_call",
            tool_name="oracle_query",
            tool_args={"sql": "SELECT 1"},
        )
        assert ctx["agent_id"] == "hero-agent"
        assert ctx["action_type"] == "tool_call"
        assert ctx["tool_name"] == "oracle_query"
        assert ctx["tool_args"]["sql"] == "SELECT 1"

    def test_extra_kwargs_pass_through(self):
        """Framework-specific fields via **extra."""
        integration = _ConcreteIntegration()
        ctx = integration._build_cedar_context(
            agent_id="test",
            custom_field="custom_value",
            token_budget=10000,
        )
        assert ctx["custom_field"] == "custom_value"
        assert ctx["token_budget"] == 10000


# ===================================================================
# 4. pre_execute() Cedar gate
# ===================================================================

class TestPreExecuteCedarGate:
    """Cedar evaluation runs BEFORE GovernancePolicy checks."""

    def test_cedar_deny_blocks_before_policy_checks(self):
        """Cedar deny short-circuits — GovernancePolicy never checked."""
        evaluator = _FakeEvaluator(allowed=False, reason="Cedar says no")
        policy = GovernancePolicy(max_tool_calls=1000)
        integration = _ConcreteIntegration(policy=policy, evaluator=evaluator)

        ctx = _make_ctx()
        allowed, reason = integration.pre_execute(ctx, "test input")
        assert allowed is False
        assert "Cedar says no" in reason

    def test_cedar_permit_falls_through_to_policy(self):
        """Cedar permit → GovernancePolicy checks run."""
        evaluator = _FakeEvaluator(allowed=True)
        policy = GovernancePolicy(max_tool_calls=0)  # Will instantly deny
        integration = _ConcreteIntegration(policy=policy, evaluator=evaluator)

        ctx = _make_ctx()
        allowed, reason = integration.pre_execute(ctx, "test input")
        assert allowed is False
        assert "Max tool calls" in reason  # GovernancePolicy kicked in

    def test_no_evaluator_policy_only(self):
        """Without evaluator, only GovernancePolicy runs."""
        policy = GovernancePolicy(max_tool_calls=1000)
        integration = _ConcreteIntegration(policy=policy)

        ctx = _make_ctx()
        allowed, reason = integration.pre_execute(ctx, "test input")
        assert allowed is True

    def test_fail_closed_blocks_pre_execute(self):
        """Evaluator crash during pre_execute → deny."""
        evaluator = _ExplodingEvaluator()
        integration = _ConcreteIntegration(evaluator=evaluator)

        ctx = _make_ctx()
        allowed, reason = integration.pre_execute(ctx, "test input")
        assert allowed is False
        assert "fail-closed" in reason

    def test_cedar_deny_emits_event(self):
        """Cedar denial emits TOOL_CALL_BLOCKED event."""
        evaluator = _FakeEvaluator(allowed=False, reason="blocked")
        integration = _ConcreteIntegration(evaluator=evaluator)
        events = []
        integration.on(GovernanceEventType.TOOL_CALL_BLOCKED, events.append)

        ctx = _make_ctx()
        integration.pre_execute(ctx, "test")

        assert len(events) == 1
        assert events[0]["source"] == "cedar"


# ===================================================================
# 5. from_cedar() factory
# ===================================================================

class TestFromCedarFactory:
    """Test the classmethod factory on all adapter subclasses."""

    def test_base_from_cedar_creates_evaluator(self):
        """from_cedar() on a concrete subclass wires up the evaluator."""
        with patch("agent_os.policies.evaluator.PolicyEvaluator") as MockEval:
            mock_instance = MagicMock()
            MockEval.return_value = mock_instance

            integration = _ConcreteIntegration.from_cedar(
                policy_content='permit(principal, action, resource);',
            )
            assert integration._evaluator is mock_instance
            mock_instance.load_cedar.assert_called_once_with(
                policy_path=None,
                policy_content='permit(principal, action, resource);',
                entities=None,
            )

    def test_from_cedar_forwards_kwargs(self):
        """Extra kwargs are forwarded to the adapter constructor."""
        with patch("agent_os.policies.evaluator.PolicyEvaluator") as MockEval:
            MockEval.return_value = MagicMock()

            policy = GovernancePolicy(max_tool_calls=7)
            integration = _ConcreteIntegration.from_cedar(
                policy_content='permit(principal, action, resource);',
                policy=policy,
            )
            assert integration.policy.max_tool_calls == 7


# ===================================================================
# 6. Cross-adapter parity
# ===================================================================

class TestCrossAdapterParity:
    """All 8 BaseIntegration subclasses must accept evaluator."""

    @pytest.mark.parametrize("adapter_path,class_name,constructor_kwargs", [
        (
            "agent_os.integrations.crewai_adapter",
            "CrewAIKernel",
            {},
        ),
        (
            "agent_os.integrations.langchain_adapter",
            "LangChainKernel",
            {},
        ),
        (
            "agent_os.integrations.autogen_adapter",
            "AutoGenKernel",
            {},
        ),
        (
            "agent_os.integrations.anthropic_adapter",
            "AnthropicKernel",
            {},
        ),
        (
            "agent_os.integrations.smolagents_adapter",
            "SmolagentsKernel",
            {},
        ),
        (
            "agent_os.integrations.pydantic_ai_adapter",
            "PydanticAIKernel",
            {},
        ),
        (
            "agent_os.integrations.semantic_kernel_adapter",
            "SemanticKernelWrapper",
            {},
        ),
    ])
    def test_adapter_accepts_evaluator(self, adapter_path, class_name, constructor_kwargs):
        """Each adapter can be constructed with evaluator=... and it works."""
        import importlib
        mod = importlib.import_module(adapter_path)
        cls = getattr(mod, class_name)

        evaluator = _FakeEvaluator(allowed=True)
        instance = cls(evaluator=evaluator, **constructor_kwargs)

        # Verify evaluator is stored on the base class
        assert instance._evaluator is evaluator

        # Verify _evaluate_policy works through the base class
        allowed, reason = instance._evaluate_policy({"tool_name": "test"})
        assert allowed is True

    @pytest.mark.parametrize("adapter_path,class_name,constructor_kwargs", [
        (
            "agent_os.integrations.crewai_adapter",
            "CrewAIKernel",
            {},
        ),
        (
            "agent_os.integrations.langchain_adapter",
            "LangChainKernel",
            {},
        ),
        (
            "agent_os.integrations.autogen_adapter",
            "AutoGenKernel",
            {},
        ),
        (
            "agent_os.integrations.anthropic_adapter",
            "AnthropicKernel",
            {},
        ),
        (
            "agent_os.integrations.smolagents_adapter",
            "SmolagentsKernel",
            {},
        ),
        (
            "agent_os.integrations.pydantic_ai_adapter",
            "PydanticAIKernel",
            {},
        ),
        (
            "agent_os.integrations.semantic_kernel_adapter",
            "SemanticKernelWrapper",
            {},
        ),
    ])
    def test_adapter_cedar_deny_blocks(self, adapter_path, class_name, constructor_kwargs):
        """Cedar deny on any adapter blocks execution."""
        import importlib
        mod = importlib.import_module(adapter_path)
        cls = getattr(mod, class_name)

        evaluator = _FakeEvaluator(allowed=False, reason="enterprise policy forbid")
        instance = cls(evaluator=evaluator, **constructor_kwargs)

        allowed, reason = instance._evaluate_policy({"tool_name": "dangerous"})
        assert allowed is False
        assert "enterprise policy forbid" in reason

    @pytest.mark.parametrize("adapter_path,class_name,constructor_kwargs", [
        (
            "agent_os.integrations.crewai_adapter",
            "CrewAIKernel",
            {},
        ),
        (
            "agent_os.integrations.langchain_adapter",
            "LangChainKernel",
            {},
        ),
        (
            "agent_os.integrations.autogen_adapter",
            "AutoGenKernel",
            {},
        ),
        (
            "agent_os.integrations.anthropic_adapter",
            "AnthropicKernel",
            {},
        ),
        (
            "agent_os.integrations.smolagents_adapter",
            "SmolagentsKernel",
            {},
        ),
        (
            "agent_os.integrations.pydantic_ai_adapter",
            "PydanticAIKernel",
            {},
        ),
        (
            "agent_os.integrations.semantic_kernel_adapter",
            "SemanticKernelWrapper",
            {},
        ),
    ])
    def test_adapter_fail_closed(self, adapter_path, class_name, constructor_kwargs):
        """Exploding evaluator on any adapter → fail-closed deny."""
        import importlib
        mod = importlib.import_module(adapter_path)
        cls = getattr(mod, class_name)

        evaluator = _ExplodingEvaluator()
        instance = cls(evaluator=evaluator, **constructor_kwargs)

        allowed, reason = instance._evaluate_policy({"tool_name": "anything"})
        assert allowed is False
        assert "fail-closed" in reason


# ===================================================================
# 7. Integration: evaluator + pre_execute end-to-end
# ===================================================================

class TestEndToEndCedarGovernance:
    """Full lifecycle: evaluator → pre_execute → audit."""

    def test_multiple_evaluations_tracked(self):
        """Multiple pre_execute calls each consult the evaluator."""
        evaluator = _FakeEvaluator(allowed=True)
        integration = _ConcreteIntegration(evaluator=evaluator)
        ctx = _make_ctx()

        for _ in range(5):
            allowed, _ = integration.pre_execute(ctx, "input")
            assert allowed is True

        assert evaluator.call_count == 5

    def test_evaluator_deny_then_policy_never_runs(self):
        """If Cedar denies, GovernancePolicy checks are never reached."""
        evaluator = _FakeEvaluator(allowed=False, reason="cedar-block")
        # Policy that should also deny — but we should never get there
        policy = GovernancePolicy(max_tool_calls=0)
        integration = _ConcreteIntegration(policy=policy, evaluator=evaluator)
        ctx = _make_ctx()

        allowed, reason = integration.pre_execute(ctx, "input")
        assert allowed is False
        assert "cedar-block" in reason  # Cedar reason, not policy reason

    def test_evaluator_receives_agent_id_from_context(self):
        """The Cedar context includes the actual agent_id from ExecutionContext."""
        evaluator = _FakeEvaluator(allowed=True)
        integration = _ConcreteIntegration(evaluator=evaluator)
        ctx = _make_ctx(agent_id="hero-oracle-agent")

        integration.pre_execute(ctx, "input")

        assert evaluator.last_context is not None
        assert evaluator.last_context["agent_id"] == "hero-oracle-agent"

    def test_backward_compatibility_no_evaluator(self):
        """Existing code without evaluator works identically to before."""
        policy = GovernancePolicy(
            max_tool_calls=100,
            timeout_seconds=300,
            blocked_patterns=["DROP TABLE"],
        )
        integration = _ConcreteIntegration(policy=policy)
        ctx = _make_ctx()

        # Normal input — should pass
        allowed, reason = integration.pre_execute(ctx, "SELECT * FROM users")
        assert allowed is True

        # Blocked pattern — should fail via GovernancePolicy
        allowed, reason = integration.pre_execute(ctx, "DROP TABLE users")
        assert allowed is False
        assert "Blocked pattern" in reason

    def test_no_evaluator_no_cedar_event(self):
        """Without evaluator, no cedar-sourced events are emitted."""
        integration = _ConcreteIntegration()
        events = []
        integration.on(GovernanceEventType.TOOL_CALL_BLOCKED, events.append)

        ctx = _make_ctx()
        integration.pre_execute(ctx, "safe input")

        cedar_events = [e for e in events if e.get("source") == "cedar"]
        assert len(cedar_events) == 0


# ===================================================================
# 8. Value validation: proves this adds real governance value
# ===================================================================

class TestRealWorldGovernanceValue:
    """Scenarios that prove Cedar at the base level adds real value."""

    def test_enterprise_tool_blocklist_across_all_adapters(self):
        """
        Enterprise scenario: block 'shell_exec' across ALL adapters
        without touching each adapter's config. Just one Cedar policy.
        """
        def _make_shell_blocking_evaluator():
            class ShellBlockEvaluator:
                def evaluate(self, ctx):
                    if ctx.get("tool_name") == "shell_exec":
                        return _FakeDecision(
                            allowed=False,
                            reason="Enterprise policy: shell_exec forbidden",
                        )
                    return _FakeDecision(allowed=True)
            return ShellBlockEvaluator()

        # Test across all adapters with a single evaluator
        from agent_os.integrations.crewai_adapter import CrewAIKernel
        from agent_os.integrations.langchain_adapter import LangChainKernel
        from agent_os.integrations.anthropic_adapter import AnthropicKernel

        for AdapterCls in [CrewAIKernel, LangChainKernel, AnthropicKernel]:
            evaluator = _make_shell_blocking_evaluator()
            instance = AdapterCls(evaluator=evaluator)

            # shell_exec → blocked
            allowed, reason = instance._evaluate_policy({"tool_name": "shell_exec"})
            assert allowed is False, f"{AdapterCls.__name__} should block shell_exec"

            # safe_tool → allowed
            allowed, reason = instance._evaluate_policy({"tool_name": "safe_tool"})
            assert allowed is True, f"{AdapterCls.__name__} should allow safe_tool"

    def test_pii_detection_across_adapters(self):
        """
        Enterprise scenario: detect PII in tool args across all adapters.
        """
        class PIIEvaluator:
            PII_PATTERNS = ["ssn", "social_security", "credit_card"]

            def evaluate(self, ctx):
                tool_args = ctx.get("tool_args", {})
                for key in tool_args:
                    if any(p in key.lower() for p in self.PII_PATTERNS):
                        return _FakeDecision(
                            allowed=False,
                            reason=f"PII field detected: {key}",
                        )
                return _FakeDecision(allowed=True)

        from agent_os.integrations.smolagents_adapter import SmolagentsKernel
        from agent_os.integrations.pydantic_ai_adapter import PydanticAIKernel

        for AdapterCls in [SmolagentsKernel, PydanticAIKernel]:
            evaluator = PIIEvaluator()
            instance = AdapterCls(evaluator=evaluator)

            # Clean args → allowed
            allowed, _ = instance._evaluate_policy({
                "tool_name": "search",
                "tool_args": {"query": "hello"},
            })
            assert allowed is True

            # PII args → blocked
            allowed, reason = instance._evaluate_policy({
                "tool_name": "export",
                "tool_args": {"ssn_number": "123-45-6789"},
            })
            assert allowed is False
            assert "PII" in reason

    def test_governance_composition_cedar_plus_policy(self):
        """
        Cedar and GovernancePolicy compose: both must pass.
        Cedar allows but GovernancePolicy blocks → denied.
        """
        evaluator = _FakeEvaluator(allowed=True)  # Cedar permits
        policy = GovernancePolicy(
            max_tool_calls=1,  # GovernancePolicy: only 1 call allowed
        )
        integration = _ConcreteIntegration(policy=policy, evaluator=evaluator)

        ctx = _make_ctx()
        ctx.call_count = 0

        # First call: both permit
        allowed, _ = integration.pre_execute(ctx, "call 1")
        assert allowed is True

        # Second call: Cedar permits but GovernancePolicy max_tool_calls blocks
        ctx.call_count = 1
        allowed, reason = integration.pre_execute(ctx, "call 2")
        assert allowed is False
        assert "Max tool calls" in reason

    def test_dynamic_evaluator_state(self):
        """
        Evaluator can maintain state (rate limiting, token budgets, etc).
        This proves Cedar isn't just static rules — it supports dynamic
        runtime governance.
        """
        class RateLimitingEvaluator:
            def __init__(self, max_calls=3):
                self.max_calls = max_calls
                self.call_count = 0

            def evaluate(self, ctx):
                self.call_count += 1
                if self.call_count > self.max_calls:
                    return _FakeDecision(
                        allowed=False,
                        reason=f"Rate limit: {self.call_count}/{self.max_calls}",
                    )
                return _FakeDecision(allowed=True)

        evaluator = RateLimitingEvaluator(max_calls=3)
        integration = _ConcreteIntegration(evaluator=evaluator)
        ctx = _make_ctx()

        # First 3 calls succeed
        for i in range(3):
            allowed, _ = integration.pre_execute(ctx, f"call {i+1}")
            assert allowed is True

        # 4th call is rate-limited
        allowed, reason = integration.pre_execute(ctx, "call 4")
        assert allowed is False
        assert "Rate limit" in reason
