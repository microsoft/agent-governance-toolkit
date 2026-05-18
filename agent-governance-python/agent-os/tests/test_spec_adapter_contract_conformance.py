# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Conformance tests for the Framework Adapter Contract specification.

Every test references a specific section of the specification.
Tests marked [Pure Specification] verify normative requirements.
Tests marked [Default Implementation] verify reference defaults.

These tests work WITHOUT optional framework SDKs installed (langchain,
crewai, autogen, etc.) by testing the base contract, data structures,
and adapter constructor defaults only.
"""

from __future__ import annotations

import unittest
from dataclasses import fields
from datetime import datetime
from unittest.mock import MagicMock

# ---------------------------------------------------------------------------
# Imports under test — base primitives (always available)
# ---------------------------------------------------------------------------

from agent_os.integrations.base import (
    BaseIntegration,
    BoundedSemaphore,
    CompositeInterceptor,
    ContentHashInterceptor,
    DriftResult,
    ExecutionContext,
    GovernanceEventType,
    GovernancePolicy,
    PatternType,
    PolicyInterceptor,
    PolicyViolationError,
    ToolCallInterceptor,
    ToolCallRequest,
    ToolCallResult,
)

# ---------------------------------------------------------------------------
# Optional adapter imports — each wrapped in try/except so tests run
# even when the underlying SDK is not installed.
# ---------------------------------------------------------------------------

try:
    from agent_os.integrations.langchain_adapter import LangChainKernel
    _HAS_LANGCHAIN_ADAPTER = True
except Exception:
    _HAS_LANGCHAIN_ADAPTER = False

try:
    from agent_os.integrations.crewai_adapter import CrewAIKernel
    _HAS_CREWAI_ADAPTER = True
except Exception:
    _HAS_CREWAI_ADAPTER = False

try:
    from agent_os.integrations.autogen_adapter import AutoGenKernel
    _HAS_AUTOGEN_ADAPTER = True
except Exception:
    _HAS_AUTOGEN_ADAPTER = False

try:
    from agent_os.integrations.openai_adapter import OpenAIKernel
    _HAS_OPENAI_ADAPTER = True
except Exception:
    _HAS_OPENAI_ADAPTER = False

try:
    from agent_os.integrations.anthropic_adapter import AnthropicKernel
    _HAS_ANTHROPIC_ADAPTER = True
except Exception:
    _HAS_ANTHROPIC_ADAPTER = False

try:
    from agent_os.integrations.google_adk_adapter import GoogleADKKernel
    _HAS_ADK_ADAPTER = True
except Exception:
    _HAS_ADK_ADAPTER = False

try:
    from agent_os.integrations.semantic_kernel_adapter import SemanticKernelWrapper
    _HAS_SK_ADAPTER = True
except Exception:
    _HAS_SK_ADAPTER = False

try:
    from agent_os.integrations.openai_agents_sdk import OpenAIAgentsKernel
    _HAS_OAI_AGENTS_ADAPTER = True
except Exception:
    _HAS_OAI_AGENTS_ADAPTER = False

try:
    from agent_os.integrations.pydantic_ai_adapter import PydanticAIKernel
    _HAS_PYDANTIC_AI_ADAPTER = True
except Exception:
    _HAS_PYDANTIC_AI_ADAPTER = False

try:
    from agent_os.integrations.smolagents_adapter import SmolagentsKernel
    _HAS_SMOLAGENTS_ADAPTER = True
except Exception:
    _HAS_SMOLAGENTS_ADAPTER = False


# ═══════════════════════════════════════════════════════════════════════════
# Section 4: GovernancePolicy
# ═══════════════════════════════════════════════════════════════════════════


class TestGovernancePolicy(unittest.TestCase):
    """Spec S4 -- GovernancePolicy creation, fields, deny rules."""

    def test_default_name(self):
        """S4.1 -- Default name is 'default'."""
        p = GovernancePolicy()
        self.assertEqual(p.name, "default")

    def test_default_max_tokens(self):
        """S4.2 -- Default max_tokens is 4096."""
        p = GovernancePolicy()
        self.assertEqual(p.max_tokens, 4096)

    def test_default_max_tool_calls(self):
        """S4.3 -- Default max_tool_calls is 10."""
        p = GovernancePolicy()
        self.assertEqual(p.max_tool_calls, 10)

    def test_default_allowed_tools_empty(self):
        """S4.4 -- Default allowed_tools is an empty list."""
        p = GovernancePolicy()
        self.assertEqual(p.allowed_tools, [])

    def test_default_blocked_patterns_empty(self):
        """S4.5 -- Default blocked_patterns is an empty list."""
        p = GovernancePolicy()
        self.assertEqual(p.blocked_patterns, [])

    def test_default_require_human_approval_false(self):
        """S4.6 -- Default require_human_approval is False."""
        p = GovernancePolicy()
        self.assertFalse(p.require_human_approval)

    def test_default_timeout_seconds(self):
        """S4.7 -- Default timeout_seconds is 300."""
        p = GovernancePolicy()
        self.assertEqual(p.timeout_seconds, 300)

    def test_default_confidence_threshold(self):
        """S4.8 -- Default confidence_threshold is 0.8."""
        p = GovernancePolicy()
        self.assertAlmostEqual(p.confidence_threshold, 0.8)

    def test_default_drift_threshold(self):
        """S4.9 -- Default drift_threshold is 0.15."""
        p = GovernancePolicy()
        self.assertAlmostEqual(p.drift_threshold, 0.15)

    def test_default_log_all_calls_true(self):
        """S4.10 -- Default log_all_calls is True."""
        p = GovernancePolicy()
        self.assertTrue(p.log_all_calls)

    def test_default_checkpoint_frequency(self):
        """S4.11 -- Default checkpoint_frequency is 5."""
        p = GovernancePolicy()
        self.assertEqual(p.checkpoint_frequency, 5)

    def test_default_max_concurrent(self):
        """S4.12 -- Default max_concurrent is 10."""
        p = GovernancePolicy()
        self.assertEqual(p.max_concurrent, 10)

    def test_default_backpressure_threshold(self):
        """S4.13 -- Default backpressure_threshold is 8."""
        p = GovernancePolicy()
        self.assertEqual(p.backpressure_threshold, 8)

    def test_default_version(self):
        """S4.14 -- Default version is '1.0.0'."""
        p = GovernancePolicy()
        self.assertEqual(p.version, "1.0.0")

    def test_custom_policy_fields(self):
        """S4.15 -- Custom policy fields are accepted."""
        p = GovernancePolicy(
            name="strict",
            max_tokens=2048,
            max_tool_calls=5,
            allowed_tools=["read_file"],
            require_human_approval=True,
            version="2.0.0",
        )
        self.assertEqual(p.name, "strict")
        self.assertEqual(p.max_tokens, 2048)
        self.assertEqual(p.max_tool_calls, 5)
        self.assertEqual(p.allowed_tools, ["read_file"])
        self.assertTrue(p.require_human_approval)
        self.assertEqual(p.version, "2.0.0")

    def test_invalid_max_tokens_raises(self):
        """S4.16 -- max_tokens=0 raises ValueError."""
        with self.assertRaises(ValueError):
            GovernancePolicy(max_tokens=0)

    def test_negative_max_tool_calls_raises(self):
        """S4.17 -- Negative max_tool_calls raises ValueError."""
        with self.assertRaises(ValueError):
            GovernancePolicy(max_tool_calls=-1)

    def test_zero_max_tool_calls_allowed(self):
        """S4.18 -- max_tool_calls=0 is valid (disables tool calls)."""
        p = GovernancePolicy(max_tool_calls=0)
        self.assertEqual(p.max_tool_calls, 0)

    def test_invalid_confidence_threshold_raises(self):
        """S4.19 -- confidence_threshold > 1.0 raises ValueError."""
        with self.assertRaises(ValueError):
            GovernancePolicy(confidence_threshold=1.5)

    def test_blocked_patterns_substring(self):
        """S4.20 -- Substring pattern matching works."""
        p = GovernancePolicy(blocked_patterns=["password"])
        matches = p.matches_pattern("my password is secret")
        self.assertIn("password", matches)

    def test_blocked_patterns_regex(self):
        """S4.21 -- Regex pattern matching works."""
        p = GovernancePolicy(
            blocked_patterns=[("rm\\s+-rf", PatternType.REGEX)]
        )
        matches = p.matches_pattern("rm -rf /")
        self.assertTrue(len(matches) > 0)

    def test_blocked_patterns_glob(self):
        """S4.22 -- Glob pattern matching works."""
        p = GovernancePolicy(
            blocked_patterns=[("*.exe", PatternType.GLOB)]
        )
        matches = p.matches_pattern("malware.exe")
        self.assertTrue(len(matches) > 0)

    def test_to_dict_round_trip(self):
        """S4.23 -- to_dict / from_dict round-trip preserves fields."""
        p = GovernancePolicy(name="test", max_tokens=1024, version="2.0.0")
        restored = GovernancePolicy.from_dict(p.to_dict())
        self.assertEqual(restored.name, p.name)
        self.assertEqual(restored.max_tokens, p.max_tokens)
        self.assertEqual(restored.version, p.version)

    def test_is_stricter_than(self):
        """S4.24 -- is_stricter_than detects stricter policies."""
        base = GovernancePolicy()
        strict = GovernancePolicy(max_tokens=1024, max_tool_calls=3)
        self.assertTrue(strict.is_stricter_than(base))

    def test_detect_conflicts_backpressure(self):
        """S4.25 -- detect_conflicts warns on useless backpressure."""
        p = GovernancePolicy(max_concurrent=10, backpressure_threshold=10)
        warnings = p.detect_conflicts()
        self.assertTrue(any("backpressure" in w for w in warnings))

    def test_policy_is_hashable(self):
        """S4.26 -- GovernancePolicy is hashable."""
        p = GovernancePolicy()
        self.assertIsInstance(hash(p), int)

    def test_policy_repr(self):
        """S4.27 -- GovernancePolicy repr includes key fields."""
        p = GovernancePolicy()
        r = repr(p)
        self.assertIn("max_tokens=", r)
        self.assertIn("version=", r)

    def test_empty_version_raises(self):
        """S4.28 -- Empty version string raises ValueError."""
        with self.assertRaises(ValueError):
            GovernancePolicy(version="")


# ═══════════════════════════════════════════════════════════════════════════
# Section 4: ExecutionContext
# ═══════════════════════════════════════════════════════════════════════════


class TestExecutionContext(unittest.TestCase):
    """Spec S4 -- ExecutionContext creation, agent_id."""

    def test_context_creation(self):
        """S4.29 -- ExecutionContext can be created with required fields."""
        p = GovernancePolicy()
        ctx = ExecutionContext(agent_id="agent-1", session_id="s1", policy=p)
        self.assertEqual(ctx.agent_id, "agent-1")
        self.assertEqual(ctx.session_id, "s1")
        self.assertIsInstance(ctx.policy, GovernancePolicy)

    def test_context_default_call_count(self):
        """S4.30 -- Default call_count is 0."""
        p = GovernancePolicy()
        ctx = ExecutionContext(agent_id="a1", session_id="s1", policy=p)
        self.assertEqual(ctx.call_count, 0)

    def test_context_default_total_tokens(self):
        """S4.31 -- Default total_tokens is 0."""
        p = GovernancePolicy()
        ctx = ExecutionContext(agent_id="a1", session_id="s1", policy=p)
        self.assertEqual(ctx.total_tokens, 0)

    def test_context_default_checkpoints(self):
        """S4.32 -- Default checkpoints is empty list."""
        p = GovernancePolicy()
        ctx = ExecutionContext(agent_id="a1", session_id="s1", policy=p)
        self.assertEqual(ctx.checkpoints, [])

    def test_context_has_start_time(self):
        """S4.33 -- ExecutionContext has start_time as datetime."""
        p = GovernancePolicy()
        ctx = ExecutionContext(agent_id="a1", session_id="s1", policy=p)
        self.assertIsInstance(ctx.start_time, datetime)

    def test_context_invalid_agent_id_empty(self):
        """S4.34 -- Empty agent_id raises ValueError."""
        with self.assertRaises(ValueError):
            ExecutionContext(
                agent_id="", session_id="s1", policy=GovernancePolicy()
            )

    def test_context_invalid_agent_id_pattern(self):
        """S4.35 -- agent_id with spaces raises ValueError."""
        with self.assertRaises(ValueError):
            ExecutionContext(
                agent_id="bad agent", session_id="s1", policy=GovernancePolicy()
            )

    def test_context_invalid_session_id_empty(self):
        """S4.36 -- Empty session_id raises ValueError."""
        with self.assertRaises(ValueError):
            ExecutionContext(
                agent_id="a1", session_id="", policy=GovernancePolicy()
            )

    def test_context_repr(self):
        """S4.37 -- ExecutionContext repr includes agent_id."""
        p = GovernancePolicy()
        ctx = ExecutionContext(agent_id="a1", session_id="s1", policy=p)
        self.assertIn("a1", repr(ctx))


# ═══════════════════════════════════════════════════════════════════════════
# Section 4: ToolCallRequest
# ═══════════════════════════════════════════════════════════════════════════


class TestToolCallRequest(unittest.TestCase):
    """Spec S4 -- ToolCallRequest fields."""

    def test_request_creation(self):
        """S4.38 -- ToolCallRequest creation with required fields."""
        req = ToolCallRequest(tool_name="search", arguments={"q": "test"})
        self.assertEqual(req.tool_name, "search")
        self.assertEqual(req.arguments, {"q": "test"})

    def test_request_default_call_id(self):
        """S4.39 -- Default call_id is empty string."""
        req = ToolCallRequest(tool_name="t", arguments={})
        self.assertEqual(req.call_id, "")

    def test_request_default_agent_id(self):
        """S4.40 -- Default agent_id is empty string."""
        req = ToolCallRequest(tool_name="t", arguments={})
        self.assertEqual(req.agent_id, "")

    def test_request_default_metadata(self):
        """S4.41 -- Default metadata is empty dict."""
        req = ToolCallRequest(tool_name="t", arguments={})
        self.assertEqual(req.metadata, {})

    def test_request_repr(self):
        """S4.42 -- ToolCallRequest repr includes tool_name."""
        req = ToolCallRequest(tool_name="calc", arguments={})
        self.assertIn("calc", repr(req))


# ═══════════════════════════════════════════════════════════════════════════
# Section 4: ToolCallResult
# ═══════════════════════════════════════════════════════════════════════════


class TestToolCallResult(unittest.TestCase):
    """Spec S4 -- ToolCallResult fields."""

    def test_result_allowed(self):
        """S4.43 -- ToolCallResult allowed=True."""
        r = ToolCallResult(allowed=True)
        self.assertTrue(r.allowed)

    def test_result_denied(self):
        """S4.44 -- ToolCallResult allowed=False with reason."""
        r = ToolCallResult(allowed=False, reason="blocked")
        self.assertFalse(r.allowed)
        self.assertEqual(r.reason, "blocked")

    def test_result_default_reason_none(self):
        """S4.45 -- Default reason is None."""
        r = ToolCallResult(allowed=True)
        self.assertIsNone(r.reason)

    def test_result_default_modified_arguments_none(self):
        """S4.46 -- Default modified_arguments is None."""
        r = ToolCallResult(allowed=True)
        self.assertIsNone(r.modified_arguments)

    def test_result_default_audit_entry_none(self):
        """S4.47 -- Default audit_entry is None."""
        r = ToolCallResult(allowed=True)
        self.assertIsNone(r.audit_entry)

    def test_result_repr(self):
        """S4.48 -- ToolCallResult repr includes allowed."""
        r = ToolCallResult(allowed=False, reason="test")
        self.assertIn("False", repr(r))


# ═══════════════════════════════════════════════════════════════════════════
# Section 5: PolicyInterceptor
# ═══════════════════════════════════════════════════════════════════════════


class TestPolicyInterceptor(unittest.TestCase):
    """Spec S5 -- PolicyInterceptor chain, composite interceptor."""

    def test_policy_interceptor_allows_valid_call(self):
        """S5.1 -- PolicyInterceptor allows a valid tool call."""
        p = GovernancePolicy(allowed_tools=["search"])
        interceptor = PolicyInterceptor(p)
        req = ToolCallRequest(tool_name="search", arguments={"q": "test"})
        result = interceptor.intercept(req)
        self.assertTrue(result.allowed)

    def test_policy_interceptor_denies_unapproved_tool(self):
        """S5.2 -- PolicyInterceptor denies tool not in allowed_tools."""
        p = GovernancePolicy(allowed_tools=["search"])
        interceptor = PolicyInterceptor(p)
        req = ToolCallRequest(tool_name="delete", arguments={})
        result = interceptor.intercept(req)
        self.assertFalse(result.allowed)

    def test_policy_interceptor_denies_blocked_pattern(self):
        """S5.3 -- PolicyInterceptor denies tool args with blocked pattern."""
        p = GovernancePolicy(blocked_patterns=["password"])
        interceptor = PolicyInterceptor(p)
        req = ToolCallRequest(tool_name="t", arguments={"data": "password=secret"})
        result = interceptor.intercept(req)
        self.assertFalse(result.allowed)

    def test_policy_interceptor_denies_human_approval(self):
        """S5.4 -- PolicyInterceptor denies when human approval required."""
        p = GovernancePolicy(require_human_approval=True)
        interceptor = PolicyInterceptor(p)
        req = ToolCallRequest(tool_name="t", arguments={})
        result = interceptor.intercept(req)
        self.assertFalse(result.allowed)

    def test_composite_interceptor_all_allow(self):
        """S5.5 -- CompositeInterceptor allows when all interceptors allow."""
        p = GovernancePolicy()
        composite = CompositeInterceptor([PolicyInterceptor(p)])
        req = ToolCallRequest(tool_name="t", arguments={})
        result = composite.intercept(req)
        self.assertTrue(result.allowed)

    def test_composite_interceptor_one_denies(self):
        """S5.6 -- CompositeInterceptor denies when any interceptor denies."""
        allow_policy = GovernancePolicy()
        deny_policy = GovernancePolicy(require_human_approval=True)
        composite = CompositeInterceptor([
            PolicyInterceptor(allow_policy),
            PolicyInterceptor(deny_policy),
        ])
        req = ToolCallRequest(tool_name="t", arguments={})
        result = composite.intercept(req)
        self.assertFalse(result.allowed)

    def test_composite_interceptor_add_returns_self(self):
        """S5.7 -- CompositeInterceptor.add() returns self for chaining."""
        composite = CompositeInterceptor()
        result = composite.add(PolicyInterceptor(GovernancePolicy()))
        self.assertIs(result, composite)

    def test_composite_interceptor_empty_allows(self):
        """S5.8 -- Empty CompositeInterceptor allows all calls."""
        composite = CompositeInterceptor()
        req = ToolCallRequest(tool_name="t", arguments={})
        result = composite.intercept(req)
        self.assertTrue(result.allowed)

    def test_content_hash_interceptor_strict_no_hash(self):
        """S5.9 -- ContentHashInterceptor strict mode denies unknown tool."""
        interceptor = ContentHashInterceptor(strict=True)
        req = ToolCallRequest(tool_name="unknown", arguments={})
        result = interceptor.intercept(req)
        self.assertFalse(result.allowed)

    def test_content_hash_interceptor_nonstrict_allows_unknown(self):
        """S5.10 -- ContentHashInterceptor non-strict allows unknown tool."""
        interceptor = ContentHashInterceptor(strict=False)
        req = ToolCallRequest(tool_name="unknown", arguments={})
        result = interceptor.intercept(req)
        self.assertTrue(result.allowed)

    def test_content_hash_interceptor_matching_hash(self):
        """S5.11 -- ContentHashInterceptor allows matching hash."""
        interceptor = ContentHashInterceptor(tool_hashes={"calc": "abc123"})
        req = ToolCallRequest(
            tool_name="calc", arguments={},
            metadata={"content_hash": "abc123"},
        )
        result = interceptor.intercept(req)
        self.assertTrue(result.allowed)

    def test_content_hash_interceptor_mismatched_hash(self):
        """S5.12 -- ContentHashInterceptor denies mismatched hash."""
        interceptor = ContentHashInterceptor(tool_hashes={"calc": "abc123"})
        req = ToolCallRequest(
            tool_name="calc", arguments={},
            metadata={"content_hash": "wrong"},
        )
        result = interceptor.intercept(req)
        self.assertFalse(result.allowed)

    def test_policy_interceptor_max_calls_exceeded(self):
        """S5.13 -- PolicyInterceptor denies when call count exceeds max."""
        p = GovernancePolicy(max_tool_calls=2)
        ctx = ExecutionContext(agent_id="a1", session_id="s1", policy=p)
        ctx.call_count = 2
        interceptor = PolicyInterceptor(p, context=ctx)
        req = ToolCallRequest(tool_name="t", arguments={})
        result = interceptor.intercept(req)
        self.assertFalse(result.allowed)


# ═══════════════════════════════════════════════════════════════════════════
# Section 3: BaseIntegration Contract
# ═══════════════════════════════════════════════════════════════════════════


class TestBaseIntegrationContract(unittest.TestCase):
    """Spec S3 -- Abstract methods, from_cedar factory, event & signal system."""

    def test_base_is_abstract(self):
        """S3.1 -- BaseIntegration cannot be instantiated directly."""
        with self.assertRaises(TypeError):
            BaseIntegration()

    def test_wrap_is_abstract(self):
        """S3.2 -- 'wrap' is an abstract method."""
        self.assertTrue(hasattr(BaseIntegration, "wrap"))

    def test_unwrap_is_abstract(self):
        """S3.3 -- 'unwrap' is an abstract method."""
        self.assertTrue(hasattr(BaseIntegration, "unwrap"))

    def test_from_cedar_exists(self):
        """S3.4 -- from_cedar is a classmethod on BaseIntegration."""
        self.assertTrue(hasattr(BaseIntegration, "from_cedar"))
        self.assertTrue(callable(BaseIntegration.from_cedar))

    def test_on_event_and_emit(self):
        """S3.5 -- Event system: on() registers listener, emit() fires it."""
        received = []

        class _Concrete(BaseIntegration):
            def wrap(self, agent):
                return agent

            def unwrap(self, governed_agent):
                return governed_agent

        kernel = _Concrete()
        kernel.on(GovernanceEventType.POLICY_CHECK, lambda data: received.append(data))
        kernel.emit(GovernanceEventType.POLICY_CHECK, {"test": True})
        self.assertEqual(len(received), 1)
        self.assertTrue(received[0]["test"])

    def test_emit_listener_error_does_not_propagate(self):
        """S3.6 -- Listener error doesn't break emit()."""
        class _Concrete(BaseIntegration):
            def wrap(self, agent):
                return agent

            def unwrap(self, governed_agent):
                return governed_agent

        kernel = _Concrete()
        kernel.on(GovernanceEventType.POLICY_CHECK, lambda data: 1 / 0)
        # Should not raise
        kernel.emit(GovernanceEventType.POLICY_CHECK, {"test": True})

    def test_signal_system(self):
        """S3.7 -- on_signal() registers handler, signal() fires it."""
        called = []

        class _Concrete(BaseIntegration):
            def wrap(self, agent):
                return agent

            def unwrap(self, governed_agent):
                return governed_agent

        kernel = _Concrete()
        kernel.on_signal("SIGSTOP", lambda aid: called.append(aid))
        kernel.signal("agent-1", "SIGSTOP")
        self.assertEqual(called, ["agent-1"])

    def test_create_context(self):
        """S3.8 -- create_context returns ExecutionContext with deep-copied policy."""
        class _Concrete(BaseIntegration):
            def wrap(self, agent):
                return agent

            def unwrap(self, governed_agent):
                return governed_agent

        kernel = _Concrete(policy=GovernancePolicy(max_tokens=2048))
        ctx = kernel.create_context("agent-1")
        self.assertEqual(ctx.agent_id, "agent-1")
        self.assertEqual(ctx.policy.max_tokens, 2048)
        # Verify deep copy — mutating original should not affect context
        kernel.policy.max_tokens = 9999
        self.assertEqual(ctx.policy.max_tokens, 2048)

    def test_default_policy_when_none(self):
        """S3.9 -- BaseIntegration uses default GovernancePolicy when None."""
        class _Concrete(BaseIntegration):
            def wrap(self, agent):
                return agent

            def unwrap(self, governed_agent):
                return governed_agent

        kernel = _Concrete()
        self.assertIsInstance(kernel.policy, GovernancePolicy)

    def test_evaluate_policy_no_evaluator(self):
        """S3.10 -- _evaluate_policy returns (True, '') with no evaluator."""
        class _Concrete(BaseIntegration):
            def wrap(self, agent):
                return agent

            def unwrap(self, governed_agent):
                return governed_agent

        kernel = _Concrete()
        allowed, reason = kernel._evaluate_policy({"agent_id": "a"})
        self.assertTrue(allowed)
        self.assertEqual(reason, "")

    def test_governance_event_type_values(self):
        """S3.11 -- GovernanceEventType has required enum values."""
        self.assertEqual(GovernanceEventType.POLICY_CHECK.value, "policy_check")
        self.assertEqual(GovernanceEventType.POLICY_VIOLATION.value, "policy_violation")
        self.assertEqual(GovernanceEventType.TOOL_CALL_BLOCKED.value, "tool_call_blocked")
        self.assertEqual(GovernanceEventType.CHECKPOINT_CREATED.value, "checkpoint_created")
        self.assertEqual(GovernanceEventType.DRIFT_DETECTED.value, "drift_detected")

    def test_pattern_type_values(self):
        """S3.12 -- PatternType has required enum values."""
        self.assertEqual(PatternType.SUBSTRING.value, "substring")
        self.assertEqual(PatternType.REGEX.value, "regex")
        self.assertEqual(PatternType.GLOB.value, "glob")

    def test_drift_result_repr(self):
        """S3.13 -- DriftResult repr indicates OK/EXCEEDED."""
        ok = DriftResult(score=0.05, exceeded=False, threshold=0.15,
                         baseline_hash="a", current_hash="b")
        self.assertIn("OK", repr(ok))
        exceeded = DriftResult(score=0.5, exceeded=True, threshold=0.15,
                               baseline_hash="a", current_hash="b")
        self.assertIn("EXCEEDED", repr(exceeded))


# ═══════════════════════════════════════════════════════════════════════════
# Section 2: Adapter Exports
# ═══════════════════════════════════════════════════════════════════════════


class TestAdapterExports(unittest.TestCase):
    """Spec S2 -- All adapters importable from integrations module."""

    def test_base_exports(self):
        """S2.1 -- Base types are importable from agent_os.integrations."""
        from agent_os.integrations import (
            BaseIntegration,
            GovernancePolicy,
            ToolCallRequest,
            ToolCallResult,
            PolicyInterceptor,
            CompositeInterceptor,
        )
        self.assertTrue(callable(GovernancePolicy))

    def test_langchain_in_all(self):
        """S2.2 -- LangChainKernel is in __all__."""
        from agent_os.integrations import __all__
        self.assertIn("LangChainKernel", __all__)

    def test_crewai_in_all(self):
        """S2.3 -- CrewAIKernel is in __all__."""
        from agent_os.integrations import __all__
        self.assertIn("CrewAIKernel", __all__)

    def test_autogen_in_all(self):
        """S2.4 -- AutoGenKernel is in __all__."""
        from agent_os.integrations import __all__
        self.assertIn("AutoGenKernel", __all__)

    def test_openai_in_all(self):
        """S2.5 -- OpenAIKernel is in __all__."""
        from agent_os.integrations import __all__
        self.assertIn("OpenAIKernel", __all__)

    def test_anthropic_in_all(self):
        """S2.6 -- AnthropicKernel is in __all__."""
        from agent_os.integrations import __all__
        self.assertIn("AnthropicKernel", __all__)

    def test_google_adk_in_all(self):
        """S2.7 -- GoogleADKKernel is in __all__."""
        from agent_os.integrations import __all__
        self.assertIn("GoogleADKKernel", __all__)

    def test_semantic_kernel_in_all(self):
        """S2.8 -- SemanticKernelWrapper is in __all__."""
        from agent_os.integrations import __all__
        self.assertIn("SemanticKernelWrapper", __all__)

    def test_pydantic_ai_in_all(self):
        """S2.9 -- PydanticAIKernel is in __all__."""
        from agent_os.integrations import __all__
        self.assertIn("PydanticAIKernel", __all__)

    def test_smolagents_in_all(self):
        """S2.10 -- SmolagentsKernel is in __all__."""
        from agent_os.integrations import __all__
        self.assertIn("SmolagentsKernel", __all__)

    def test_bounded_semaphore_exported(self):
        """S2.11 -- BoundedSemaphore is importable."""
        from agent_os.integrations import BoundedSemaphore
        self.assertTrue(callable(BoundedSemaphore))


# ═══════════════════════════════════════════════════════════════════════════
# Section 7: LangChainAdapter
# ═══════════════════════════════════════════════════════════════════════════


@unittest.skipUnless(_HAS_LANGCHAIN_ADAPTER, "LangChain adapter not importable")
class TestLangChainAdapter(unittest.TestCase):
    """Spec S7 -- LangChainAdapter constructor defaults, as_middleware."""

    def test_default_policy(self):
        """S7.1 -- LangChainKernel default policy is GovernancePolicy()."""
        k = LangChainKernel()
        self.assertIsInstance(k.policy, GovernancePolicy)

    def test_is_base_integration(self):
        """S7.2 -- LangChainKernel inherits BaseIntegration."""
        self.assertTrue(issubclass(LangChainKernel, BaseIntegration))

    def test_has_as_middleware(self):
        """S7.3 -- LangChainKernel has as_middleware method."""
        self.assertTrue(hasattr(LangChainKernel, "as_middleware"))

    def test_has_wrap(self):
        """S7.4 -- LangChainKernel has wrap method."""
        self.assertTrue(hasattr(LangChainKernel, "wrap"))

    def test_has_health_check(self):
        """S7.5 -- LangChainKernel has health_check method."""
        self.assertTrue(hasattr(LangChainKernel, "health_check"))

    def test_custom_policy(self):
        """S7.6 -- LangChainKernel accepts custom policy."""
        p = GovernancePolicy(max_tokens=512)
        k = LangChainKernel(policy=p)
        self.assertEqual(k.policy.max_tokens, 512)


# ═══════════════════════════════════════════════════════════════════════════
# Section 8: CrewAIAdapter
# ═══════════════════════════════════════════════════════════════════════════


@unittest.skipUnless(_HAS_CREWAI_ADAPTER, "CrewAI adapter not importable")
class TestCrewAIAdapter(unittest.TestCase):
    """Spec S8 -- CrewAIAdapter constructor defaults, as_hooks."""

    def test_default_policy(self):
        """S8.1 -- CrewAIKernel default policy is GovernancePolicy()."""
        k = CrewAIKernel()
        self.assertIsInstance(k.policy, GovernancePolicy)

    def test_is_base_integration(self):
        """S8.2 -- CrewAIKernel inherits BaseIntegration."""
        self.assertTrue(issubclass(CrewAIKernel, BaseIntegration))

    def test_has_as_hooks(self):
        """S8.3 -- CrewAIKernel has as_hooks method."""
        self.assertTrue(hasattr(CrewAIKernel, "as_hooks"))

    def test_has_wrap(self):
        """S8.4 -- CrewAIKernel has wrap method."""
        self.assertTrue(hasattr(CrewAIKernel, "wrap"))

    def test_custom_policy(self):
        """S8.5 -- CrewAIKernel accepts custom policy."""
        p = GovernancePolicy(max_tool_calls=3)
        k = CrewAIKernel(policy=p)
        self.assertEqual(k.policy.max_tool_calls, 3)


# ═══════════════════════════════════════════════════════════════════════════
# Section 9: AutoGenAdapter
# ═══════════════════════════════════════════════════════════════════════════


@unittest.skipUnless(_HAS_AUTOGEN_ADAPTER, "AutoGen adapter not importable")
class TestAutoGenAdapter(unittest.TestCase):
    """Spec S9 -- AutoGenAdapter constructor defaults, as_handler."""

    def test_default_policy(self):
        """S9.1 -- AutoGenKernel default policy is GovernancePolicy()."""
        k = AutoGenKernel()
        self.assertIsInstance(k.policy, GovernancePolicy)

    def test_is_base_integration(self):
        """S9.2 -- AutoGenKernel inherits BaseIntegration."""
        self.assertTrue(issubclass(AutoGenKernel, BaseIntegration))

    def test_has_as_handler(self):
        """S9.3 -- AutoGenKernel has as_handler method."""
        self.assertTrue(hasattr(AutoGenKernel, "as_handler"))

    def test_has_health_check(self):
        """S9.4 -- AutoGenKernel has health_check method."""
        self.assertTrue(hasattr(AutoGenKernel, "health_check"))

    def test_custom_policy(self):
        """S9.5 -- AutoGenKernel accepts custom policy."""
        p = GovernancePolicy(blocked_patterns=["DROP TABLE"])
        k = AutoGenKernel(policy=p)
        self.assertEqual(len(k.policy.blocked_patterns), 1)


# ═══════════════════════════════════════════════════════════════════════════
# Section 10: OpenAIAdapter
# ═══════════════════════════════════════════════════════════════════════════


@unittest.skipUnless(_HAS_OPENAI_ADAPTER, "OpenAI adapter not importable")
class TestOpenAIAdapter(unittest.TestCase):
    """Spec S10 -- OpenAIAdapter constructor defaults."""

    def test_default_policy(self):
        """S10.1 -- OpenAIKernel default policy is GovernancePolicy()."""
        k = OpenAIKernel()
        self.assertIsInstance(k.policy, GovernancePolicy)

    def test_is_base_integration(self):
        """S10.2 -- OpenAIKernel inherits BaseIntegration."""
        self.assertTrue(issubclass(OpenAIKernel, BaseIntegration))

    def test_has_health_check(self):
        """S10.3 -- OpenAIKernel has health_check method."""
        self.assertTrue(hasattr(OpenAIKernel, "health_check"))

    def test_custom_policy(self):
        """S10.4 -- OpenAIKernel accepts custom policy."""
        p = GovernancePolicy(timeout_seconds=60)
        k = OpenAIKernel(policy=p)
        self.assertEqual(k.policy.timeout_seconds, 60)


# ═══════════════════════════════════════════════════════════════════════════
# Section 11: AnthropicAdapter
# ═══════════════════════════════════════════════════════════════════════════


@unittest.skipUnless(_HAS_ANTHROPIC_ADAPTER, "Anthropic adapter not importable")
class TestAnthropicAdapter(unittest.TestCase):
    """Spec S11 -- AnthropicAdapter constructor defaults, as_message_hook."""

    def test_default_policy(self):
        """S11.1 -- AnthropicKernel default policy is GovernancePolicy()."""
        k = AnthropicKernel()
        self.assertIsInstance(k.policy, GovernancePolicy)

    def test_is_base_integration(self):
        """S11.2 -- AnthropicKernel inherits BaseIntegration."""
        self.assertTrue(issubclass(AnthropicKernel, BaseIntegration))

    def test_has_as_message_hook(self):
        """S11.3 -- AnthropicKernel has as_message_hook method."""
        self.assertTrue(hasattr(AnthropicKernel, "as_message_hook"))

    def test_has_health_check(self):
        """S11.4 -- AnthropicKernel has health_check method."""
        self.assertTrue(hasattr(AnthropicKernel, "health_check"))

    def test_custom_policy(self):
        """S11.5 -- AnthropicKernel accepts custom policy."""
        p = GovernancePolicy(confidence_threshold=0.95)
        k = AnthropicKernel(policy=p)
        self.assertAlmostEqual(k.policy.confidence_threshold, 0.95)


# ═══════════════════════════════════════════════════════════════════════════
# Section 12: GoogleADKAdapter
# ═══════════════════════════════════════════════════════════════════════════


@unittest.skipUnless(_HAS_ADK_ADAPTER, "Google ADK adapter not importable")
class TestGoogleADKAdapter(unittest.TestCase):
    """Spec S12 -- GoogleADKAdapter constructor defaults, max_tool_calls=50."""

    def test_default_policy(self):
        """S12.1 -- GoogleADKKernel default policy is GovernancePolicy()."""
        k = GoogleADKKernel()
        self.assertIsInstance(k.policy, GovernancePolicy)

    def test_is_base_integration(self):
        """S12.2 -- GoogleADKKernel inherits BaseIntegration."""
        self.assertTrue(issubclass(GoogleADKKernel, BaseIntegration))

    def test_max_tool_calls_default_50(self):
        """S12.3 -- GoogleADKKernel default max_tool_calls is 50."""
        k = GoogleADKKernel()
        self.assertEqual(k.policy.max_tool_calls, 50)

    def test_has_health_check(self):
        """S12.4 -- GoogleADKKernel has health_check method."""
        self.assertTrue(hasattr(GoogleADKKernel, "health_check"))


# ═══════════════════════════════════════════════════════════════════════════
# Section 13: SemanticKernelAdapter
# ═══════════════════════════════════════════════════════════════════════════


@unittest.skipUnless(_HAS_SK_ADAPTER, "Semantic Kernel adapter not importable")
class TestSemanticKernelAdapter(unittest.TestCase):
    """Spec S13 -- SemanticKernelAdapter constructor defaults, as_filter."""

    def test_default_policy(self):
        """S13.1 -- SemanticKernelWrapper default policy is GovernancePolicy()."""
        k = SemanticKernelWrapper()
        self.assertIsInstance(k.policy, GovernancePolicy)

    def test_is_base_integration(self):
        """S13.2 -- SemanticKernelWrapper inherits BaseIntegration."""
        self.assertTrue(issubclass(SemanticKernelWrapper, BaseIntegration))

    def test_has_as_filter(self):
        """S13.3 -- SemanticKernelWrapper has as_filter method."""
        self.assertTrue(hasattr(SemanticKernelWrapper, "as_filter"))

    def test_has_health_check(self):
        """S13.4 -- SemanticKernelWrapper has health_check method."""
        self.assertTrue(hasattr(SemanticKernelWrapper, "health_check"))

    def test_custom_policy(self):
        """S13.5 -- SemanticKernelWrapper accepts custom policy."""
        p = GovernancePolicy(max_tokens=1024)
        k = SemanticKernelWrapper(policy=p)
        self.assertEqual(k.policy.max_tokens, 1024)


# ═══════════════════════════════════════════════════════════════════════════
# Section 14: OpenAIAgentsSDKAdapter
# ═══════════════════════════════════════════════════════════════════════════


@unittest.skipUnless(_HAS_OAI_AGENTS_ADAPTER, "OpenAI Agents SDK adapter not importable")
class TestOpenAIAgentsSDKAdapter(unittest.TestCase):
    """Spec S14 -- OpenAIAgentsSDKAdapter constructor defaults, as_hooks."""

    def test_default_policy(self):
        """S14.1 -- OpenAIAgentsKernel default policy is GovernancePolicy()."""
        k = OpenAIAgentsKernel()
        self.assertIsInstance(k.policy, GovernancePolicy)

    def test_is_base_integration(self):
        """S14.2 -- OpenAIAgentsKernel inherits BaseIntegration."""
        self.assertTrue(issubclass(OpenAIAgentsKernel, BaseIntegration))

    def test_has_as_hooks(self):
        """S14.3 -- OpenAIAgentsKernel has as_hooks method."""
        self.assertTrue(hasattr(OpenAIAgentsKernel, "as_hooks"))

    def test_has_health_check(self):
        """S14.4 -- OpenAIAgentsKernel has health_check method."""
        self.assertTrue(hasattr(OpenAIAgentsKernel, "health_check"))

    def test_max_tool_calls_default_50(self):
        """S14.5 -- OpenAIAgentsKernel default max_tool_calls is 50."""
        k = OpenAIAgentsKernel()
        self.assertEqual(k.policy.max_tool_calls, 50)


# ═══════════════════════════════════════════════════════════════════════════
# Section 15: PydanticAIAdapter
# ═══════════════════════════════════════════════════════════════════════════


@unittest.skipUnless(_HAS_PYDANTIC_AI_ADAPTER, "PydanticAI adapter not importable")
class TestPydanticAIAdapter(unittest.TestCase):
    """Spec S15 -- PydanticAIAdapter constructor defaults, as_capability."""

    def test_default_policy(self):
        """S15.1 -- PydanticAIKernel default policy is GovernancePolicy()."""
        k = PydanticAIKernel()
        self.assertIsInstance(k.policy, GovernancePolicy)

    def test_is_base_integration(self):
        """S15.2 -- PydanticAIKernel inherits BaseIntegration."""
        self.assertTrue(issubclass(PydanticAIKernel, BaseIntegration))

    def test_has_as_capability(self):
        """S15.3 -- PydanticAIKernel has as_capability method."""
        self.assertTrue(hasattr(PydanticAIKernel, "as_capability"))

    def test_has_health_check(self):
        """S15.4 -- PydanticAIKernel has health_check method."""
        self.assertTrue(hasattr(PydanticAIKernel, "health_check"))


# ═══════════════════════════════════════════════════════════════════════════
# Section 16: SmolagentsAdapter
# ═══════════════════════════════════════════════════════════════════════════


@unittest.skipUnless(_HAS_SMOLAGENTS_ADAPTER, "Smolagents adapter not importable")
class TestSmolagentsAdapter(unittest.TestCase):
    """Spec S16 -- SmolagentsAdapter constructor defaults, as_step_callback."""

    def test_default_policy(self):
        """S16.1 -- SmolagentsKernel default policy is GovernancePolicy()."""
        k = SmolagentsKernel()
        self.assertIsInstance(k.policy, GovernancePolicy)

    def test_is_base_integration(self):
        """S16.2 -- SmolagentsKernel inherits BaseIntegration."""
        self.assertTrue(issubclass(SmolagentsKernel, BaseIntegration))

    def test_has_as_step_callback(self):
        """S16.3 -- SmolagentsKernel has as_step_callback method."""
        self.assertTrue(hasattr(SmolagentsKernel, "as_step_callback"))

    def test_has_health_check(self):
        """S16.4 -- SmolagentsKernel has health_check method."""
        self.assertTrue(hasattr(SmolagentsKernel, "health_check"))

    def test_max_tool_calls_default_50(self):
        """S16.5 -- SmolagentsKernel default max_tool_calls is 50."""
        k = SmolagentsKernel()
        self.assertEqual(k.policy.max_tool_calls, 50)


# ═══════════════════════════════════════════════════════════════════════════
# Section 17: Health Check Contract
# ═══════════════════════════════════════════════════════════════════════════


class TestHealthCheckContract(unittest.TestCase):
    """Spec S17 -- health_check exists on all adapters."""

    def _assert_has_health_check(self, cls):
        self.assertTrue(
            hasattr(cls, "health_check"),
            f"{cls.__name__} must have health_check method",
        )

    @unittest.skipUnless(_HAS_LANGCHAIN_ADAPTER, "skip")
    def test_langchain_health_check(self):
        """S17.1 -- LangChainKernel has health_check."""
        self._assert_has_health_check(LangChainKernel)

    @unittest.skipUnless(_HAS_CREWAI_ADAPTER, "skip")
    def test_crewai_has_as_hooks(self):
        """S17.2 -- CrewAIKernel has as_hooks method."""
        self.assertTrue(hasattr(CrewAIKernel, "as_hooks"))

    @unittest.skipUnless(_HAS_AUTOGEN_ADAPTER, "skip")
    def test_autogen_health_check(self):
        """S17.3 -- AutoGenKernel has health_check."""
        self._assert_has_health_check(AutoGenKernel)

    @unittest.skipUnless(_HAS_OPENAI_ADAPTER, "skip")
    def test_openai_health_check(self):
        """S17.4 -- OpenAIKernel has health_check."""
        self._assert_has_health_check(OpenAIKernel)

    @unittest.skipUnless(_HAS_ANTHROPIC_ADAPTER, "skip")
    def test_anthropic_health_check(self):
        """S17.5 -- AnthropicKernel has health_check."""
        self._assert_has_health_check(AnthropicKernel)

    @unittest.skipUnless(_HAS_ADK_ADAPTER, "skip")
    def test_google_adk_health_check(self):
        """S17.6 -- GoogleADKKernel has health_check."""
        self._assert_has_health_check(GoogleADKKernel)

    @unittest.skipUnless(_HAS_SK_ADAPTER, "skip")
    def test_semantic_kernel_health_check(self):
        """S17.7 -- SemanticKernelWrapper has health_check."""
        self._assert_has_health_check(SemanticKernelWrapper)

    @unittest.skipUnless(_HAS_OAI_AGENTS_ADAPTER, "skip")
    def test_openai_agents_health_check(self):
        """S17.8 -- OpenAIAgentsKernel has health_check."""
        self._assert_has_health_check(OpenAIAgentsKernel)

    @unittest.skipUnless(_HAS_PYDANTIC_AI_ADAPTER, "skip")
    def test_pydantic_ai_health_check(self):
        """S17.9 -- PydanticAIKernel has health_check."""
        self._assert_has_health_check(PydanticAIKernel)

    @unittest.skipUnless(_HAS_SMOLAGENTS_ADAPTER, "skip")
    def test_smolagents_health_check(self):
        """S17.10 -- SmolagentsKernel has health_check."""
        self._assert_has_health_check(SmolagentsKernel)

    @unittest.skipUnless(_HAS_LANGCHAIN_ADAPTER, "skip")
    def test_langchain_health_check_returns_dict(self):
        """S17.11 -- LangChainKernel.health_check() returns a dict."""
        k = LangChainKernel()
        hc = k.health_check()
        self.assertIsInstance(hc, dict)
        self.assertIn("status", hc)


# ═══════════════════════════════════════════════════════════════════════════
# Section 20: Failure Semantics
# ═══════════════════════════════════════════════════════════════════════════


class TestFailureSemantics(unittest.TestCase):
    """Spec S20 -- Fail-closed behavior."""

    def test_evaluate_policy_fail_closed(self):
        """S20.1 -- _evaluate_policy denies on evaluator exception (fail-closed)."""
        class _Concrete(BaseIntegration):
            def wrap(self, agent):
                return agent

            def unwrap(self, governed_agent):
                return governed_agent

        bad_evaluator = MagicMock()
        bad_evaluator.evaluate.side_effect = RuntimeError("boom")
        kernel = _Concrete(evaluator=bad_evaluator)
        allowed, reason = kernel._evaluate_policy({"agent_id": "a"})
        self.assertFalse(allowed)
        self.assertIn("fail-closed", reason)

    def test_policy_violation_error_importable(self):
        """S20.2 -- PolicyViolationError is importable from base."""
        self.assertTrue(issubclass(PolicyViolationError, Exception))

    def test_bounded_semaphore_reject_at_max(self):
        """S20.3 -- BoundedSemaphore rejects when max_concurrent reached."""
        sem = BoundedSemaphore(max_concurrent=2)
        sem.try_acquire()
        sem.try_acquire()
        ok, reason = sem.try_acquire()
        self.assertFalse(ok)
        self.assertIn("Max concurrency", reason)

    def test_bounded_semaphore_backpressure(self):
        """S20.4 -- BoundedSemaphore detects backpressure threshold."""
        sem = BoundedSemaphore(max_concurrent=5, backpressure_threshold=3)
        for _ in range(3):
            sem.try_acquire()
        self.assertTrue(sem.is_under_pressure)

    def test_bounded_semaphore_release(self):
        """S20.5 -- BoundedSemaphore.release() frees a slot."""
        sem = BoundedSemaphore(max_concurrent=1)
        sem.try_acquire()
        sem.release()
        ok, _ = sem.try_acquire()
        self.assertTrue(ok)

    def test_bounded_semaphore_stats(self):
        """S20.6 -- BoundedSemaphore.stats() returns expected keys."""
        sem = BoundedSemaphore()
        stats = sem.stats()
        for key in ("active", "max_concurrent", "available", "under_pressure",
                     "total_acquired", "total_rejected"):
            self.assertIn(key, stats)

    def test_bounded_semaphore_available(self):
        """S20.7 -- BoundedSemaphore.available returns correct value."""
        sem = BoundedSemaphore(max_concurrent=5)
        sem.try_acquire()
        self.assertEqual(sem.available, 4)

    def test_bounded_semaphore_release_at_zero(self):
        """S20.8 -- BoundedSemaphore.release() at 0 does not go negative."""
        sem = BoundedSemaphore()
        sem.release()
        self.assertEqual(sem.active, 0)


if __name__ == "__main__":
    unittest.main()
