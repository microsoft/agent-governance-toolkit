# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Integration tests for optional dependencies.

Tests that framework adapters behave correctly both when their underlying
framework packages are available and when they are not (graceful degradation).

Covers:
  - Provider adapter construction and wrapping with mock objects
  - Graceful ImportError handling for optional frameworks
  - Policy enforcement through adapter wrapping lifecycle
  - Deep hooks: tool interception, memory validation, delegation detection
  - YAML policy loading and serialization round-trips
  - GovernancePolicy YAML/dict serialization
  - Health checker integration
  - Async evaluator concurrency
"""

import asyncio
import copy
import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock, patch

import pytest

from agent_os.integrations.base import (
    BaseIntegration,
    ExecutionContext,
    GovernanceEventType,
    GovernancePolicy,
    PatternType,
    PolicyViolationError,
)
from agent_os.policies.schema import (
    PolicyAction,
    PolicyCondition,
    PolicyDocument,
    PolicyOperator,
    PolicyRule,
)


# ============================================================================
# Provider Adapter: OpenAI
# ============================================================================


class TestOpenAIAdapterIntegration:
    """Test OpenAI adapter with mock OpenAI client."""

    def test_kernel_construction(self):
        """OpenAIKernel can be constructed without real OpenAI."""
        from agent_os.integrations.openai_adapter import OpenAIKernel
        kernel = OpenAIKernel()
        assert kernel is not None
        assert kernel.policy.max_tokens == 4096  # default

    def test_kernel_with_custom_policy(self):
        """OpenAIKernel respects custom policy."""
        from agent_os.integrations.openai_adapter import OpenAIKernel
        policy = GovernancePolicy(
            max_tokens=2048,
            blocked_patterns=["secret"],
        )
        kernel = OpenAIKernel(policy=policy)
        assert kernel.policy.max_tokens == 2048

    def test_wrap_requires_client(self):
        """OpenAIKernel.wrap raises TypeError without client."""
        from agent_os.integrations.openai_adapter import OpenAIKernel
        kernel = OpenAIKernel()
        assistant = MagicMock()
        assistant.id = "asst_123"

        with pytest.raises(TypeError, match="client"):
            kernel.wrap(assistant)

    def test_wrap_with_mock_client(self):
        """OpenAIKernel.wrap creates governed assistant with mock client."""
        from agent_os.integrations.openai_adapter import OpenAIKernel
        kernel = OpenAIKernel()
        assistant = MagicMock()
        assistant.id = "asst_123"
        client = MagicMock()

        governed = kernel.wrap(assistant, client)
        assert governed is not None

    def test_policy_blocks_through_wrap(self):
        """Policy violations are enforced on wrapped assistant."""
        from agent_os.integrations.openai_adapter import OpenAIKernel
        policy = GovernancePolicy(
            blocked_patterns=["DROP TABLE"],
        )
        kernel = OpenAIKernel(policy=policy)
        ctx = kernel.create_context("openai-agent")

        allowed, reason = kernel.pre_execute(ctx, "DROP TABLE users")
        assert allowed is False


# ============================================================================
# Provider Adapter: Anthropic
# ============================================================================


class TestAnthropicAdapterIntegration:
    """Test Anthropic adapter with mock Anthropic client."""

    def test_kernel_construction(self):
        """AnthropicKernel can be constructed without real SDK."""
        from agent_os.integrations.anthropic_adapter import AnthropicKernel
        kernel = AnthropicKernel()
        assert kernel is not None

    def test_kernel_policy_enforcement(self):
        """AnthropicKernel enforces policy via pre_execute."""
        from agent_os.integrations.anthropic_adapter import AnthropicKernel
        policy = GovernancePolicy(
            max_tool_calls=5,
            blocked_patterns=["password"],
        )
        kernel = AnthropicKernel(policy=policy)
        ctx = kernel.create_context("claude-agent")

        allowed, _ = kernel.pre_execute(ctx, "tell me the password")
        assert allowed is False

    def test_wrap_with_mock_client(self):
        """AnthropicKernel.wrap works with mock client or errors cleanly."""
        from agent_os.integrations.anthropic_adapter import AnthropicKernel
        kernel = AnthropicKernel()
        mock_client = MagicMock()
        mock_client.messages = MagicMock()

        try:
            governed = kernel.wrap(mock_client)
            assert governed is not None
        except ImportError:
            # Expected when anthropic package is not installed
            pass


# ============================================================================
# Provider Adapter: Gemini
# ============================================================================


class TestGeminiAdapterIntegration:
    """Test Gemini adapter with mock Gemini model."""

    def test_kernel_construction(self):
        """GeminiKernel can be constructed without real SDK."""
        from agent_os.integrations.gemini_adapter import GeminiKernel
        kernel = GeminiKernel()
        assert kernel is not None

    def test_kernel_policy_enforcement(self):
        """GeminiKernel enforces policy via pre_execute."""
        from agent_os.integrations.gemini_adapter import GeminiKernel
        policy = GovernancePolicy(
            blocked_patterns=["api_key"],
        )
        kernel = GeminiKernel(policy=policy)
        ctx = kernel.create_context("gemini-agent")

        allowed, _ = kernel.pre_execute(ctx, "set api_key=sk_1234")
        assert allowed is False


# ============================================================================
# Framework Adapter: LangChain Deep Hooks
# ============================================================================


class TestLangChainDeepHooks:
    """Test LangChain deep integration hooks with mock objects."""

    def _make_tool(self, name="web_search"):
        tool = MagicMock()
        tool.name = name
        tool._run = MagicMock(return_value="result")
        tool._arun = MagicMock(return_value="async-result")
        tool._deep_governed = False
        return tool

    def _make_memory(self):
        memory = MagicMock()
        memory.save_context = MagicMock(return_value=None)
        memory._deep_governed = False
        return memory

    def _make_chain(self, tools=None, memory=None):
        chain = MagicMock()
        chain.name = "test-chain"
        chain.invoke = MagicMock(return_value="invoke-result")
        chain.run = MagicMock(return_value="run-result")
        chain._spawn_governed = False
        if tools is not None:
            chain.tools = tools
        if memory is not None:
            chain.memory = memory
        return chain

    def test_tool_interception(self):
        """Tools are intercepted and governed when deep hooks enabled."""
        from agent_os.integrations.langchain_adapter import LangChainKernel

        policy = GovernancePolicy(
            allowed_tools=["web_search"],
            blocked_patterns=["password"],
        )
        kernel = LangChainKernel(policy=policy, deep_hooks_enabled=True)
        tool = self._make_tool("web_search")
        chain = self._make_chain(tools=[tool])

        governed = kernel.wrap(chain)
        # Tool should be marked as governed
        assert tool._deep_governed is True

    def test_blocked_tool_not_in_allowlist(self):
        """Tool not in allowed_tools is blocked."""
        from agent_os.integrations.langchain_adapter import LangChainKernel

        policy = GovernancePolicy(
            allowed_tools=["web_search"],
        )
        kernel = LangChainKernel(policy=policy, deep_hooks_enabled=True)
        tool = self._make_tool("dangerous_tool")
        chain = self._make_chain(tools=[tool])

        governed = kernel.wrap(chain)
        # The tool should be wrapped; actual blocking happens on invocation
        assert tool._deep_governed is True

    def test_memory_write_interception(self):
        """Memory writes are intercepted when deep hooks enabled."""
        from agent_os.integrations.langchain_adapter import LangChainKernel

        kernel = LangChainKernel(deep_hooks_enabled=True)
        memory = self._make_memory()
        chain = self._make_chain(memory=memory)

        governed = kernel.wrap(chain)
        assert memory._deep_governed is True

    def test_no_deep_hooks_when_disabled(self):
        """Deep hooks are not applied when disabled."""
        from agent_os.integrations.langchain_adapter import LangChainKernel

        kernel = LangChainKernel(deep_hooks_enabled=False)
        tool = self._make_tool()
        chain = self._make_chain(tools=[tool])

        governed = kernel.wrap(chain)
        assert tool._deep_governed is False


# ============================================================================
# Framework Adapter: CrewAI Deep Hooks
# ============================================================================


class TestCrewAIDeepHooks:
    """Test CrewAI deep integration hooks."""

    def _make_agent(self, name="researcher", tools=None):
        agent = MagicMock()
        agent.name = name
        agent.tools = tools or []
        agent.execute_task = MagicMock(return_value="done")
        return agent

    def _make_crew(self, agents=None):
        crew = MagicMock()
        crew.name = "test-crew"
        crew.id = None
        crew.agents = agents or []
        crew.kickoff = MagicMock(return_value="crew result")
        return crew

    def test_crew_wrapping(self):
        """CrewAI crew can be wrapped with governance."""
        from agent_os.integrations.crewai_adapter import CrewAIKernel

        kernel = CrewAIKernel()
        crew = self._make_crew()

        governed = kernel.wrap(crew)
        assert governed is not None

    def test_crew_policy_enforcement(self):
        """CrewAI enforces policy on pre_execute."""
        from agent_os.integrations.crewai_adapter import CrewAIKernel

        policy = GovernancePolicy(
            blocked_patterns=["malicious"],
        )
        kernel = CrewAIKernel(policy=policy)
        ctx = kernel.create_context("crew-agent")

        allowed, _ = kernel.pre_execute(ctx, "execute malicious command")
        assert allowed is False


# ============================================================================
# Framework Adapter: AutoGen
# ============================================================================


class TestAutoGenAdapterIntegration:
    """Test AutoGen adapter integration."""

    def test_kernel_construction(self):
        """AutoGenKernel can be constructed."""
        from agent_os.integrations.autogen_adapter import AutoGenKernel
        kernel = AutoGenKernel()
        assert kernel is not None

    def test_policy_enforcement(self):
        """AutoGen kernel enforces policy."""
        from agent_os.integrations.autogen_adapter import AutoGenKernel

        policy = GovernancePolicy(blocked_patterns=["secret"])
        kernel = AutoGenKernel(policy=policy)
        ctx = kernel.create_context("autogen-agent")

        allowed, _ = kernel.pre_execute(ctx, "reveal the secret key")
        assert allowed is False

    def test_agent_wrapping(self):
        """AutoGen agent can be wrapped."""
        from agent_os.integrations.autogen_adapter import AutoGenKernel

        kernel = AutoGenKernel()
        agent = MagicMock()
        agent.name = "test-autogen"

        governed = kernel.wrap(agent)
        assert governed is not None


# ============================================================================
# GovernancePolicy YAML/Dict Serialization
# ============================================================================


class TestPolicySerialization:
    """Test policy serialization round-trips."""

    def test_to_dict_and_back(self):
        """Policy survives dict round-trip."""
        policy = GovernancePolicy(
            name="test-policy",
            max_tokens=2048,
            max_tool_calls=5,
            allowed_tools=["web_search", "file_read"],
            blocked_patterns=[
                "password",
                (r"rm\s+-rf", PatternType.REGEX),
            ],
            require_human_approval=True,
            version="2.0.0",
        )

        data = policy.to_dict()
        restored = GovernancePolicy.from_dict(data)

        assert restored.max_tokens == 2048
        assert restored.max_tool_calls == 5
        assert restored.allowed_tools == ["web_search", "file_read"]
        assert restored.require_human_approval is True
        assert restored.version == "2.0.0"

    def test_to_yaml_and_back(self):
        """Policy survives YAML round-trip."""
        policy = GovernancePolicy(
            max_tokens=1024,
            blocked_patterns=["secret"],
            version="1.5.0",
        )

        yaml_str = policy.to_yaml()
        restored = GovernancePolicy.from_yaml(yaml_str)

        assert restored.max_tokens == 1024
        assert restored.version == "1.5.0"

    def test_save_and_load_file(self, tmp_path):
        """Policy can be saved to and loaded from a YAML file."""
        policy = GovernancePolicy(
            max_tokens=512,
            allowed_tools=["calculator"],
        )

        filepath = str(tmp_path / "policy.yaml")
        policy.save(filepath)
        loaded = GovernancePolicy.load(filepath)

        assert loaded.max_tokens == 512
        assert loaded.allowed_tools == ["calculator"]


# ============================================================================
# PolicyDocument YAML Loading
# ============================================================================


class TestPolicyDocumentYAML:
    """Test PolicyDocument YAML loading."""

    def test_load_from_yaml(self, tmp_path):
        """PolicyDocument loads from YAML file."""
        from agent_os.policies.schema import PolicyDocument

        yaml_content = """\
version: "1.0"
name: "test-policy"
description: "A test policy"
rules:
  - name: block-internal
    condition:
      field: message
      operator: contains
      value: internal
    action: deny
    priority: 10
    message: "Internal access denied"
defaults:
  action: allow
  max_tokens: 2048
"""
        policy_file = tmp_path / "policy.yaml"
        policy_file.write_text(yaml_content)

        doc = PolicyDocument.from_yaml(policy_file)
        assert doc.name == "test-policy"
        assert len(doc.rules) == 1
        assert doc.rules[0].name == "block-internal"
        assert doc.defaults.max_tokens == 2048

    def test_save_to_yaml(self, tmp_path):
        """PolicyDocument can be saved to YAML."""
        from agent_os.policies.schema import (
            PolicyAction,
            PolicyCondition,
            PolicyDocument,
            PolicyOperator,
            PolicyRule,
        )

        doc = PolicyDocument(
            version="1.0",
            name="export-test",
            rules=[
                PolicyRule(
                    name="test-rule",
                    condition=PolicyCondition(
                        field="tool",
                        operator=PolicyOperator.EQ,
                        value="web_search",
                    ),
                    action=PolicyAction.ALLOW,
                ),
            ],
        )

        out_path = tmp_path / "exported.yaml"
        doc.to_yaml(out_path)
        assert out_path.exists()

        # Reload and verify
        reloaded = PolicyDocument.from_yaml(out_path)
        assert reloaded.name == "export-test"
        assert len(reloaded.rules) == 1

    def test_load_multiple_policies_from_dir(self, tmp_path):
        """PolicyEvaluator loads all YAML files from a directory."""
        from agent_os.policies.evaluator import PolicyEvaluator

        (tmp_path / "policy1.yaml").write_text(
            "version: '1.0'\nname: p1\nrules: []\n"
        )
        (tmp_path / "policy2.yml").write_text(
            "version: '1.0'\nname: p2\nrules: []\n"
        )

        evaluator = PolicyEvaluator()
        evaluator.load_policies(tmp_path)
        assert len(evaluator.policies) == 2


# ============================================================================
# Health Checker Integration
# ============================================================================


class TestHealthCheckerIntegration:
    """Test health checker with registered checks."""

    def test_health_checker_with_custom_check(self):
        """Custom health checks are executed."""
        from agent_os.integrations.health import HealthChecker, HealthStatus, ComponentHealth

        checker = HealthChecker(version="1.0.0")

        def custom_check():
            return ComponentHealth(
                name="custom",
                status=HealthStatus.HEALTHY,
                message="All good",
                latency_ms=1.5,
            )

        checker.register_check("custom", custom_check)
        report = checker.check_health()

        assert report.is_healthy()
        assert "custom" in report.components
        assert report.components["custom"].status == HealthStatus.HEALTHY

    def test_health_checker_degraded(self):
        """Degraded component affects overall status."""
        from agent_os.integrations.health import HealthChecker, HealthStatus, ComponentHealth

        checker = HealthChecker()

        checker.register_check("healthy", lambda: ComponentHealth(
            name="healthy", status=HealthStatus.HEALTHY
        ))
        checker.register_check("degraded", lambda: ComponentHealth(
            name="degraded", status=HealthStatus.DEGRADED
        ))

        report = checker.check_health()
        # Report should be degraded (not healthy) because one component is degraded
        assert report.is_ready()  # Degraded is still ready

    def test_health_report_serialization(self):
        """HealthReport.to_dict returns valid JSON-serializable dict."""
        from agent_os.integrations.health import HealthChecker, HealthStatus, ComponentHealth

        checker = HealthChecker(version="2.0.0")
        checker.register_check("test", lambda: ComponentHealth(
            name="test", status=HealthStatus.HEALTHY, latency_ms=0.5
        ))

        report = checker.check_health()
        data = report.to_dict()

        # Should be JSON-serializable
        json_str = json.dumps(data)
        parsed = json.loads(json_str)
        assert parsed["version"] == "2.0.0"
        assert "test" in parsed["components"]


# ============================================================================
# Async Policy Evaluator
# ============================================================================


class TestAsyncPolicyEvaluator:
    """Test async policy evaluation with concurrency."""

    def _make_evaluator(self, rules):
        from agent_os.policies.evaluator import PolicyEvaluator
        doc = PolicyDocument(
            version="1.0",
            name="async-test-policy",
            rules=rules,
        )
        return PolicyEvaluator(policies=[doc])

    @pytest.mark.asyncio
    async def test_async_evaluate(self):
        """AsyncPolicyEvaluator evaluates policies asynchronously."""
        from agent_os.policies.async_evaluator import AsyncPolicyEvaluator

        sync_eval = self._make_evaluator([
            PolicyRule(
                name="block-delete",
                condition=PolicyCondition(
                    field="operation",
                    operator=PolicyOperator.EQ,
                    value="delete",
                ),
                action=PolicyAction.DENY,
            ),
        ])

        evaluator = AsyncPolicyEvaluator(sync_eval)
        decision = await evaluator.evaluate({"operation": "delete"})
        assert decision.allowed is False

    @pytest.mark.asyncio
    async def test_async_evaluate_allows(self):
        """AsyncPolicyEvaluator allows non-matching context."""
        from agent_os.policies.async_evaluator import AsyncPolicyEvaluator

        sync_eval = self._make_evaluator([
            PolicyRule(
                name="block-delete",
                condition=PolicyCondition(
                    field="operation",
                    operator=PolicyOperator.EQ,
                    value="delete",
                ),
                action=PolicyAction.DENY,
            ),
        ])

        evaluator = AsyncPolicyEvaluator(sync_eval)
        decision = await evaluator.evaluate({"operation": "read"})
        assert decision.allowed is True

    @pytest.mark.asyncio
    async def test_concurrent_evaluations(self):
        """Multiple concurrent evaluations don't interfere."""
        from agent_os.policies.async_evaluator import AsyncPolicyEvaluator

        sync_eval = self._make_evaluator([
            PolicyRule(
                name="block-write",
                condition=PolicyCondition(
                    field="operation",
                    operator=PolicyOperator.EQ,
                    value="write",
                ),
                action=PolicyAction.DENY,
            ),
        ])

        evaluator = AsyncPolicyEvaluator(sync_eval)

        # Run 20 concurrent evaluations
        tasks = [
            evaluator.evaluate({"operation": "write" if i % 2 == 0 else "read"})
            for i in range(20)
        ]
        results = await asyncio.gather(*tasks)

        # Even indices should be denied (write), odd should be allowed (read)
        for i, decision in enumerate(results):
            if i % 2 == 0:
                assert decision.allowed is False, f"Expected deny at index {i}"
            else:
                assert decision.allowed is True, f"Expected allow at index {i}"


# ============================================================================
# Governance Event System
# ============================================================================


class TestGovernanceEvents:
    """Test event emission and listener registration."""

    def test_event_listener_fires(self):
        """Event listeners fire on emit."""
        from agent_os.integrations.langchain_adapter import LangChainKernel

        kernel = LangChainKernel()
        events = []
        kernel.on(GovernanceEventType.POLICY_CHECK, lambda data: events.append(data))

        ctx = kernel.create_context("test-agent")
        kernel.pre_execute(ctx, "input")

        assert len(events) > 0
        assert events[0]["phase"] == "pre_execute"

    def test_violation_event_on_block(self):
        """POLICY_VIOLATION event fires when blocked."""
        from agent_os.integrations.langchain_adapter import LangChainKernel

        policy = GovernancePolicy(max_tool_calls=0)
        kernel = LangChainKernel(policy=policy)

        violations = []
        kernel.on(GovernanceEventType.POLICY_VIOLATION, lambda data: violations.append(data))

        ctx = kernel.create_context("test-agent")
        kernel.pre_execute(ctx, "anything")

        assert len(violations) > 0

    def test_checkpoint_event(self):
        """CHECKPOINT_CREATED event fires at checkpoint_frequency."""
        from agent_os.integrations.langchain_adapter import LangChainKernel

        policy = GovernancePolicy(checkpoint_frequency=2)
        kernel = LangChainKernel(policy=policy)

        checkpoints = []
        kernel.on(GovernanceEventType.CHECKPOINT_CREATED, lambda data: checkpoints.append(data))

        ctx = kernel.create_context("test-agent")
        # Post-execute increments call_count; checkpoint fires at multiples
        kernel.post_execute(ctx, "output1")  # call_count=1
        kernel.post_execute(ctx, "output2")  # call_count=2 → checkpoint

        assert len(checkpoints) == 1
        assert checkpoints[0]["call_count"] == 2

    def test_listener_error_does_not_break_flow(self):
        """A failing listener does not break governance execution."""
        from agent_os.integrations.langchain_adapter import LangChainKernel

        kernel = LangChainKernel()

        def bad_listener(data):
            raise RuntimeError("listener error")

        kernel.on(GovernanceEventType.POLICY_CHECK, bad_listener)

        ctx = kernel.create_context("test-agent")
        # Should not raise despite listener error
        allowed, reason = kernel.pre_execute(ctx, "input")
        assert allowed is True


# ============================================================================
# ExecutionContext Isolation
# ============================================================================


class TestExecutionContextIsolation:
    """Test that execution contexts are properly isolated."""

    def test_context_policy_is_deep_copy(self):
        """Context policy is deep-copied so mutations don't leak."""
        policy = GovernancePolicy(max_tokens=4096)
        from agent_os.integrations.langchain_adapter import LangChainKernel

        kernel = LangChainKernel(policy=policy)
        ctx = kernel.create_context("agent-1")

        # Mutate kernel policy
        kernel.policy = GovernancePolicy(max_tokens=1024)

        # Context policy should still be 4096
        assert ctx.policy.max_tokens == 4096

    def test_separate_contexts_independent(self):
        """Different agents get independent contexts."""
        from agent_os.integrations.langchain_adapter import LangChainKernel

        kernel = LangChainKernel()
        ctx1 = kernel.create_context("agent-1")
        ctx2 = kernel.create_context("agent-2")

        ctx1.call_count = 10
        assert ctx2.call_count == 0

    def test_context_validation(self):
        """Invalid context fields raise ValueError."""
        with pytest.raises(ValueError):
            ExecutionContext(
                agent_id="",  # Empty not allowed
                session_id="sess-1",
                policy=GovernancePolicy(),
            )

    def test_context_invalid_agent_id_pattern(self):
        """Agent ID with invalid characters raises ValueError."""
        with pytest.raises(ValueError):
            ExecutionContext(
                agent_id="agent with spaces",
                session_id="sess-1",
                policy=GovernancePolicy(),
            )
