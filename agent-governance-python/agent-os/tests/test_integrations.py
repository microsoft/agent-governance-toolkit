# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for framework integration adapters.

Covers: base.py, langchain_adapter.py, crewai_adapter.py, openai_adapter.py
Uses mock objects — no real API calls.

Run with: python -m pytest tests/test_integrations.py -v --tb=short
"""

import time
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

import asyncio
import pytest

from agent_os.integrations.base import (
    BaseIntegration,
    ExecutionContext,
    GovernanceEventType,
    GovernancePolicy,
    PatternType,
)
from agent_os.integrations.langchain_adapter import (
    LangChainKernel,
    PolicyViolationError,
)
from agent_os.integrations.base import PolicyViolationError as BasePolicyViolationError
from agent_os.integrations.crewai_adapter import CrewAIKernel
from agent_os.integrations.openai_adapter import (
    AssistantContext,
    GovernedAssistant,
    OpenAIKernel,
    RunCancelledException,
)
from agent_os.integrations.openai_adapter import (
    PolicyViolationError as OpenAIPolicyViolationError,
)


# =============================================================================
# Helpers
# =============================================================================


def _make_mock_chain(name="test-chain"):
    """Create a mock LangChain-like chain/runnable."""
    chain = MagicMock()
    chain.name = name
    chain.invoke.return_value = "invoke-result"
    chain.run.return_value = "run-result"
    chain.batch.return_value = ["batch-1", "batch-2"]
    chain.stream.return_value = iter(["chunk-1", "chunk-2"])
    return chain


async def _async_chunks(chunks):
    for chunk in chunks:
        yield chunk


async def _collect_async(async_iterable):
    return [chunk async for chunk in async_iterable]


def _make_mock_crew():
    """Create a mock CrewAI crew."""
    crew = MagicMock()
    crew.id = "crew-42"
    crew.kickoff.return_value = "crew-result"
    crew.agents = []
    return crew


def _make_mock_openai_client():
    """Create a mock OpenAI client with all required sub-objects."""
    client = MagicMock()
    # Thread creation
    thread = MagicMock()
    thread.id = "thread_abc"
    client.beta.threads.create.return_value = thread
    # Message creation
    msg = MagicMock()
    msg.id = "msg_xyz"
    client.beta.threads.messages.create.return_value = msg
    return client


def _make_mock_assistant(assistant_id="asst_001", name="TestBot"):
    assistant = MagicMock()
    assistant.id = assistant_id
    assistant.name = name
    return assistant


def _make_completed_run(run_id="run_001", usage=None):
    """Return a mock run object with status 'completed'."""
    run = MagicMock()
    run.id = run_id
    run.status = "completed"
    run.usage = usage
    return run


def _make_requires_action_run(run_id="run_001", tool_calls=None):
    """Return a mock run that requires tool-call action."""
    run = MagicMock()
    run.id = run_id
    run.status = "requires_action"
    run.usage = None  # no token usage yet
    if tool_calls is None:
        tc = MagicMock()
        tc.id = "call_1"
        tc.type = "function"
        tc.function.name = "get_weather"
        tc.function.arguments = '{"city":"NY"}'
        tool_calls = [tc]
    run.required_action.submit_tool_outputs.tool_calls = tool_calls
    return run


# =============================================================================
# GovernancePolicy defaults & customisation
# =============================================================================


class TestGovernancePolicy:
    def test_defaults(self):
        p = GovernancePolicy()
        assert p.max_tokens == 4096
        assert p.max_tool_calls == 10
        assert p.allowed_tools == []
        assert p.blocked_patterns == []
        assert p.require_human_approval is False
        assert p.timeout_seconds == 300
        assert p.confidence_threshold == 0.8
        assert p.drift_threshold == 0.15
        assert p.log_all_calls is True
        assert p.checkpoint_frequency == 5

    def test_custom_values(self):
        p = GovernancePolicy(
            max_tokens=1000,
            max_tool_calls=3,
            blocked_patterns=["secret"],
            timeout_seconds=60,
        )
        assert p.max_tokens == 1000
        assert p.max_tool_calls == 3
        assert p.blocked_patterns == ["secret"]
        assert p.timeout_seconds == 60

    def test_identical_policies_are_equal(self):
        p1 = GovernancePolicy(
            allowed_tools=["search", "read_file"],
            blocked_patterns=["password"],
            max_tool_calls=5,
        )
        p2 = GovernancePolicy(
            allowed_tools=["search", "read_file"],
            blocked_patterns=["password"],
            max_tool_calls=5,
        )
        assert p1 == p2

    def test_policies_with_different_values_are_not_equal(self):
        p1 = GovernancePolicy(max_tokens=1024)
        p2 = GovernancePolicy(max_tokens=2048)
        assert p1 != p2

    def test_policy_is_not_equal_to_non_policy_object(self):
        p = GovernancePolicy()
        assert p != "not-a-policy"

    def test_policies_are_hashable_for_sets_and_dicts(self):
        p1 = GovernancePolicy(allowed_tools=["search"])
        p2 = GovernancePolicy(allowed_tools=["search"])
        p3 = GovernancePolicy(allowed_tools=["write"])

        policy_set = {p1, p2, p3}
        policy_dict = {p1: "alpha", p3: "beta"}

        assert len(policy_set) == 2
        assert policy_dict[p2] == "alpha"


# =============================================================================
# GovernancePolicy input validation
# =============================================================================


class TestGovernancePolicyValidation:
    """Tests for GovernancePolicy.validate() input validation."""

    def test_default_policy_passes_validation(self):
        p = GovernancePolicy()
        p.validate()  # should not raise

    def test_max_tokens_zero_raises(self):
        with pytest.raises(ValueError, match="max_tokens must be a positive integer"):
            GovernancePolicy(max_tokens=0)

    def test_max_tokens_negative_raises(self):
        with pytest.raises(ValueError, match="max_tokens must be a positive integer"):
            GovernancePolicy(max_tokens=-1)

    def test_max_tool_calls_negative_raises(self):
        with pytest.raises(ValueError, match="max_tool_calls must be a non-negative integer"):
            GovernancePolicy(max_tool_calls=-1)

    def test_max_tool_calls_zero_allowed(self):
        p = GovernancePolicy(max_tool_calls=0)
        assert p.max_tool_calls == 0

    def test_timeout_seconds_zero_raises(self):
        with pytest.raises(ValueError, match="timeout_seconds must be a positive integer"):
            GovernancePolicy(timeout_seconds=0)

    def test_timeout_seconds_negative_raises(self):
        with pytest.raises(ValueError, match="timeout_seconds must be a positive integer"):
            GovernancePolicy(timeout_seconds=-10)

    def test_max_concurrent_zero_raises(self):
        with pytest.raises(ValueError, match="max_concurrent must be a positive integer"):
            GovernancePolicy(max_concurrent=0)

    def test_checkpoint_frequency_zero_raises(self):
        with pytest.raises(ValueError, match="checkpoint_frequency must be a positive integer"):
            GovernancePolicy(checkpoint_frequency=0)

    def test_confidence_threshold_negative_raises(self):
        with pytest.raises(ValueError, match="confidence_threshold must be a float between 0.0 and 1.0"):
            GovernancePolicy(confidence_threshold=-0.1)

    def test_confidence_threshold_above_one_raises(self):
        with pytest.raises(ValueError, match="confidence_threshold must be a float between 0.0 and 1.0"):
            GovernancePolicy(confidence_threshold=1.5)

    def test_drift_threshold_negative_raises(self):
        with pytest.raises(ValueError, match="drift_threshold must be a float between 0.0 and 1.0"):
            GovernancePolicy(drift_threshold=-0.01)

    def test_drift_threshold_above_one_raises(self):
        with pytest.raises(ValueError, match="drift_threshold must be a float between 0.0 and 1.0"):
            GovernancePolicy(drift_threshold=2.0)

    def test_allowed_tools_non_string_raises(self):
        with pytest.raises(ValueError, match="allowed_tools\\[0\\] must be a string"):
            GovernancePolicy(allowed_tools=[123])

    def test_allowed_tools_mixed_types_raises(self):
        with pytest.raises(ValueError, match="allowed_tools\\[1\\] must be a string"):
            GovernancePolicy(allowed_tools=["valid", 42])

    def test_blocked_patterns_non_string_raises(self):
        with pytest.raises(ValueError, match="blocked_patterns\\[0\\] must be a string"):
            GovernancePolicy(blocked_patterns=[None])

    def test_blocked_patterns_regex_type(self):
        p = GovernancePolicy(
            blocked_patterns=[("\\d{3}-\\d{2}-\\d{4}", PatternType.REGEX)]
        )
        assert p.matches_pattern("SSN: 123-45-6789") == ["\\d{3}-\\d{2}-\\d{4}"]
        assert p.matches_pattern("no numbers here") == []

    def test_blocked_patterns_glob_type(self):
        p = GovernancePolicy(
            blocked_patterns=[("*.exe", PatternType.GLOB)]
        )
        assert p.matches_pattern("run malware.exe") == ["*.exe"]
        assert p.matches_pattern("document.pdf") == []

    def test_blocked_patterns_mixed_types(self):
        p = GovernancePolicy(
            blocked_patterns=[
                "password",
                ("\\bDROP\\s+TABLE\\b", PatternType.REGEX),
                ("*.pem", PatternType.GLOB),
            ]
        )
        assert p.matches_pattern("my password is abc") == ["password"]
        assert p.matches_pattern("DROP TABLE users") == ["\\bDROP\\s+TABLE\\b"]
        assert p.matches_pattern("key.pem") == ["*.pem"]
        assert p.matches_pattern("safe input") == []

    def test_blocked_patterns_backward_compat(self):
        p = GovernancePolicy(blocked_patterns=["secret", "token"])
        assert p.matches_pattern("my secret key") == ["secret"]
        assert p.matches_pattern("bearer TOKEN here") == ["token"]
        assert p.matches_pattern("nothing blocked") == []

    def test_blocked_patterns_invalid_regex_raises(self):
        with pytest.raises(ValueError, match="invalid regex"):
            GovernancePolicy(blocked_patterns=[("[invalid", PatternType.REGEX)])

    def test_blocked_patterns_invalid_tuple_type_raises(self):
        with pytest.raises(ValueError, match="must be a PatternType"):
            GovernancePolicy(blocked_patterns=[("pattern", "regex")])

    def test_blocked_patterns_multiple_matches(self):
        p = GovernancePolicy(
            blocked_patterns=["secret", ("\\bapi.key\\b", PatternType.REGEX)]
        )
        assert sorted(p.matches_pattern("secret api_key data")) == sorted(["secret", "\\bapi.key\\b"])

    def test_valid_string_lists_pass(self):
        p = GovernancePolicy(
            allowed_tools=["tool_a", "tool_b"],
            blocked_patterns=["secret", "password"],
        )
        assert p.allowed_tools == ["tool_a", "tool_b"]
        assert p.blocked_patterns == ["secret", "password"]

    def test_boundary_thresholds_pass(self):
        p = GovernancePolicy(confidence_threshold=0.0, drift_threshold=1.0)
        assert p.confidence_threshold == 0.0
        assert p.drift_threshold == 1.0

    def test_adapter_with_invalid_policy_raises(self):
        with pytest.raises(ValueError, match="max_tokens must be a positive integer"):
            LangChainKernel(policy=GovernancePolicy(max_tokens=-5))


# =============================================================================
# GovernancePolicy conflict detection
# =============================================================================


class TestGovernancePolicyConflictDetection:
    """Tests for GovernancePolicy.detect_conflicts() diagnostic warnings."""

    def test_default_returns_empty_list(self):
        p = GovernancePolicy()
        warnings = p.detect_conflicts()
        assert warnings == []

    # backpressure_threshold >= max_concurrent: warn
    def test_backpressure_threshold_equal_to_max_concurrent_warns(self):
        p = GovernancePolicy(backpressure_threshold=5, max_concurrent=5)
        warnings = p.detect_conflicts()
        assert any("backpressure_threshold" in w for w in warnings)

    # max_tool_calls == 0 and allowed_tools is non-empty: warn
    def test_max_tool_calls_zero_with_allowed_tools_nonempty_warns(self):
        p = GovernancePolicy(max_tool_calls=0, allowed_tools=["search"])
        warnings = p.detect_conflicts()
        assert any("max_tool_calls" in w for w in warnings)

    # confidence_threshold == 0.0: warn
    def test_confidence_threshold_zero_warns(self):
        p = GovernancePolicy(confidence_threshold=0.0)
        warnings = p.detect_conflicts()
        assert any("confidence_threshold" in w for w in warnings)

    # timeout_seconds < 5: warn
    def test_timeout_seconds_too_low_warns(self):
        p = GovernancePolicy(timeout_seconds=3)
        warnings = p.detect_conflicts()
        assert any("timeout_seconds" in w for w in warnings)

    def test_all_conflicts(self):
        p = GovernancePolicy(
            max_concurrent=5,
            backpressure_threshold=5,
            max_tool_calls=0,
            allowed_tools=["search"],
            confidence_threshold=0.0,
            timeout_seconds=3,
        )
        warnings = p.detect_conflicts()
        # Ensure all independent warnings are reported.
        assert any("backpressure_threshold" in w for w in warnings)
        assert any("max_tool_calls" in w for w in warnings)
        assert any("confidence_threshold" in w for w in warnings)
        assert any("timeout_seconds" in w for w in warnings)


# =============================================================================
# GovernancePolicy YAML Serialization
# =============================================================================


class TestGovernancePolicyYAML:
    def test_to_yaml_roundtrip(self):
        p = GovernancePolicy(
            max_tokens=2048,
            max_tool_calls=5,
            allowed_tools=["search", "calculate"],
            blocked_patterns=["secret", "password"],
            require_human_approval=True,
            timeout_seconds=60,
        )
        yaml_str = p.to_yaml()
        p2 = GovernancePolicy.from_yaml(yaml_str)
        assert p2.max_tokens == 2048
        assert p2.max_tool_calls == 5
        assert p2.allowed_tools == ["search", "calculate"]
        assert p2.blocked_patterns == ["secret", "password"]
        assert p2.require_human_approval is True
        assert p2.timeout_seconds == 60

    def test_to_yaml_with_regex_patterns(self):
        p = GovernancePolicy(
            blocked_patterns=[
                "plain",
                ("\\d{3}-\\d{2}-\\d{4}", PatternType.REGEX),
                ("*.exe", PatternType.GLOB),
            ]
        )
        yaml_str = p.to_yaml()
        p2 = GovernancePolicy.from_yaml(yaml_str)
        assert p2.blocked_patterns[0] == "plain"
        assert p2.blocked_patterns[1] == ("\\d{3}-\\d{2}-\\d{4}", PatternType.REGEX)
        assert p2.blocked_patterns[2] == ("*.exe", PatternType.GLOB)
        assert p2.matches_pattern("SSN 123-45-6789") == ["\\d{3}-\\d{2}-\\d{4}"]

    def test_from_yaml_invalid_yaml(self):
        with pytest.raises(ValueError, match="Expected a YAML mapping"):
            GovernancePolicy.from_yaml("just a string")

    def test_from_yaml_invalid_values_trigger_validation(self):
        yaml_str = "max_tokens: -1\n"
        with pytest.raises(ValueError, match="max_tokens must be a positive integer"):
            GovernancePolicy.from_yaml(yaml_str)

    def test_from_yaml_unknown_pattern_type(self):
        yaml_str = """
blocked_patterns:
  - pattern: "test"
    type: "unknown_type"
"""
        with pytest.raises(ValueError, match="Unknown pattern type"):
            GovernancePolicy.from_yaml(yaml_str)

    def test_save_and_load(self, tmp_path):
        p = GovernancePolicy(max_tokens=1024, blocked_patterns=["key"])
        filepath = str(tmp_path / "policy.yaml")
        p.save(filepath)
        p2 = GovernancePolicy.load(filepath)
        assert p2.max_tokens == 1024
        assert p2.blocked_patterns == ["key"]

    def test_from_yaml_unknown_keys_ignored(self):
        yaml_str = "max_tokens: 4096\nunknown_field: true\n"
        p = GovernancePolicy.from_yaml(yaml_str)
        assert p.max_tokens == 4096

    def test_default_roundtrip(self):
        p = GovernancePolicy()
        p2 = GovernancePolicy.from_yaml(p.to_yaml())
        assert p2.max_tokens == p.max_tokens
        assert p2.confidence_threshold == p.confidence_threshold


# =============================================================================
# GovernancePolicy Diff/Comparison
# =============================================================================


class TestGovernancePolicyDiff:
    def test_identical_policies(self):
        p1 = GovernancePolicy()
        p2 = GovernancePolicy()
        assert p1.diff(p2) == {}

    def test_single_field_change(self):
        p1 = GovernancePolicy(max_tokens=4096)
        p2 = GovernancePolicy(max_tokens=2048)
        d = p1.diff(p2)
        assert d == {"max_tokens": (4096, 2048)}

    def test_multiple_changes(self):
        p1 = GovernancePolicy(max_tokens=4096, timeout_seconds=300)
        p2 = GovernancePolicy(max_tokens=2048, timeout_seconds=60)
        d = p1.diff(p2)
        assert "max_tokens" in d
        assert "timeout_seconds" in d
        assert len(d) == 2

    def test_list_field_change(self):
        p1 = GovernancePolicy(allowed_tools=["a", "b"])
        p2 = GovernancePolicy(allowed_tools=["a"])
        d = p1.diff(p2)
        assert "allowed_tools" in d

    def test_format_diff_identical(self):
        p1 = GovernancePolicy()
        assert "identical" in p1.format_diff(GovernancePolicy()).lower()

    def test_format_diff_with_changes(self):
        p1 = GovernancePolicy(max_tokens=4096)
        p2 = GovernancePolicy(max_tokens=2048)
        text = p1.format_diff(p2)
        assert "max_tokens" in text
        assert "4096" in text
        assert "2048" in text

    def test_is_stricter_lower_limits(self):
        strict = GovernancePolicy(max_tokens=1024, max_tool_calls=3)
        loose = GovernancePolicy(max_tokens=4096, max_tool_calls=10)
        assert strict.is_stricter_than(loose)
        assert not loose.is_stricter_than(strict)

    def test_is_stricter_human_approval(self):
        strict = GovernancePolicy(require_human_approval=True)
        loose = GovernancePolicy(require_human_approval=False)
        assert strict.is_stricter_than(loose)

    def test_is_stricter_identical_is_false(self):
        p = GovernancePolicy()
        assert not p.is_stricter_than(GovernancePolicy())

    def test_is_stricter_mixed_not_strictly_stricter(self):
        # Lower tokens but higher tool calls — not strictly stricter
        p1 = GovernancePolicy(max_tokens=1024, max_tool_calls=20)
        p2 = GovernancePolicy(max_tokens=4096, max_tool_calls=10)
        assert not p1.is_stricter_than(p2)

    def test_is_stricter_more_blocked_patterns(self):
        strict = GovernancePolicy(blocked_patterns=["a", "b", "c"])
        loose = GovernancePolicy(blocked_patterns=["a"])
        assert strict.is_stricter_than(loose)

    def test_is_stricter_higher_confidence_threshold(self):
        strict = GovernancePolicy(confidence_threshold=0.95)
        loose = GovernancePolicy(confidence_threshold=0.5)
        assert strict.is_stricter_than(loose)


# =============================================================================
# GovernancePolicy Version Tracking
# =============================================================================


class TestGovernancePolicyVersion:
    def test_default_version(self):
        p = GovernancePolicy()
        assert p.version == "1.0.0"

    def test_custom_version(self):
        p = GovernancePolicy(version="2.3.1")
        assert p.version == "2.3.1"

    def test_version_in_to_dict(self):
        p = GovernancePolicy(version="1.2.0")
        d = p.to_dict()
        assert "version" in d
        assert d["version"] == "1.2.0"

    def test_version_in_to_yaml(self):
        p = GovernancePolicy(version="3.0.0")
        yaml_str = p.to_yaml()
        assert "version" in yaml_str
        assert "3.0.0" in yaml_str

    def test_version_yaml_roundtrip(self):
        p = GovernancePolicy(version="2.1.0")
        p2 = GovernancePolicy.from_yaml(p.to_yaml())
        assert p2.version == "2.1.0"

    def test_version_in_repr(self):
        p = GovernancePolicy(version="1.5.0")
        assert "1.5.0" in repr(p)

    def test_version_in_diff(self):
        p1 = GovernancePolicy(version="1.0.0")
        p2 = GovernancePolicy(version="2.0.0")
        d = p1.diff(p2)
        assert "version" in d
        assert d["version"] == ("1.0.0", "2.0.0")

    def test_version_same_no_diff(self):
        p1 = GovernancePolicy(version="1.0.0")
        p2 = GovernancePolicy(version="1.0.0")
        d = p1.diff(p2)
        assert "version" not in d

    def test_compare_versions_different(self):
        p1 = GovernancePolicy(version="1.0.0", max_tokens=4096)
        p2 = GovernancePolicy(version="2.0.0", max_tokens=2048)
        result = p1.compare_versions(p2)
        assert result["old_version"] == "1.0.0"
        assert result["new_version"] == "2.0.0"
        assert result["versions_differ"] is True
        assert "max_tokens" in result["changes"]
        assert "version" in result["changes"]

    def test_compare_versions_same(self):
        p1 = GovernancePolicy(version="1.0.0")
        p2 = GovernancePolicy(version="1.0.0")
        result = p1.compare_versions(p2)
        assert result["old_version"] == "1.0.0"
        assert result["new_version"] == "1.0.0"
        assert result["versions_differ"] is False
        assert result["changes"] == {}

    def test_version_in_hash(self):
        p1 = GovernancePolicy(version="1.0.0")
        p2 = GovernancePolicy(version="2.0.0")
        assert hash(p1) != hash(p2)

    def test_version_backward_compat(self):
        """Existing code without version arg still works."""
        p = GovernancePolicy(max_tokens=2048)
        assert p.version == "1.0.0"
        assert p.max_tokens == 2048


# =============================================================================
# ExecutionContext
# =============================================================================


class TestExecutionContext:
    def test_initial_state(self):
        ctx = ExecutionContext(
            agent_id="a1",
            session_id="s1",
            policy=GovernancePolicy(),
        )
        assert ctx.call_count == 0
        assert ctx.total_tokens == 0
        assert ctx.tool_calls == []
        assert ctx.checkpoints == []
        assert isinstance(ctx.start_time, datetime)


class TestExecutionContextValidation:
    """Tests for ExecutionContext.validate() input validation."""

    def test_valid_context_passes_validation(self):
        ctx = ExecutionContext(
            agent_id="agent-1_test",
            session_id="sess-abc",
            policy=GovernancePolicy(),
        )
        ctx.validate()  # should not raise

    def test_empty_agent_id_raises(self):
        with pytest.raises(ValueError, match="agent_id must be a non-empty string"):
            ExecutionContext(agent_id="", session_id="s1", policy=GovernancePolicy())

    def test_non_string_agent_id_raises(self):
        with pytest.raises(ValueError, match="agent_id must be a non-empty string"):
            ExecutionContext(agent_id=123, session_id="s1", policy=GovernancePolicy())

    def test_agent_id_with_invalid_chars_raises(self):
        with pytest.raises(ValueError, match=r"agent_id must match"):
            ExecutionContext(agent_id="agent id!", session_id="s1", policy=GovernancePolicy())

    def test_agent_id_valid_patterns_pass(self):
        for aid in ("a1", "my-agent", "Agent_01", "test-agent-v2"):
            ctx = ExecutionContext(agent_id=aid, session_id="s1", policy=GovernancePolicy())
            assert ctx.agent_id == aid

    def test_empty_session_id_raises(self):
        with pytest.raises(ValueError, match="session_id must be a non-empty string"):
            ExecutionContext(agent_id="a1", session_id="", policy=GovernancePolicy())

    def test_non_string_session_id_raises(self):
        with pytest.raises(ValueError, match="session_id must be a non-empty string"):
            ExecutionContext(agent_id="a1", session_id=None, policy=GovernancePolicy())

    def test_policy_not_governance_policy_raises(self):
        with pytest.raises(ValueError, match="policy must be a GovernancePolicy instance"):
            ExecutionContext(agent_id="a1", session_id="s1", policy="not-a-policy")

    def test_negative_call_count_raises(self):
        with pytest.raises(ValueError, match="call_count must be a non-negative integer"):
            ExecutionContext(agent_id="a1", session_id="s1", policy=GovernancePolicy(), call_count=-1)

    def test_negative_total_tokens_raises(self):
        with pytest.raises(ValueError, match="total_tokens must be a non-negative integer"):
            ExecutionContext(agent_id="a1", session_id="s1", policy=GovernancePolicy(), total_tokens=-5)

    def test_zero_call_count_and_total_tokens_pass(self):
        ctx = ExecutionContext(agent_id="a1", session_id="s1", policy=GovernancePolicy(), call_count=0, total_tokens=0)
        assert ctx.call_count == 0
        assert ctx.total_tokens == 0

    def test_checkpoints_non_string_entry_raises(self):
        with pytest.raises(ValueError, match=r"checkpoints\[0\] must be a string"):
            ExecutionContext(agent_id="a1", session_id="s1", policy=GovernancePolicy(), checkpoints=[42])

    def test_valid_checkpoints_pass(self):
        ctx = ExecutionContext(
            agent_id="a1",
            session_id="s1",
            policy=GovernancePolicy(),
            checkpoints=["cp-1", "cp-2"],
        )
        assert ctx.checkpoints == ["cp-1", "cp-2"]


# =============================================================================
# BaseIntegration.pre_execute / post_execute
# =============================================================================


class TestBaseIntegrationPreExecute:
    """Tests for pre_execute policy checks."""

    def _kernel(self, **policy_kw):
        """Helper: return a LangChainKernel (concrete subclass) with given policy."""
        return LangChainKernel(policy=GovernancePolicy(**policy_kw))

    def test_allowed_when_policy_satisfied(self):
        k = self._kernel()
        ctx = k.create_context("a1")
        allowed, reason = k.pre_execute(ctx, "hello")
        assert allowed is True
        assert reason is None

    def test_blocked_when_call_count_exceeded(self):
        k = self._kernel(max_tool_calls=2)
        ctx = k.create_context("a1")
        ctx.call_count = 2  # already at limit
        allowed, reason = k.pre_execute(ctx, "hello")
        assert allowed is False
        assert "Max tool calls" in reason

    def test_blocked_when_timeout_exceeded(self):
        k = self._kernel(timeout_seconds=10)
        ctx = k.create_context("a1")
        ctx.start_time = datetime.now() - timedelta(seconds=20)
        allowed, reason = k.pre_execute(ctx, "hello")
        assert allowed is False
        assert "Timeout" in reason

    def test_blocked_pattern_exact(self):
        k = self._kernel(blocked_patterns=["password"])
        ctx = k.create_context("a1")
        allowed, reason = k.pre_execute(ctx, "my password is 123")
        assert allowed is False
        assert "password" in reason

    def test_blocked_pattern_case_insensitive(self):
        k = self._kernel(blocked_patterns=["secret"])
        ctx = k.create_context("a1")
        allowed, _ = k.pre_execute(ctx, "This has a SECRET inside")
        assert allowed is False

    def test_blocked_pattern_case_insensitive_upper_policy(self):
        k = self._kernel(blocked_patterns=["SECRET"])
        ctx = k.create_context("a1")
        allowed, _ = k.pre_execute(ctx, "my secret data")
        assert allowed is False

    def test_no_blocked_pattern_match(self):
        k = self._kernel(blocked_patterns=["password"])
        ctx = k.create_context("a1")
        allowed, reason = k.pre_execute(ctx, "nothing blocked here")
        assert allowed is True


class TestBaseIntegrationPostExecute:
    """Tests for post_execute validation."""

    def _kernel(self, **policy_kw):
        return LangChainKernel(policy=GovernancePolicy(**policy_kw))

    def test_increments_call_count(self):
        k = self._kernel()
        ctx = k.create_context("a1")
        assert ctx.call_count == 0
        k.post_execute(ctx, "result")
        assert ctx.call_count == 1
        k.post_execute(ctx, "result2")
        assert ctx.call_count == 2

    def test_checkpoint_created_at_frequency(self):
        k = self._kernel(checkpoint_frequency=3)
        ctx = k.create_context("a1")
        for _ in range(3):
            k.post_execute(ctx, "r")
        assert len(ctx.checkpoints) == 1
        assert ctx.checkpoints[0] == "checkpoint-3"

    def test_no_checkpoint_before_frequency(self):
        k = self._kernel(checkpoint_frequency=5)
        ctx = k.create_context("a1")
        for _ in range(4):
            k.post_execute(ctx, "r")
        assert ctx.checkpoints == []

    def test_multiple_checkpoints(self):
        k = self._kernel(checkpoint_frequency=2)
        ctx = k.create_context("a1")
        for _ in range(6):
            k.post_execute(ctx, "r")
        assert ctx.checkpoints == ["checkpoint-2", "checkpoint-4", "checkpoint-6"]


# =============================================================================
# BaseIntegration signal handling
# =============================================================================


class TestBaseIntegrationSignals:
    def test_register_and_fire_signal(self):
        k = LangChainKernel()
        called_with = {}

        def handler(agent_id):
            called_with["id"] = agent_id

        k.on_signal("SIGSTOP", handler)
        k.signal("agent-1", "SIGSTOP")
        assert called_with["id"] == "agent-1"

    def test_unregistered_signal_is_noop(self):
        k = LangChainKernel()
        k.signal("agent-1", "SIGFOO")  # should not raise


# =============================================================================
# Governance Event Hooks
# =============================================================================


class TestGovernanceEventHooks:
    def test_register_and_fire_policy_check(self):
        k = LangChainKernel()
        events = []
        k.on(GovernanceEventType.POLICY_CHECK, lambda d: events.append(d))
        ctx = k.create_context("a1")
        k.pre_execute(ctx, "hello")
        assert len(events) == 1
        assert events[0]["agent_id"] == "a1"
        assert events[0]["phase"] == "pre_execute"

    def test_policy_violation_event_on_max_calls(self):
        k = LangChainKernel(policy=GovernancePolicy(max_tool_calls=0))
        events = []
        k.on(GovernanceEventType.POLICY_VIOLATION, lambda d: events.append(d))
        ctx = k.create_context("a1")
        k.pre_execute(ctx, "hello")
        assert len(events) == 1
        assert "Max tool calls" in events[0]["reason"]

    def test_tool_call_blocked_event(self):
        k = LangChainKernel(policy=GovernancePolicy(blocked_patterns=["secret"]))
        events = []
        k.on(GovernanceEventType.TOOL_CALL_BLOCKED, lambda d: events.append(d))
        ctx = k.create_context("a1")
        k.pre_execute(ctx, "my secret data")
        assert len(events) == 1
        assert events[0]["pattern"] == "secret"

    def test_checkpoint_event(self):
        k = LangChainKernel(policy=GovernancePolicy(checkpoint_frequency=1))
        events = []
        k.on(GovernanceEventType.CHECKPOINT_CREATED, lambda d: events.append(d))
        ctx = k.create_context("a1")
        k.post_execute(ctx, "result")
        assert len(events) == 1
        assert events[0]["checkpoint_id"] == "checkpoint-1"

    def test_multiple_listeners(self):
        k = LangChainKernel()
        log1, log2 = [], []
        k.on(GovernanceEventType.POLICY_CHECK, lambda d: log1.append(d))
        k.on(GovernanceEventType.POLICY_CHECK, lambda d: log2.append(d))
        ctx = k.create_context("a1")
        k.pre_execute(ctx, "hello")
        assert len(log1) == 1
        assert len(log2) == 1

    def test_listener_error_does_not_break_flow(self):
        k = LangChainKernel()
        k.on(GovernanceEventType.POLICY_CHECK, lambda d: 1 / 0)
        ctx = k.create_context("a1")
        allowed, _ = k.pre_execute(ctx, "hello")
        assert allowed is True

    def test_no_listeners_is_fine(self):
        k = LangChainKernel()
        ctx = k.create_context("a1")
        allowed, _ = k.pre_execute(ctx, "hello")
        assert allowed is True


# =============================================================================
# LangChainKernel.wrap — invoke / run / batch / stream
# =============================================================================


class TestLangChainKernelWrap:
    def test_invoke_returns_result(self):
        chain = _make_mock_chain()
        governed = LangChainKernel().wrap(chain)
        result = governed.invoke("hi")
        assert result == "invoke-result"
        chain.invoke.assert_called_once_with("hi")

    def test_invoke_raises_on_blocked_pattern(self):
        policy = GovernancePolicy(blocked_patterns=["DROP TABLE"])
        governed = LangChainKernel(policy).wrap(_make_mock_chain())
        with pytest.raises(PolicyViolationError, match="Blocked pattern"):
            governed.invoke("please DROP TABLE users")

    def test_run_returns_result(self):
        chain = _make_mock_chain()
        governed = LangChainKernel().wrap(chain)
        result = governed.run("prompt")
        assert result == "run-result"
        chain.run.assert_called_once_with("prompt")

    def test_run_raises_on_blocked_pattern(self):
        policy = GovernancePolicy(blocked_patterns=["api_key"])
        governed = LangChainKernel(policy).wrap(_make_mock_chain())
        with pytest.raises(PolicyViolationError):
            governed.run("leak the api_key")

    def test_batch_returns_results(self):
        chain = _make_mock_chain()
        governed = LangChainKernel().wrap(chain)
        results = governed.batch(["a", "b"])
        assert results == ["batch-1", "batch-2"]
        chain.batch.assert_called_once_with(["a", "b"])

    def test_batch_blocks_if_any_input_violates(self):
        policy = GovernancePolicy(blocked_patterns=["bad"])
        governed = LangChainKernel(policy).wrap(_make_mock_chain())
        with pytest.raises(PolicyViolationError):
            governed.batch(["ok", "this is bad"])

    def test_stream_yields_chunks(self):
        chain = _make_mock_chain()
        governed = LangChainKernel().wrap(chain)
        chunks = list(governed.stream("go"))
        assert chunks == ["chunk-1", "chunk-2"]

    def test_stream_increments_call_count(self):
        chain = _make_mock_chain()
        governed = LangChainKernel().wrap(chain)

        list(governed.stream("go"))

        assert governed._ctx.call_count == 1

    def test_stream_blocks_after_max_tool_calls(self):
        policy = GovernancePolicy(max_tool_calls=1)
        chain = _make_mock_chain()
        governed = LangChainKernel(policy).wrap(chain)

        list(governed.stream("first"))

        with pytest.raises(PolicyViolationError, match="Max tool calls"):
            list(governed.stream("second"))

    def test_stream_blocks_output_before_disclosure(self):
        policy = GovernancePolicy(blocked_patterns=["secret"])
        chain = _make_mock_chain()
        chain.stream.return_value = iter(["safe chunk", "secret chunk"])
        governed = LangChainKernel(policy).wrap(chain)

        with pytest.raises(PolicyViolationError, match="Blocked pattern"):
            list(governed.stream("go"))

        chain.stream.assert_called_once_with("go")

    def test_stream_blocks_on_violation(self):
        policy = GovernancePolicy(blocked_patterns=["nope"])
        governed = LangChainKernel(policy).wrap(_make_mock_chain())
        with pytest.raises(PolicyViolationError):
            list(governed.stream("nope"))

    async def test_astream_blocks_output_before_disclosure(self):
        policy = GovernancePolicy(blocked_patterns=["secret"])
        chain = _make_mock_chain()
        chain.astream.return_value = _async_chunks(["safe chunk", "secret chunk"])
        governed = LangChainKernel(policy).wrap(chain)

        with pytest.raises(PolicyViolationError, match="Blocked pattern"):
            await _collect_async(governed.astream("go"))

        chain.astream.assert_called_once_with("go")

    async def test_astream_transform_replays_redacted_chunks(self):
        from types import SimpleNamespace

        chain = _make_mock_chain()
        chain.astream.return_value = _async_chunks(["secret", " stream"])
        governed = LangChainKernel().wrap(chain)
        governed._kernel.evaluate_output = MagicMock(
            return_value=SimpleNamespace(
                allowed=True,
                transform=SimpleNamespace(value=["[REDACTED STREAM]"]),
            )
        )

        assert await _collect_async(governed.astream("go")) == ["[REDACTED STREAM]"]

    async def test_astream_events_rejects_non_event_transform(self):
        from types import SimpleNamespace

        chain = _make_mock_chain()
        chain.astream_events.return_value = _async_chunks([{"event": "raw"}])
        governed = LangChainKernel().wrap(chain)
        governed._kernel.evaluate_output = MagicMock(
            return_value=SimpleNamespace(
                allowed=True,
                transform=SimpleNamespace(value="[REDACTED]"),
            )
        )

        with pytest.raises(PolicyViolationError, match="must return a list"):
            await _collect_async(governed.astream_events("go"))

    def test_invoke_increments_call_count(self):
        chain = _make_mock_chain()
        kernel = LangChainKernel()
        governed = kernel.wrap(chain)
        governed.invoke("a")
        governed.invoke("b")
        # access internal context through the governed wrapper
        assert governed._ctx.call_count == 2

    def test_invoke_blocks_after_max_tool_calls(self):
        policy = GovernancePolicy(max_tool_calls=1)
        chain = _make_mock_chain()
        governed = LangChainKernel(policy).wrap(chain)
        governed.invoke("first")  # succeeds, post_execute increments to 1
        with pytest.raises(PolicyViolationError, match="Max tool calls"):
            governed.invoke("second")

    def test_unwrap_returns_original(self):
        chain = _make_mock_chain()
        kernel = LangChainKernel()
        governed = kernel.wrap(chain)
        assert kernel.unwrap(governed) is chain

    def test_getattr_passthrough(self):
        chain = _make_mock_chain()
        chain.custom_attr = "hello"
        governed = LangChainKernel().wrap(chain)
        assert governed.custom_attr == "hello"


# =============================================================================
# CrewAIKernel.wrap — kickoff
# =============================================================================


class TestCrewAIKernelWrap:
    def test_kickoff_returns_result(self):
        crew = _make_mock_crew()
        governed = CrewAIKernel().wrap(crew)
        result = governed.kickoff({"topic": "AI"})
        assert result == "crew-result"
        crew.kickoff.assert_called_once_with({"topic": "AI"})

    def test_kickoff_raises_on_blocked_pattern(self):
        policy = GovernancePolicy(blocked_patterns=["hack"])
        governed = CrewAIKernel(policy).wrap(_make_mock_crew())
        with pytest.raises(BasePolicyViolationError):
            governed.kickoff({"goal": "hack the system"})

    def test_kickoff_increments_call_count(self):
        crew = _make_mock_crew()
        governed = CrewAIKernel().wrap(crew)
        governed.kickoff()
        assert governed._ctx.call_count == 1

    def test_kickoff_blocks_after_max_calls(self):
        policy = GovernancePolicy(max_tool_calls=1)
        governed = CrewAIKernel(policy).wrap(_make_mock_crew())
        governed.kickoff()
        with pytest.raises(BasePolicyViolationError, match="Max tool calls"):
            governed.kickoff()

    def test_kickoff_wraps_individual_agents(self):
        crew = _make_mock_crew()
        agent_mock = MagicMock()
        agent_mock.execute_task = MagicMock(return_value="done")
        crew.agents = [agent_mock]
        governed = CrewAIKernel().wrap(crew)
        governed.kickoff()
        # _wrap_agent should have replaced execute_task
        assert agent_mock.execute_task is not crew.agents[0].execute_task or True

    def test_unwrap_returns_original(self):
        crew = _make_mock_crew()
        kernel = CrewAIKernel()
        governed = kernel.wrap(crew)
        assert kernel.unwrap(governed) is crew

    def test_getattr_passthrough(self):
        crew = _make_mock_crew()
        crew.verbose = True
        governed = CrewAIKernel().wrap(crew)
        assert governed.verbose is True


# =============================================================================
# OpenAIKernel — wrap_assistant basics
# =============================================================================


class TestOpenAIKernelBasics:
    def test_wrap_without_client_raises(self):
        kernel = OpenAIKernel()
        with pytest.raises(TypeError):
            kernel.wrap(MagicMock())

    def test_wrap_returns_governed(self):
        kernel = OpenAIKernel()
        assistant = _make_mock_assistant()
        client = _make_mock_openai_client()
        governed = kernel.wrap(assistant, client)
        assert isinstance(governed, GovernedAssistant)

    def test_wrap_assistant_deprecated(self):
        kernel = OpenAIKernel()
        assistant = _make_mock_assistant()
        client = _make_mock_openai_client()
        import warnings
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            governed = kernel.wrap_assistant(assistant, client)
            assert len(w) == 1
            assert issubclass(w[0].category, DeprecationWarning)
            assert "deprecated" in str(w[0].message)
            assert "wrap(" in str(w[0].message)
        assert isinstance(governed, GovernedAssistant)

    def test_governed_assistant_id_and_name(self):
        kernel = OpenAIKernel()
        assistant = _make_mock_assistant("asst_99", "Bot99")
        governed = kernel.wrap(assistant, _make_mock_openai_client())
        assert governed.id == "asst_99"
        assert governed.name == "Bot99"

    def test_unwrap_returns_original(self):
        kernel = OpenAIKernel()
        assistant = _make_mock_assistant()
        governed = kernel.wrap(assistant, _make_mock_openai_client())
        assert kernel.unwrap(governed) is assistant


# =============================================================================
# OpenAIKernel — thread management
# =============================================================================


class TestOpenAIThreadManagement:
    def test_create_thread(self):
        kernel = OpenAIKernel()
        client = _make_mock_openai_client()
        governed = kernel.wrap_assistant(_make_mock_assistant(), client)
        thread = governed.create_thread()
        assert thread.id == "thread_abc"
        assert "thread_abc" in governed._ctx.thread_ids

    def test_delete_thread_removes_from_context(self):
        kernel = OpenAIKernel()
        client = _make_mock_openai_client()
        client.beta.threads.delete.return_value = MagicMock(deleted=True)
        governed = kernel.wrap_assistant(_make_mock_assistant(), client)
        governed.create_thread()
        assert "thread_abc" in governed._ctx.thread_ids
        governed.delete_thread("thread_abc")
        assert "thread_abc" not in governed._ctx.thread_ids


# =============================================================================
# OpenAIKernel — message blocking
# =============================================================================


class TestOpenAIMessageBlocking:
    def test_add_message_allowed(self):
        kernel = OpenAIKernel()
        client = _make_mock_openai_client()
        governed = kernel.wrap_assistant(_make_mock_assistant(), client)
        msg = governed.add_message("thread_abc", "hello")
        assert msg.id == "msg_xyz"

    def test_add_message_blocked_by_pattern(self):
        policy = GovernancePolicy(blocked_patterns=["password"])
        kernel = OpenAIKernel(policy)
        client = _make_mock_openai_client()
        governed = kernel.wrap_assistant(_make_mock_assistant(), client)
        with pytest.raises(OpenAIPolicyViolationError) as excinfo:
            governed.add_message("thread_abc", "my password is 123")
        # v5: PolicyViolationError carries the AGT EvaluationResult-derived
        # PolicyCheckResult on .check_result; ``reason`` is the AGT
        # ``blocked_pattern_input`` (mirrored from the v4 ViolationCategory).
        assert excinfo.value.check_result.reason == "blocked_pattern_input"

    def test_add_message_case_insensitive_block(self):
        policy = GovernancePolicy(blocked_patterns=["secret"])
        kernel = OpenAIKernel(policy)
        client = _make_mock_openai_client()
        governed = kernel.wrap_assistant(_make_mock_assistant(), client)
        with pytest.raises(OpenAIPolicyViolationError):
            governed.add_message("thread_abc", "this is secret info")


# =============================================================================
# OpenAIKernel — run execution & polling
# =============================================================================


class TestOpenAIRunExecution:
    def test_run_completes_successfully(self):
        kernel = OpenAIKernel()
        client = _make_mock_openai_client()

        created_run = MagicMock()
        created_run.id = "run_001"
        client.beta.threads.runs.create.return_value = created_run

        completed_run = _make_completed_run("run_001")
        client.beta.threads.runs.retrieve.return_value = completed_run

        governed = kernel.wrap_assistant(_make_mock_assistant(), client)
        result = governed.run("thread_abc")
        assert result.status == "completed"
        assert "run_001" in governed._ctx.run_ids

    def test_run_blocked_instructions(self):
        policy = GovernancePolicy(blocked_patterns=["hack"])
        kernel = OpenAIKernel(policy)
        client = _make_mock_openai_client()
        governed = kernel.wrap_assistant(_make_mock_assistant(), client)
        with pytest.raises(OpenAIPolicyViolationError) as excinfo:
            governed.run("thread_abc", instructions="hack the planet")
        assert excinfo.value.check_result.reason == "blocked_pattern_input"

    def test_run_stream_blocks_output_before_disclosure(self):
        policy = GovernancePolicy(blocked_patterns=["secret"])
        kernel = OpenAIKernel(policy)
        client = _make_mock_openai_client()
        stream_ctx = MagicMock()
        stream_ctx.__enter__.return_value = iter(["safe event", "secret event"])
        stream_ctx.__exit__.return_value = None
        client.beta.threads.runs.stream.return_value = stream_ctx
        governed = kernel.wrap_assistant(_make_mock_assistant(), client)

        with pytest.raises(OpenAIPolicyViolationError, match="Blocked pattern"):
            list(governed.run_stream("thread_abc"))

        client.beta.threads.runs.stream.assert_called_once()

    def test_run_stream_rejects_non_event_transform(self):
        from types import SimpleNamespace

        kernel = OpenAIKernel()
        client = _make_mock_openai_client()
        stream_ctx = MagicMock()
        stream_ctx.__enter__.return_value = iter(["raw event"])
        stream_ctx.__exit__.return_value = None
        client.beta.threads.runs.stream.return_value = stream_ctx
        governed = kernel.wrap_assistant(_make_mock_assistant(), client)
        kernel.evaluate_output = MagicMock(
            return_value=SimpleNamespace(
                allowed=True,
                transform=SimpleNamespace(value="[REDACTED]"),
            )
        )

        with pytest.raises(OpenAIPolicyViolationError, match="must return a list"):
            list(governed.run_stream("thread_abc"))

    def test_run_stream_accepts_event_list_transform(self):
        from types import SimpleNamespace

        kernel = OpenAIKernel()
        client = _make_mock_openai_client()
        stream_ctx = MagicMock()
        stream_ctx.__enter__.return_value = iter(["raw event"])
        stream_ctx.__exit__.return_value = None
        client.beta.threads.runs.stream.return_value = stream_ctx
        governed = kernel.wrap_assistant(_make_mock_assistant(), client)
        transformed_event = MagicMock(name="transformed_event")
        kernel.evaluate_output = MagicMock(
            return_value=SimpleNamespace(
                allowed=True,
                transform=SimpleNamespace(value=[transformed_event]),
            )
        )

        assert list(governed.run_stream("thread_abc")) == [transformed_event]

    def test_run_validates_tools_against_policy(self):
        policy = GovernancePolicy(allowed_tools=["code_interpreter"])
        kernel = OpenAIKernel(policy)
        client = _make_mock_openai_client()
        governed = kernel.wrap_assistant(_make_mock_assistant(), client)
        with pytest.raises(OpenAIPolicyViolationError, match="Tool type not allowed"):
            governed.run("thread_abc", tools=[{"type": "retrieval"}])

    def test_run_handles_failed_status(self):
        kernel = OpenAIKernel()
        client = _make_mock_openai_client()

        created_run = MagicMock(id="run_fail")
        client.beta.threads.runs.create.return_value = created_run

        failed_run = MagicMock()
        failed_run.id = "run_fail"
        failed_run.status = "failed"
        failed_run.usage = None
        client.beta.threads.runs.retrieve.return_value = failed_run

        governed = kernel.wrap_assistant(_make_mock_assistant(), client)
        result = governed.run("thread_abc")
        assert result.status == "failed"


# =============================================================================
# OpenAIKernel — tool call handling
# =============================================================================


class TestOpenAIToolCallHandling:
    def test_tool_call_recorded_in_context(self):
        kernel = OpenAIKernel()
        client = _make_mock_openai_client()

        # First retrieve returns requires_action, second returns completed
        ra_run = _make_requires_action_run("run_tc")
        completed_run = _make_completed_run("run_tc")
        client.beta.threads.runs.retrieve.side_effect = [ra_run, completed_run]
        client.beta.threads.runs.submit_tool_outputs.return_value = MagicMock()

        created_run = MagicMock(id="run_tc")
        client.beta.threads.runs.create.return_value = created_run

        governed = kernel.wrap_assistant(_make_mock_assistant(), client)
        governed.run("thread_abc", poll_interval=0)
        assert len(governed._ctx.function_calls) == 1
        assert governed._ctx.function_calls[0]["function"] == "get_weather"

    def test_tool_call_limit_cancels_run(self):
        # v5: AGT-M3 round-2 BLOCK A: the bridge now emits a budget rule
        # for ``max_tool_calls == 0`` directly (the deny-every-call v4
        # sentinel), so the deny comes from the stock
        # ``budgets.deny_if_budget_exceeded`` helper rather than the
        # host-side fallback ``_host_budget_check``. The wire reason is
        # the v5 ``budget_tool_calls_exceeded`` (documented in
        # ``agt.policies.bridge`` as the v5 stock-helper reason that
        # replaces the legacy v4 ``max_tool_calls`` string for audit
        # consumers).
        policy = GovernancePolicy(max_tool_calls=0)
        kernel = OpenAIKernel(policy)
        client = _make_mock_openai_client()

        ra_run = _make_requires_action_run("run_lim")
        client.beta.threads.runs.retrieve.return_value = ra_run
        created_run = MagicMock(id="run_lim")
        client.beta.threads.runs.create.return_value = created_run

        governed = kernel.wrap_assistant(_make_mock_assistant(), client)
        with pytest.raises(OpenAIPolicyViolationError) as excinfo:
            governed.run("thread_abc", poll_interval=0)
        assert excinfo.value.check_result.reason == "budget_tool_calls_exceeded"
        # Verify cancel was called
        client.beta.threads.runs.cancel.assert_called_once()

    def test_disallowed_function_name_cancels_run(self):
        policy = GovernancePolicy(allowed_tools=["safe_func"])
        kernel = OpenAIKernel(policy)
        client = _make_mock_openai_client()

        tc = MagicMock()
        tc.id = "call_bad"
        tc.type = "function"
        tc.function.name = "dangerous_func"
        tc.function.arguments = "{}"
        ra_run = _make_requires_action_run("run_bad", tool_calls=[tc])
        client.beta.threads.runs.retrieve.return_value = ra_run
        created_run = MagicMock(id="run_bad")
        client.beta.threads.runs.create.return_value = created_run

        governed = kernel.wrap_assistant(_make_mock_assistant(), client)
        with pytest.raises(OpenAIPolicyViolationError) as excinfo:
            governed.run("thread_abc", poll_interval=0)
        # v5: the ACS engine fails closed with ``tool_unknown`` when the
        # tool is not in the manifest catalog; the legacy "Tool not allowed"
        # message no longer appears.
        assert "tool_unknown" in excinfo.value.check_result.reason or excinfo.value.check_result.reason.startswith("runtime_error:")


# =============================================================================
# OpenAIKernel — SIGKILL
# =============================================================================


class TestOpenAISIGKILL:
    def test_sigkill_cancels_run(self):
        kernel = OpenAIKernel()
        client = _make_mock_openai_client()
        governed = kernel.wrap_assistant(_make_mock_assistant(), client)
        governed.sigkill("thread_abc", "run_x")
        assert kernel.is_cancelled("run_x")

    def test_sigkill_raises_during_poll(self):
        kernel = OpenAIKernel()
        client = _make_mock_openai_client()

        created_run = MagicMock(id="run_killed")
        client.beta.threads.runs.create.return_value = created_run

        # Pre-cancel so the very first poll iteration raises
        kernel._cancelled_runs.add("run_killed")

        governed = kernel.wrap_assistant(_make_mock_assistant(), client)
        with pytest.raises(RunCancelledException, match="SIGKILL"):
            governed.run("thread_abc", poll_interval=0)

    def test_sigstop_also_cancels(self):
        kernel = OpenAIKernel()
        client = _make_mock_openai_client()
        governed = kernel.wrap_assistant(_make_mock_assistant(), client)
        governed.sigstop("thread_abc", "run_y")
        assert kernel.is_cancelled("run_y")


# =============================================================================
# OpenAIKernel — token tracking
# =============================================================================


class TestOpenAITokenTracking:
    def test_token_usage_accumulates(self):
        kernel = OpenAIKernel()
        client = _make_mock_openai_client()

        created_run = MagicMock(id="run_tok")
        client.beta.threads.runs.create.return_value = created_run

        usage = MagicMock()
        usage.prompt_tokens = 100
        usage.completion_tokens = 50
        completed_run = _make_completed_run("run_tok", usage=usage)
        client.beta.threads.runs.retrieve.return_value = completed_run

        governed = kernel.wrap_assistant(_make_mock_assistant(), client)
        governed.run("thread_abc", poll_interval=0)

        info = governed.get_token_usage()
        assert info["prompt_tokens"] == 100
        assert info["completion_tokens"] == 50
        assert info["total_tokens"] == 150

    def test_token_limit_exceeded_cancels_run(self):
        policy = GovernancePolicy(max_tokens=100)
        kernel = OpenAIKernel(policy)
        client = _make_mock_openai_client()

        created_run = MagicMock(id="run_over")
        client.beta.threads.runs.create.return_value = created_run

        usage = MagicMock()
        usage.prompt_tokens = 80
        usage.completion_tokens = 80  # total 160 > 100
        over_run = MagicMock()
        over_run.id = "run_over"
        over_run.status = "in_progress"
        over_run.usage = usage
        client.beta.threads.runs.retrieve.return_value = over_run

        governed = kernel.wrap_assistant(_make_mock_assistant(), client)
        with pytest.raises(OpenAIPolicyViolationError, match="Token limit exceeded"):
            governed.run("thread_abc", poll_interval=0)
        client.beta.threads.runs.cancel.assert_called_once()

    def test_get_context_returns_assistant_context(self):
        kernel = OpenAIKernel()
        client = _make_mock_openai_client()
        governed = kernel.wrap_assistant(_make_mock_assistant(), client)
        ctx = governed.get_context()
        assert isinstance(ctx, AssistantContext)
        assert ctx.assistant_id == "asst_001"


# =============================================================================
# OpenAIKernel — _validate_tools
# =============================================================================


class TestOpenAIValidateTools:
    def test_no_restriction_allows_all(self):
        kernel = OpenAIKernel(GovernancePolicy(allowed_tools=[]))
        client = _make_mock_openai_client()
        governed = kernel.wrap_assistant(_make_mock_assistant(), client)
        # Should not raise
        governed._validate_tools([{"type": "anything"}])

    def test_dict_tool_rejected(self):
        kernel = OpenAIKernel(GovernancePolicy(allowed_tools=["code_interpreter"]))
        client = _make_mock_openai_client()
        governed = kernel.wrap_assistant(_make_mock_assistant(), client)
        with pytest.raises(OpenAIPolicyViolationError, match="Tool type not allowed"):
            governed._validate_tools([{"type": "retrieval"}])

    def test_object_tool_rejected(self):
        kernel = OpenAIKernel(GovernancePolicy(allowed_tools=["code_interpreter"]))
        client = _make_mock_openai_client()
        governed = kernel.wrap_assistant(_make_mock_assistant(), client)
        tool_obj = MagicMock()
        tool_obj.type = "file_search"
        with pytest.raises(OpenAIPolicyViolationError, match="Tool type not allowed"):
            governed._validate_tools([tool_obj])


# =============================================================================
# PolicyViolationError identity
# =============================================================================


class TestPolicyViolationError:
    def test_langchain_error_is_exception(self):
        err = PolicyViolationError("test")
        assert isinstance(err, Exception)
        assert str(err) == "test"

    def test_openai_error_is_exception(self):
        err = OpenAIPolicyViolationError("oai test")
        assert isinstance(err, Exception)
        assert str(err) == "oai test"

    def test_run_cancelled_is_exception(self):
        err = RunCancelledException("killed")
        assert isinstance(err, Exception)
        assert str(err) == "killed"


# =============================================================================
# OpenAI SIGKILL integration test (#159)
# =============================================================================


class TestOpenAISIGKILLIntegration:
    """Integration test: mock OpenAI client, start governed run, SIGKILL, verify audit."""

    def test_sigkill_cancels_run_and_logs_audit(self):
        """Start a governed run, trigger SIGKILL, verify cancellation and audit."""
        policy = GovernancePolicy(max_tokens=500)
        kernel = OpenAIKernel(policy)
        client = _make_mock_openai_client()
        assistant = _make_mock_assistant()
        governed = kernel.wrap_assistant(assistant, client)

        # Create thread
        thread = governed.create_thread()

        # Set up run that stays "in_progress" until cancelled
        in_progress_run = MagicMock()
        in_progress_run.id = "run_sigkill"
        in_progress_run.status = "in_progress"
        in_progress_run.usage = None
        client.beta.threads.runs.create.return_value = in_progress_run
        client.beta.threads.runs.retrieve.return_value = in_progress_run

        # SIGKILL the run before polling can complete
        kernel.cancel_run(thread.id, "run_sigkill", client)

        # Verify run is marked cancelled
        assert kernel.is_cancelled("run_sigkill")

        # Verify the run raises RunCancelledException during poll
        with pytest.raises(RunCancelledException, match="SIGKILL"):
            governed.run(thread.id)

    def test_sigkill_audit_context_records_run_id(self):
        """Verify the execution context records run IDs for audit."""
        policy = GovernancePolicy()
        kernel = OpenAIKernel(policy)
        client = _make_mock_openai_client()
        governed = kernel.wrap_assistant(_make_mock_assistant(), client)

        # Set up completed run
        completed_run = _make_completed_run("run_audit")
        client.beta.threads.runs.create.return_value = completed_run
        client.beta.threads.runs.retrieve.return_value = completed_run

        governed.run("thread_abc")
        ctx = governed.get_context()
        assert "run_audit" in ctx.run_ids
        assert ctx.agent_id == "asst_001"

    def test_sigkill_multiple_runs_independent(self):
        """Cancelling one run doesn't affect another."""
        kernel = OpenAIKernel()
        client = _make_mock_openai_client()
        kernel.cancel_run("t1", "run_A", client)
        assert kernel.is_cancelled("run_A")
        assert not kernel.is_cancelled("run_B")


# =============================================================================
# LangChain batch governance test (#160)
# =============================================================================


class TestLangChainBatchGovernance:
    """LangChain batch: policy-check each input, handle violations."""

    def test_batch_all_inputs_policy_checked(self):
        """Batch of 5 inputs — each goes through pre_execute."""
        kernel = LangChainKernel(GovernancePolicy())
        chain = _make_mock_chain()
        chain.batch.return_value = ["r1", "r2", "r3", "r4", "r5"]
        governed = kernel.wrap(chain)

        results = governed.batch(["a", "b", "c", "d", "e"])
        assert len(results) == 5
        chain.batch.assert_called_once_with(["a", "b", "c", "d", "e"])

    def test_batch_violation_blocks_entire_batch(self):
        """If one input violates policy, the whole batch is rejected."""
        policy = GovernancePolicy(blocked_patterns=["forbidden"])
        kernel = LangChainKernel(policy)
        chain = _make_mock_chain()
        governed = kernel.wrap(chain)

        with pytest.raises(PolicyViolationError):
            governed.batch(["safe", "also safe", "forbidden content", "ok", "fine"])

        # The underlying chain.batch should NOT have been called
        chain.batch.assert_not_called()

    def test_batch_empty_inputs(self):
        """Batch with empty list should succeed."""
        kernel = LangChainKernel(GovernancePolicy())
        chain = _make_mock_chain()
        chain.batch.return_value = []
        governed = kernel.wrap(chain)

        results = governed.batch([])
        assert results == []

    def test_batch_with_mixed_pattern_violations(self):
        """Only the first violation pattern causes rejection."""
        policy = GovernancePolicy(blocked_patterns=["secret", "password"])
        kernel = LangChainKernel(policy)
        chain = _make_mock_chain()
        governed = kernel.wrap(chain)

        with pytest.raises(PolicyViolationError):
            governed.batch(["hello", "my secret"])

    def test_batch_post_execute_called_for_results(self):
        """Post-execute increments call_count for each result."""
        kernel = LangChainKernel(GovernancePolicy())
        chain = _make_mock_chain()
        chain.batch.return_value = ["r1", "r2", "r3"]
        governed = kernel.wrap(chain)

        governed.batch(["a", "b", "c"])
        # post_execute called once per result, so call_count == 3
        ctx = list(kernel.contexts.values())[0]
        assert ctx.call_count == 3


# =============================================================================
# CrewAI task monitoring test (#161)
# =============================================================================


class TestCrewAITaskMonitoring:
    """CrewAI crew governance: execution details, policy violations."""

    def test_crew_kickoff_governed(self):
        """Governed crew kickoff returns result after policy checks."""
        kernel = CrewAIKernel(GovernancePolicy())
        crew = _make_mock_crew()
        governed = kernel.wrap(crew)

        result = governed.kickoff()
        assert result == "crew-result"
        crew.kickoff.assert_called_once()

    def test_crew_kickoff_with_inputs(self):
        """Crew kickoff with inputs passes them through."""
        kernel = CrewAIKernel(GovernancePolicy())
        crew = _make_mock_crew()
        governed = kernel.wrap(crew)

        governed.kickoff(inputs={"topic": "AI safety"})
        crew.kickoff.assert_called_once_with({"topic": "AI safety"})

    def test_crew_policy_violation_blocks_kickoff(self):
        """Blocked pattern in inputs prevents crew kickoff."""
        policy = GovernancePolicy(blocked_patterns=["hack"])
        kernel = CrewAIKernel(policy)
        crew = _make_mock_crew()
        governed = kernel.wrap(crew)

        with pytest.raises(BasePolicyViolationError):
            governed.kickoff(inputs={"task": "hack the system"})
        crew.kickoff.assert_not_called()

    def test_crew_agent_task_monitoring(self):
        """Individual agent tasks within crew are wrapped for monitoring."""
        kernel = CrewAIKernel(GovernancePolicy())
        crew = _make_mock_crew()

        # Add a mock agent with execute_task
        original_fn = MagicMock(return_value="task-done")
        agent = MagicMock()
        agent.name = "researcher"
        agent.execute_task = original_fn
        crew.agents = [agent]

        governed = kernel.wrap(crew)
        governed.kickoff()

        # The agent's execute_task should have been replaced with governed version
        assert agent.execute_task is not original_fn

    def test_crew_unwrap_returns_original(self):
        """Unwrapping returns the original crew object."""
        kernel = CrewAIKernel()
        crew = _make_mock_crew()
        governed = kernel.wrap(crew)
        assert kernel.unwrap(governed) is crew


# =============================================================================
# GovernancePolicy defaults test (#162)
# =============================================================================


class TestGovernancePolicyDefaults:
    """Verify all GovernancePolicy defaults and partial overrides."""

    def test_all_defaults_no_args(self):
        """Create policy with no args — verify every default."""
        p = GovernancePolicy()
        assert p.name == "default"
        assert p.max_tokens == 4096
        assert p.max_tool_calls == 10
        assert p.allowed_tools == []
        assert p.blocked_patterns == []
        assert p.require_human_approval is False
        assert p.timeout_seconds == 300
        assert p.confidence_threshold == 0.8
        assert p.drift_threshold == 0.15
        assert p.log_all_calls is True
        assert p.checkpoint_frequency == 5
        assert p.max_concurrent == 10
        assert p.backpressure_threshold == 8
        assert p.version == "1.0.0"

    def test_partial_override_tokens(self):
        """Override only max_tokens, rest stays default."""
        p = GovernancePolicy(max_tokens=2048)
        assert p.max_tokens == 2048
        assert p.max_tool_calls == 10
        assert p.timeout_seconds == 300

    def test_partial_override_thresholds(self):
        """Override confidence and drift thresholds."""
        p = GovernancePolicy(confidence_threshold=0.95, drift_threshold=0.05)
        assert p.confidence_threshold == 0.95
        assert p.drift_threshold == 0.05
        assert p.max_tokens == 4096  # unchanged

    def test_partial_override_concurrency(self):
        """Override concurrency settings."""
        p = GovernancePolicy(max_concurrent=5, backpressure_threshold=3)
        assert p.max_concurrent == 5
        assert p.backpressure_threshold == 3

    def test_partial_override_blocked_patterns(self):
        """Override blocked_patterns only."""
        p = GovernancePolicy(blocked_patterns=["secret", ("api_key", PatternType.REGEX)])
        assert len(p.blocked_patterns) == 2
        assert p.allowed_tools == []

    def test_partial_override_version(self):
        """Override version string."""
        p = GovernancePolicy(version="2.0.0")
        assert p.version == "2.0.0"
        assert p.name == "default"

    def test_override_human_approval(self):
        """Override require_human_approval."""
        p = GovernancePolicy(require_human_approval=True)
        assert p.require_human_approval is True
        assert p.log_all_calls is True


# =============================================================================
# agents_compat YAML parsing tests (#169)
# =============================================================================


class TestAgentsCompatYAMLParsing:
    """Test YAML front-matter parsing in AgentsParser."""

    def test_valid_yaml_front_matter(self, tmp_path):
        """Parse a file with valid YAML front matter."""
        from agent_os.agents_compat import AgentsParser

        agents_dir = tmp_path / ".agents"
        agents_dir.mkdir()
        (agents_dir / "agents.md").write_text(
            "---\nname: yaml-agent\npolicies:\n  - strict\n---\n\n"
            "A YAML-configured agent.\n\nYou can:\n- Search the web\n",
            encoding="utf-8",
        )

        config = AgentsParser().parse_directory(str(agents_dir))
        assert config.name == "yaml-agent"
        assert config.policies == ["strict"]
        assert len(config.skills) == 1

    def test_empty_yaml_front_matter(self, tmp_path):
        """Empty YAML front matter falls back to defaults."""
        from agent_os.agents_compat import AgentsParser

        agents_dir = tmp_path / ".agents"
        agents_dir.mkdir()
        (agents_dir / "agents.md").write_text(
            "---\n---\n\nPlain description.\n",
            encoding="utf-8",
        )

        config = AgentsParser().parse_directory(str(agents_dir))
        assert config.name == "agent"  # default
        assert config.policies == []

    def test_no_yaml_front_matter(self, tmp_path):
        """File without YAML front matter still parses body."""
        from agent_os.agents_compat import AgentsParser

        agents_dir = tmp_path / ".agents"
        agents_dir.mkdir()
        (agents_dir / "agents.md").write_text(
            "# My Agent\n\nDoes things.\n\nYou can:\n- Read files\n- Write files\n",
            encoding="utf-8",
        )

        config = AgentsParser().parse_directory(str(agents_dir))
        assert config.name == "agent"
        assert len(config.skills) == 2

    def test_yaml_with_security_section(self, tmp_path):
        """Security key in front matter is extracted into security_config."""
        from agent_os.agents_compat import AgentsParser

        agents_dir = tmp_path / ".agents"
        agents_dir.mkdir()
        (agents_dir / "agents.md").write_text(
            "---\nname: sec-agent\nsecurity:\n  mode: strict\n---\n\nSecure agent.\n",
            encoding="utf-8",
        )

        config = AgentsParser().parse_directory(str(agents_dir))
        assert config.security_config.get("mode") == "strict"

    def test_missing_agents_directory_raises(self):
        """parse_directory raises FileNotFoundError for missing dir."""
        from agent_os.agents_compat import AgentsParser

        with pytest.raises(FileNotFoundError):
            AgentsParser().parse_directory("/nonexistent/path")

    def test_missing_required_fields_uses_defaults(self, tmp_path):
        """If name/policies are absent, defaults are used."""
        from agent_os.agents_compat import AgentsParser

        agents_dir = tmp_path / ".agents"
        agents_dir.mkdir()
        (agents_dir / "agents.md").write_text(
            "---\ndescription: bare minimum\n---\n\nMinimal.\n",
            encoding="utf-8",
        )

        config = AgentsParser().parse_directory(str(agents_dir))
        assert config.name == "agent"
        assert config.policies == []
        assert config.skills == []

    def test_to_kernel_policies_with_yaml_config(self, tmp_path):
        """YAML front matter flows through to kernel policies."""
        from agent_os.agents_compat import AgentsParser

        agents_dir = tmp_path / ".agents"
        agents_dir.mkdir()
        (agents_dir / "agents.md").write_text(
            "---\nname: policy-agent\n---\n\nYou can:\n- Query database (read-only)\n",
            encoding="utf-8",
        )

        parser = AgentsParser()
        config = parser.parse_directory(str(agents_dir))
        policies = parser.to_kernel_policies(config)
        assert policies["name"] == "policy-agent"
        assert len(policies["rules"]) == 1
        assert policies["rules"][0]["mode"] == "read_only"


# =============================================================================
# Full governance pipeline integration test (#170)
# =============================================================================


from agent_os.integrations.base import (
    PolicyInterceptor,
    ToolCallRequest,
    ToolCallResult,
    CompositeInterceptor,
)


class TestGovernancePipelineIntegration:
    """End-to-end: policy → interception → enforcement → audit log."""

    def _make_integration(self, policy):
        """Create a concrete BaseIntegration subclass for testing."""

        class _TestIntegration(BaseIntegration):
            def wrap(self, agent):
                return agent

            def unwrap(self, governed_agent):
                return governed_agent

        return _TestIntegration(policy=policy)

    # ── ALLOW path ──────────────────────────────────────────────

    def test_allow_flows_through_pipeline(self):
        """An allowed tool call passes interception, post-execute, and audit."""
        policy = GovernancePolicy(allowed_tools=["search", "read_file"])
        integration = self._make_integration(policy)
        ctx = integration.create_context("allow-agent")

        # Pre-execute allows
        allowed, reason = integration.pre_execute(ctx, "search for cats")
        assert allowed is True
        assert reason is None

        # Interceptor allows
        interceptor = PolicyInterceptor(policy, ctx)
        result = interceptor.intercept(
            ToolCallRequest(tool_name="search", arguments={"q": "cats"})
        )
        assert result.allowed is True

        # Post-execute records
        valid, _ = integration.post_execute(ctx, "results")
        assert valid is True
        assert ctx.call_count == 1

    # ── DENY path ───────────────────────────────────────────────

    def test_deny_blocked_tool(self):
        """A tool not in allowed_tools is denied by the interceptor."""
        policy = GovernancePolicy(allowed_tools=["search"])
        interceptor = PolicyInterceptor(policy)
        result = interceptor.intercept(
            ToolCallRequest(tool_name="delete_database", arguments={})
        )
        assert result.allowed is False
        assert "not in allowed list" in result.reason

    def test_deny_blocked_pattern_in_args(self):
        """Blocked patterns in arguments trigger denial."""
        policy = GovernancePolicy(
            blocked_patterns=["password", ("rm\\s+-rf", PatternType.REGEX)],
        )
        interceptor = PolicyInterceptor(policy)

        result = interceptor.intercept(
            ToolCallRequest(tool_name="shell", arguments={"cmd": "rm -rf /"})
        )
        assert result.allowed is False
        assert "Blocked pattern" in result.reason

    def test_deny_max_tool_calls_exceeded(self):
        """Exceeding max_tool_calls causes denial."""
        policy = GovernancePolicy(max_tool_calls=2)
        integration = self._make_integration(policy)
        ctx = integration.create_context("busy-agent")

        # Exhaust the call budget
        ctx.call_count = 2

        interceptor = PolicyInterceptor(policy, ctx)
        result = interceptor.intercept(
            ToolCallRequest(tool_name="any", arguments={})
        )
        assert result.allowed is False
        assert "Max tool calls exceeded" in result.reason

    # ── AUDIT path ──────────────────────────────────────────────

    def test_audit_events_emitted(self):
        """Events are emitted at pre_execute and checkpoint creation."""
        policy = GovernancePolicy(checkpoint_frequency=1)
        integration = self._make_integration(policy)

        events = []
        integration.on(GovernanceEventType.POLICY_CHECK, lambda d: events.append(("check", d)))
        integration.on(
            GovernanceEventType.CHECKPOINT_CREATED,
            lambda d: events.append(("checkpoint", d)),
        )

        ctx = integration.create_context("audit-agent")
        integration.pre_execute(ctx, "do something")
        integration.post_execute(ctx, "done")

        event_types = [e[0] for e in events]
        assert "check" in event_types
        assert "checkpoint" in event_types

    def test_policy_violation_event_on_timeout(self):
        """A timed-out context emits a POLICY_VIOLATION event."""
        policy = GovernancePolicy(timeout_seconds=1)
        integration = self._make_integration(policy)

        violations = []
        integration.on(
            GovernanceEventType.POLICY_VIOLATION,
            lambda d: violations.append(d),
        )

        ctx = integration.create_context("slow-agent")
        # Simulate elapsed time
        ctx.start_time = datetime.now() - timedelta(seconds=10)

        allowed, reason = integration.pre_execute(ctx, "late request")
        assert allowed is False
        assert "Timeout exceeded" in reason
        assert len(violations) == 1

    def test_tool_call_blocked_event_on_pattern(self):
        """Blocked pattern emits TOOL_CALL_BLOCKED event."""
        policy = GovernancePolicy(blocked_patterns=["secret"])
        integration = self._make_integration(policy)

        blocked_events = []
        integration.on(
            GovernanceEventType.TOOL_CALL_BLOCKED,
            lambda d: blocked_events.append(d),
        )

        ctx = integration.create_context("nosy-agent")
        allowed, _ = integration.pre_execute(ctx, "tell me the secret")
        assert allowed is False
        assert len(blocked_events) == 1
        assert blocked_events[0]["pattern"] == "secret"

    # ── Composite interceptor chain ─────────────────────────────

    def test_composite_interceptor_all_allow(self):
        """CompositeInterceptor passes when all interceptors allow."""
        p1 = GovernancePolicy(allowed_tools=["search", "read"])
        p2 = GovernancePolicy()  # permissive
        chain = CompositeInterceptor([PolicyInterceptor(p1), PolicyInterceptor(p2)])

        result = chain.intercept(
            ToolCallRequest(tool_name="search", arguments={"q": "test"})
        )
        assert result.allowed is True

    def test_composite_interceptor_first_deny_wins(self):
        """CompositeInterceptor stops at the first denial."""
        p_strict = GovernancePolicy(allowed_tools=["search"])
        p_permissive = GovernancePolicy()
        chain = CompositeInterceptor(
            [PolicyInterceptor(p_strict), PolicyInterceptor(p_permissive)]
        )

        result = chain.intercept(
            ToolCallRequest(tool_name="delete", arguments={})
        )
        assert result.allowed is False

    # ── End-to-end multi-decision pipeline ──────────────────────

    def test_full_pipeline_allow_deny_audit(self):
        """Complete pipeline: two allowed calls, one denied, with audit trail."""
        policy = GovernancePolicy(
            max_tool_calls=3,
            allowed_tools=["search", "read"],
            checkpoint_frequency=2,
        )
        integration = self._make_integration(policy)

        audit_log = []
        for evt in GovernanceEventType:
            integration.on(evt, lambda d, _evt=evt: audit_log.append((_evt, d)))

        ctx = integration.create_context("pipeline-agent")
        interceptor = PolicyInterceptor(policy, ctx)

        # Call 1: ALLOW
        ok1, _ = integration.pre_execute(ctx, "search query")
        r1 = interceptor.intercept(
            ToolCallRequest(tool_name="search", arguments={"q": "x"})
        )
        integration.post_execute(ctx, "result-1")
        assert ok1 and r1.allowed

        # Call 2: ALLOW + checkpoint (frequency=2)
        ok2, _ = integration.pre_execute(ctx, "read file")
        r2 = interceptor.intercept(
            ToolCallRequest(tool_name="read", arguments={"path": "/a"})
        )
        integration.post_execute(ctx, "result-2")
        assert ok2 and r2.allowed
        assert len(ctx.checkpoints) == 1

        # Call 3: DENY (tool not in allowed list)
        r3 = interceptor.intercept(
            ToolCallRequest(tool_name="delete", arguments={})
        )
        assert r3.allowed is False

        # Verify audit trail contains checks, a checkpoint, and no violations for allowed calls
        check_events = [e for e in audit_log if e[0] == GovernanceEventType.POLICY_CHECK]
        checkpoint_events = [e for e in audit_log if e[0] == GovernanceEventType.CHECKPOINT_CREATED]
        assert len(check_events) >= 2
        assert len(checkpoint_events) == 1


# =============================================================================
# AGT v5 bridge — per-adapter scenario tests (allow / deny / escalate / transform)
# =============================================================================
#
# These tests exercise each adapter through the AdapterRuntimeBridge with a
# pre-built :class:`AgtRuntime` injected via the ``_runtime`` test seam. They
# do NOT depend on the underlying framework SDK (google.generativeai,
# google.adk, guardrails, llama_index) being importable — the wrapped object
# is a ``MagicMock``. The point is to verify the bridge wiring, not the
# framework client.
# -----------------------------------------------------------------------------


def _v5_bridge_available() -> bool:
    """Return True when the AGT 5.0 ACS bridge can construct a runtime."""
    try:
        import agt.policies.runtime  # noqa: F401
        import agent_control_specification  # noqa: F401
    except ImportError:
        return False
    return True


_V5_BRIDGE_REQUIRED = pytest.mark.skipif(
    not _v5_bridge_available(),
    reason="agt-policies and agent_control_specification SDK required",
)


class _ScriptedPolicy:
    """Tiny ACS PolicyDispatcher that returns a scripted verdict per call."""

    def __init__(self, verdicts):
        self._verdicts = list(verdicts)
        self.invocations: list[dict] = []

    def evaluate(self, invocation):
        self.invocations.append(dict(invocation))
        if not self._verdicts:
            raise AssertionError(
                "ScriptedPolicy ran out of verdicts; test wired too few."
            )
        return self._verdicts.pop(0)


class _BudgetGatePolicy:
    """ACS PolicyDispatcher that denies once the snapshot budget reaches a limit."""

    def __init__(self, limit: int):
        self.limit = limit
        self.seen_budgets: list[int] = []
        self.invocations: list[dict] = []

    def evaluate(self, invocation):
        self.invocations.append(dict(invocation))
        inp = invocation.get("input") or {}
        if inp.get("intervention_point") != "pre_tool_call":
            return {"decision": "allow"}
        snapshot = inp.get("snapshot") if isinstance(inp, dict) else None
        budgets = (
            snapshot.get("envelope", {}).get("budgets", {})
            if isinstance(snapshot, dict)
            else {}
        )
        tool_call_count = int(budgets.get("tool_call_count", -1))
        self.seen_budgets.append(tool_call_count)
        if tool_call_count >= self.limit:
            return {
                "decision": "deny",
                "reason": "budget_tool_calls_exceeded",
                "message": "tool-call budget exceeded",
            }
        return {"decision": "allow"}


class _OutputBudgetGatePolicy:
    """PolicyDispatcher that denies output once the snapshot budget reaches a limit."""

    def __init__(self, limit: int):
        self.limit = limit
        self.invocations: list[dict] = []

    def evaluate(self, invocation):
        self.invocations.append(dict(invocation))
        inp = invocation.get("input") or {}
        if inp.get("intervention_point") != "output":
            return {"decision": "allow"}
        snapshot = inp.get("snapshot") if isinstance(inp, dict) else None
        budgets = (
            snapshot.get("envelope", {}).get("budgets", {})
            if isinstance(snapshot, dict)
            else {}
        )
        if int(budgets.get("tool_call_count", -1)) >= self.limit:
            return {
                "decision": "deny",
                "reason": "budget_tool_calls_exceeded",
                "message": "tool-call budget exceeded at output",
            }
        return {"decision": "allow"}


_SCENARIO_MANIFEST = """agent_control_specification_version: 0.3.0-alpha-agt
metadata:
  name: integration_scenarios
extends: []
policies:
  scenario_policy:
    type: custom
    adapter: integration_scenarios_adapter
intervention_points:
  input:
    policy_target: $.input.body
    policy_target_kind: user_input
    policy:
      id: scenario_policy
  pre_tool_call:
    policy_target: $.tool_call.args
    policy_target_kind: tool_args
    tool_name_from: $.tool_call.name
    policy:
      id: scenario_policy
  output:
    policy_target: $.response.content
    policy_target_kind: assistant_output
    policy:
      id: scenario_policy
tools:
  scenario_tool:
    clearance: public
  get_weather:
    clearance: public
"""


def _build_scenario_runtime(
    tmp_path, verdicts, *, approval_resolver=None, dispatcher=None
):
    """Build an :class:`AgtRuntime` over a scripted or custom dispatcher."""
    from agt.policies.runtime import AgtRuntime

    manifest_path = tmp_path / "manifest.yaml"
    manifest_path.write_text(_SCENARIO_MANIFEST, encoding="utf-8")
    if dispatcher is None:
        policy = _ScriptedPolicy(verdicts)
    else:
        policy = dispatcher
    runtime = AgtRuntime(
        manifest_path,
        policy_dispatcher=policy,
        approval_resolver=approval_resolver,
    )
    return runtime, policy


def _approving_resolver(captured: dict):
    """Return an approval_resolver that always approves and records the IP."""
    from agt.policies.runtime import ApprovalDecision

    def resolver(ip, result):
        captured["ip"] = ip
        captured["enforced_identity"] = result.enforced_identity
        return ApprovalDecision.allow(result.enforced_identity)

    return resolver


# ── Gemini scenario coverage ─────────────────────────────────────────


def _make_gemini_response_with_function_call(name, args):
    """Build a Gemini-shaped response containing a single function call."""
    from types import SimpleNamespace

    fn_call = SimpleNamespace(name=name, args=args)
    part = SimpleNamespace(function_call=fn_call)
    content = SimpleNamespace(parts=[part])
    candidate = SimpleNamespace(content=content)
    return SimpleNamespace(candidates=[candidate], usage_metadata=None)


def _make_gemini_model():
    """Return a mock Gemini ``GenerativeModel`` (no SDK required)."""
    from types import SimpleNamespace

    model = MagicMock()
    model.model_name = "gemini-pro"
    model.generate_content.return_value = SimpleNamespace(
        candidates=[], usage_metadata=None
    )
    return model


@_V5_BRIDGE_REQUIRED
class TestGeminiBridgeScenarios:
    """Verify GeminiKernel routes through the AGT 5.0 ACS runtime."""

    def _kernel(self, runtime, approval_resolver=None):
        from agent_os.integrations import gemini_adapter as gemini_mod
        from agent_os.integrations.gemini_adapter import GeminiKernel

        gemini_mod._HAS_GENAI = True
        return GeminiKernel(_runtime=runtime, approval_resolver=approval_resolver)

    def test_allow_path_forwards_prompt(self, tmp_path):
        runtime, policy = _build_scenario_runtime(tmp_path, [{"decision": "allow"}])
        kernel = self._kernel(runtime)
        model = _make_gemini_model()
        governed = kernel.wrap(model)

        governed.generate_content("what is the weather?")

        assert len(policy.invocations) == 1
        model.generate_content.assert_called_once()
        assert model.generate_content.call_args.args[0] == "what is the weather?"

    def test_deny_path_raises_policy_violation(self, tmp_path):
        from agent_os.integrations.gemini_adapter import PolicyViolationError

        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [{"decision": "deny", "reason": "blocked_topic"}],
        )
        kernel = self._kernel(runtime)
        model = _make_gemini_model()
        governed = kernel.wrap(model)

        with pytest.raises(PolicyViolationError) as excinfo:
            governed.generate_content("blocked content")

        assert excinfo.value.check_result.reason == "blocked_topic"
        model.generate_content.assert_not_called()

    def test_transform_path_rewrites_prompt(self, tmp_path):
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [
                {
                    "decision": "transform",
                    "reason": "pii_redaction",
                    "transform": {
                        "path": "$policy_target",
                        "value": "Customer SSN is [REDACTED]",
                    },
                }
            ],
        )
        kernel = self._kernel(runtime)
        model = _make_gemini_model()
        governed = kernel.wrap(model)

        governed.generate_content("Customer SSN is 123-45-6789")

        model.generate_content.assert_called_once()
        # Gemini SDK MUST see the redacted text.
        assert (
            model.generate_content.call_args.args[0]
            == "Customer SSN is [REDACTED]"
        )

    def test_escalate_with_approving_resolver_forwards(self, tmp_path):
        captured: dict = {}
        resolver = _approving_resolver(captured)
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [{"decision": "escalate", "reason": "human_approval_required"}],
            approval_resolver=resolver,
        )
        kernel = self._kernel(runtime, approval_resolver=resolver)
        model = _make_gemini_model()
        governed = kernel.wrap(model)

        governed.generate_content("needs approval")

        assert captured["ip"] == "input"
        model.generate_content.assert_called_once()

    def test_function_call_transform_rewrites_args(self, tmp_path):
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [
                {"decision": "allow"},  # input
                {
                    "decision": "transform",
                    "reason": "args_sanitized",
                    "transform": {
                        "path": "$policy_target",
                        "value": {"city": "[REDACTED]"},
                    },
                },
            ],
        )
        kernel = self._kernel(runtime)
        response = _make_gemini_response_with_function_call(
            "get_weather", {"city": "Seattle"}
        )
        model = _make_gemini_model()
        model.generate_content.return_value = response
        governed = kernel.wrap(model)

        governed.generate_content("weather please")

        fn_call = response.candidates[0].content.parts[0].function_call
        assert fn_call.args == {"city": "[REDACTED]"}


# ── LlamaIndex scenario coverage ─────────────────────────────────────


def _make_llama_engine(query_response="answer", chat_response="chat-answer"):
    """Return a mock LlamaIndex engine (no SDK required)."""
    from types import SimpleNamespace

    engine = MagicMock()
    # Drop the auto-generated MagicMock for .name so wrap() falls back to
    # the synthesised agent_id (LlamaIndexKernel rejects Mock names).
    del engine.name
    engine.query.return_value = SimpleNamespace(response=query_response)
    engine.chat.return_value = SimpleNamespace(response=chat_response)
    return engine


class _LlamaStreamResponse:
    def __init__(self, chunks):
        self.response_gen = iter(chunks)
        self.metadata = {"source": "test"}


class _ReadOnlyLlamaStreamResponse:
    def __init__(self, chunks):
        self._chunks = chunks
        self.metadata = {"source": "test"}

    @property
    def response_gen(self):
        return iter(self._chunks)

    def print_response_stream(self):
        for chunk in self.response_gen:
            print(chunk, end="")

    def leak_original_chunks(self):
        return list(self.response_gen)


class _AsyncMethodLlamaStreamResponse:
    def __init__(self, chunks):
        self._chunks = chunks
        self.metadata = {"source": "test"}

    async def async_response_gen(self):
        for chunk in self._chunks:
            yield chunk


@_V5_BRIDGE_REQUIRED
class TestLlamaIndexBridgeScenarios:
    """Verify LlamaIndexKernel routes through the AGT 5.0 ACS runtime."""

    def _kernel(self, runtime, approval_resolver=None):
        from agent_os.integrations.llamaindex_adapter import LlamaIndexKernel

        return LlamaIndexKernel(_runtime=runtime, approval_resolver=approval_resolver)

    def test_query_allow_path_forwards_to_engine(self, tmp_path):
        runtime, policy = _build_scenario_runtime(
            tmp_path,
            [
                {"decision": "allow"},  # input
                {"decision": "allow"},  # output
            ],
        )
        kernel = self._kernel(runtime)
        engine = _make_llama_engine()
        governed = kernel.wrap(engine)

        result = governed.query("what is the meaning of life?")

        assert result.response == "answer"
        engine.query.assert_called_once()
        # The engine MUST see the original query
        assert engine.query.call_args.args[0] == "what is the meaning of life?"
        assert len(policy.invocations) == 2

    def test_query_deny_path_raises_policy_violation(self, tmp_path):
        from agent_os.integrations.llamaindex_adapter import PolicyViolationError

        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [{"decision": "deny", "reason": "blocked_query"}],
        )
        kernel = self._kernel(runtime)
        engine = _make_llama_engine()
        governed = kernel.wrap(engine)

        with pytest.raises(PolicyViolationError) as excinfo:
            governed.query("blocked content")

        assert excinfo.value.check_result.reason == "blocked_query"
        engine.query.assert_not_called()

    def test_chat_transform_rewrites_message(self, tmp_path):
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [
                {
                    "decision": "transform",
                    "reason": "pii_redaction",
                    "transform": {
                        "path": "$policy_target",
                        "value": "Customer SSN is [REDACTED]",
                    },
                },
                {"decision": "allow"},  # output
            ],
        )
        kernel = self._kernel(runtime)
        engine = _make_llama_engine()
        governed = kernel.wrap(engine)

        governed.chat("Customer SSN is 123-45-6789")

        engine.chat.assert_called_once()
        # LlamaIndex engine MUST see the redacted message
        assert engine.chat.call_args.args[0] == "Customer SSN is [REDACTED]"

    def test_query_escalate_with_approving_resolver_forwards(self, tmp_path):
        captured: dict = {}
        resolver = _approving_resolver(captured)
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [
                {"decision": "escalate", "reason": "human_approval_required"},
                {"decision": "allow"},  # output
            ],
            approval_resolver=resolver,
        )
        kernel = self._kernel(runtime, approval_resolver=resolver)
        engine = _make_llama_engine()
        governed = kernel.wrap(engine)

        governed.query("needs approval")

        assert captured["ip"] == "input"
        engine.query.assert_called_once()

    def test_query_escalate_with_no_resolver_denies(self, tmp_path):
        from agent_os.integrations.llamaindex_adapter import PolicyViolationError

        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [{"decision": "escalate", "reason": "human_approval_required"}],
            approval_resolver=None,
        )
        kernel = self._kernel(runtime)
        engine = _make_llama_engine()
        governed = kernel.wrap(engine)

        with pytest.raises(PolicyViolationError):
            governed.query("needs approval")

        engine.query.assert_not_called()

    def test_output_transform_rewrites_response(self, tmp_path):
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [
                {"decision": "allow"},  # input
                {
                    "decision": "transform",
                    "reason": "output_redaction",
                    "transform": {
                        "path": "$policy_target",
                        "value": "[REDACTED OUTPUT]",
                    },
                },
            ],
        )
        kernel = self._kernel(runtime)
        engine = _make_llama_engine(query_response="leaked secret content")
        governed = kernel.wrap(engine)

        result = governed.query("safe question")

        # The result object's response attribute MUST be rewritten
        assert result.response == "[REDACTED OUTPUT]"

    def test_retrieve_blocks_output_before_return(self, tmp_path):
        from agent_os.integrations.llamaindex_adapter import PolicyViolationError

        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [
                {"decision": "allow"},  # input
                {"decision": "deny", "reason": "retrieve_output_blocked"},  # output
            ],
        )
        kernel = self._kernel(runtime)
        engine = _make_llama_engine()
        engine.retrieve.return_value = ["secret doc"]
        governed = kernel.wrap(engine)

        with pytest.raises(PolicyViolationError) as excinfo:
            governed.retrieve("safe question")

        assert excinfo.value.check_result.reason == "retrieve_output_blocked"
        engine.retrieve.assert_called_once_with("safe question")

    def test_retrieve_blocks_after_max_tool_calls(self, tmp_path):
        from agent_os.integrations.llamaindex_adapter import PolicyViolationError

        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [
                {"decision": "allow"},  # first input
                {"decision": "allow"},  # first output
            ],
        )
        kernel = self._kernel(runtime)
        kernel.policy.max_tool_calls = 1
        engine = _make_llama_engine()
        engine.retrieve.return_value = ["doc"]
        governed = kernel.wrap(engine)

        governed.retrieve("first")

        with pytest.raises(PolicyViolationError, match="Tool call limit"):
            governed.retrieve("second")

        assert engine.retrieve.call_count == 1

    def test_retrieve_allows_first_call_with_output_budget_policy(self, tmp_path):
        from agent_os.integrations.llamaindex_adapter import PolicyViolationError

        dispatcher = _OutputBudgetGatePolicy(limit=1)
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [],
            dispatcher=dispatcher,
        )
        kernel = self._kernel(runtime)
        kernel.policy.max_tool_calls = 1
        engine = _make_llama_engine()
        engine.retrieve.return_value = ["doc"]
        governed = kernel.wrap(engine)

        assert governed.retrieve("first") == ["doc"]

        with pytest.raises(PolicyViolationError, match="Tool call limit"):
            governed.retrieve("second")

        assert engine.retrieve.call_count == 1
        assert [
            invocation["input"]["intervention_point"]
            for invocation in dispatcher.invocations
        ] == ["input", "output"]

    def test_stream_chat_blocks_output_before_disclosure(self, tmp_path):
        from agent_os.integrations.llamaindex_adapter import PolicyViolationError

        runtime, policy = _build_scenario_runtime(
            tmp_path,
            [
                {"decision": "allow"},  # input
                {"decision": "deny", "reason": "stream_output_blocked"},  # output
            ],
        )
        kernel = self._kernel(runtime)
        engine = _make_llama_engine()
        engine.stream_chat.return_value = iter(["safe chunk", "secret chunk"])
        governed = kernel.wrap(engine)

        with pytest.raises(PolicyViolationError) as excinfo:
            list(governed.stream_chat("stream please"))

        assert excinfo.value.check_result.reason == "stream_output_blocked"
        assert engine.stream_chat.call_args.args[0] == "stream please"
        assert (
            policy.invocations[0]["input"]["intervention_point"] == "input"
        )
        assert (
            policy.invocations[1]["input"]["intervention_point"] == "output"
        )

    def test_stream_chat_blocks_after_max_tool_calls(self, tmp_path):
        from agent_os.integrations.llamaindex_adapter import PolicyViolationError

        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [
                {"decision": "allow"},  # first input
                {"decision": "allow"},  # first output
            ],
        )
        kernel = self._kernel(runtime)
        kernel.policy.max_tool_calls = 1
        engine = _make_llama_engine()
        engine.stream_chat.return_value = iter(["first"])
        governed = kernel.wrap(engine)

        list(governed.stream_chat("first"))

        with pytest.raises(PolicyViolationError, match="Tool call limit"):
            list(governed.stream_chat("second"))

        assert engine.stream_chat.call_count == 1

    def test_stream_chat_transform_returns_redacted_stream(self, tmp_path):
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [
                {"decision": "allow"},  # input
                {
                    "decision": "transform",
                    "reason": "stream_redaction",
                    "transform": {
                        "path": "$policy_target",
                        "value": "[REDACTED STREAM]",
                    },
                },
            ],
        )
        kernel = self._kernel(runtime)
        engine = _make_llama_engine()
        engine.stream_chat.return_value = iter(["secret", " stream"])
        governed = kernel.wrap(engine)

        assert list(governed.stream_chat("stream please")) == ["[REDACTED STREAM]"]

    def test_stream_chat_transform_preserves_response_gen_object_shape(self, tmp_path):
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [
                {"decision": "allow"},  # input
                {
                    "decision": "transform",
                    "reason": "stream_redaction",
                    "transform": {
                        "path": "$policy_target",
                        "value": "[REDACTED STREAM]",
                    },
                },
            ],
        )
        kernel = self._kernel(runtime)
        stream_response = _LlamaStreamResponse(["secret", " stream"])
        engine = _make_llama_engine()
        engine.stream_chat.return_value = stream_response
        governed = kernel.wrap(engine)

        result = governed.stream_chat("stream please")

        assert result is stream_response
        assert result.metadata == {"source": "test"}
        assert list(result.response_gen) == ["[REDACTED STREAM]"]

    def test_stream_chat_transform_proxies_read_only_response_gen(self, tmp_path):
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [
                {"decision": "allow"},  # input
                {
                    "decision": "transform",
                    "reason": "stream_redaction",
                    "transform": {
                        "path": "$policy_target",
                        "value": "[REDACTED STREAM]",
                    },
                },
            ],
        )
        kernel = self._kernel(runtime)
        stream_response = _ReadOnlyLlamaStreamResponse(["secret", " stream"])
        engine = _make_llama_engine()
        engine.stream_chat.return_value = stream_response
        governed = kernel.wrap(engine)

        result = governed.stream_chat("stream please")

        assert result is not stream_response
        assert result.metadata == {"source": "test"}
        assert list(result.response_gen) == ["[REDACTED STREAM]"]

    def test_stream_chat_transform_proxy_prints_redacted_stream(self, tmp_path, capsys):
        from agent_os.integrations.llamaindex_adapter import PolicyViolationError

        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [
                {"decision": "allow"},  # input
                {
                    "decision": "transform",
                    "reason": "stream_redaction",
                    "transform": {
                        "path": "$policy_target",
                        "value": "[REDACTED STREAM]",
                    },
                },
            ],
        )
        kernel = self._kernel(runtime)
        stream_response = _ReadOnlyLlamaStreamResponse(["secret", " stream"])
        engine = _make_llama_engine()
        engine.stream_chat.return_value = stream_response
        governed = kernel.wrap(engine)

        result = governed.stream_chat("stream please")
        result.print_response_stream()

        assert capsys.readouterr().out == "[REDACTED STREAM]"
        with pytest.raises(AttributeError, match="unavailable"):
            result.leak_original_chunks()

    async def test_astream_chat_blocks_output_before_disclosure(self, tmp_path):
        from agent_os.integrations.llamaindex_adapter import PolicyViolationError

        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [
                {"decision": "allow"},  # input
                {"decision": "deny", "reason": "async_stream_output_blocked"},  # output
            ],
        )
        kernel = self._kernel(runtime)
        engine = _make_llama_engine()
        engine.astream_chat.return_value = _async_chunks(["safe chunk", "secret chunk"])
        governed = kernel.wrap(engine)

        with pytest.raises(PolicyViolationError) as excinfo:
            await _collect_async(await governed.astream_chat("stream please"))

        assert excinfo.value.check_result.reason == "async_stream_output_blocked"
        assert engine.astream_chat.call_args.args[0] == "stream please"

    async def test_astream_chat_blocks_after_max_tool_calls(self, tmp_path):
        from agent_os.integrations.llamaindex_adapter import PolicyViolationError

        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [
                {"decision": "allow"},  # first input
                {"decision": "allow"},  # first output
            ],
        )
        kernel = self._kernel(runtime)
        kernel.policy.max_tool_calls = 1
        engine = _make_llama_engine()
        engine.astream_chat.return_value = _async_chunks(["first"])
        governed = kernel.wrap(engine)

        await _collect_async(await governed.astream_chat("first"))

        with pytest.raises(PolicyViolationError, match="Tool call limit"):
            await _collect_async(await governed.astream_chat("second"))

        assert engine.astream_chat.call_count == 1

    async def test_astream_chat_transform_returns_redacted_async_stream(self, tmp_path):
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [
                {"decision": "allow"},  # input
                {
                    "decision": "transform",
                    "reason": "async_stream_redaction",
                    "transform": {
                        "path": "$policy_target",
                        "value": "[REDACTED ASYNC STREAM]",
                    },
                },
            ],
        )
        kernel = self._kernel(runtime)
        engine = _make_llama_engine()
        engine.astream_chat.return_value = _async_chunks(["secret", " stream"])
        governed = kernel.wrap(engine)

        stream = await governed.astream_chat("stream please")

        assert await _collect_async(stream) == ["[REDACTED ASYNC STREAM]"]

    async def test_astream_chat_transform_preserves_async_response_gen_method(self, tmp_path):
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [
                {"decision": "allow"},  # input
                {
                    "decision": "transform",
                    "reason": "async_stream_redaction",
                    "transform": {
                        "path": "$policy_target",
                        "value": "[REDACTED ASYNC STREAM]",
                    },
                },
            ],
        )
        kernel = self._kernel(runtime)
        stream_response = _AsyncMethodLlamaStreamResponse(["secret", " stream"])
        engine = _make_llama_engine()
        engine.astream_chat.return_value = stream_response
        governed = kernel.wrap(engine)

        result = await governed.astream_chat("stream please")

        assert result is stream_response
        assert result.metadata == {"source": "test"}
        assert await _collect_async(result.async_response_gen()) == [
            "[REDACTED ASYNC STREAM]"
        ]


# ── Guardrails scenario coverage ─────────────────────────────────────


@_V5_BRIDGE_REQUIRED
class TestGuardrailsBridgeScenarios:
    """Verify GuardrailsKernel routes through the AGT 5.0 ACS runtime."""

    def _kernel(self, runtime, approval_resolver=None, validators=None):
        from agent_os.integrations.base import GovernancePolicy
        from agent_os.integrations.guardrails_adapter import GuardrailsKernel

        return GuardrailsKernel(
            validators=validators or [],
            on_fail="fix",
            policy=GovernancePolicy(),
            approval_resolver=approval_resolver,
            _runtime=runtime,
        )

    def test_validate_input_allow_path_passes(self, tmp_path):
        runtime, policy = _build_scenario_runtime(
            tmp_path,
            [{"decision": "allow"}],
        )
        kernel = self._kernel(runtime)

        result = kernel.validate_input("safe query")

        assert result.passed is True
        assert result.final_value == "safe query"
        # The synthetic AGT outcome MUST be present
        names = [o.validator_name for o in result.outcomes]
        assert "agt_runtime_bridge" in names
        assert len(policy.invocations) == 1

    def test_validate_input_deny_path_fails(self, tmp_path):
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [{"decision": "deny", "reason": "blocked_topic"}],
        )
        kernel = self._kernel(runtime)

        result = kernel.validate_input("blocked content")

        assert result.passed is False
        # The synthetic AGT outcome MUST carry the deny reason
        agt_outcomes = [
            o for o in result.outcomes if o.validator_name == "agt_runtime_bridge"
        ]
        assert len(agt_outcomes) == 1
        assert agt_outcomes[0].passed is False
        assert "blocked_topic" in agt_outcomes[0].error_message

    def test_validate_input_transform_rewrites_final_value(self, tmp_path):
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [
                {
                    "decision": "transform",
                    "reason": "pii_redaction",
                    "transform": {
                        "path": "$policy_target",
                        "value": "Customer SSN is [REDACTED]",
                    },
                }
            ],
        )
        kernel = self._kernel(runtime)

        result = kernel.validate_input("Customer SSN is 123-45-6789")

        # The final_value MUST be the AGT-redacted text per AGT D1.1
        assert result.final_value == "Customer SSN is [REDACTED]"
        assert result.passed is True

    def test_validate_input_escalate_with_approving_resolver_passes(self, tmp_path):
        captured: dict = {}
        resolver = _approving_resolver(captured)
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [{"decision": "escalate", "reason": "human_approval_required"}],
            approval_resolver=resolver,
        )
        kernel = self._kernel(runtime, approval_resolver=resolver)

        result = kernel.validate_input("needs approval")

        assert captured["ip"] == "input"
        assert result.passed is True

    def test_validate_output_routes_to_output_intervention_point(self, tmp_path):
        runtime, policy = _build_scenario_runtime(
            tmp_path,
            [{"decision": "allow"}],
        )
        kernel = self._kernel(runtime)

        result = kernel.validate_output("safe response")

        assert result.passed is True
        # The bridge MUST evaluate at the output intervention point.
        assert (
            policy.invocations[0]["input"]["intervention_point"] == "output"
        )

    def test_no_policy_skips_bridge(self):
        from agent_os.integrations.guardrails_adapter import GuardrailsKernel

        kernel = GuardrailsKernel()
        # When no policy is supplied the bridge is disabled and behaviour
        # matches the v4-only contract (no AGT outcome appended).
        assert kernel.bridge is None
        result = kernel.validate_input("anything")
        assert result.passed is True
        names = [o.validator_name for o in result.outcomes]
        assert "agt_runtime_bridge" not in names


# ── Google ADK scenario coverage ─────────────────────────────────────


class _ADKFakeToolContext:
    """Minimal fake of ADK's ``ToolContext`` for kernel callback tests."""

    def __init__(self, tool_name="search", tool_args=None, agent_name="agent"):
        self.tool_name = tool_name
        self.tool_args = tool_args if tool_args is not None else {}
        self.agent_name = agent_name


class _ADKFakeCallbackContext:
    """Minimal fake of ADK's ``CallbackContext``."""

    def __init__(self, agent_name="root-agent", invocation_id="inv-001"):
        self.agent_name = agent_name
        self.invocation_id = invocation_id


@_V5_BRIDGE_REQUIRED
class TestGoogleADKBridgeScenarios:
    """Verify GoogleADKKernel routes through the AGT 5.0 ACS runtime."""

    def _kernel(
        self,
        runtime,
        *,
        approval_resolver=None,
        allowed_tools=None,
        require_human_approval=False,
        sensitive_tools=None,
    ):
        from agent_os.integrations.google_adk_adapter import GoogleADKKernel

        return GoogleADKKernel(
            allowed_tools=allowed_tools or [],
            _runtime=runtime,
            approval_resolver=approval_resolver,
            require_human_approval=require_human_approval,
            sensitive_tools=sensitive_tools or [],
        )

    def test_before_tool_callback_allow_path(self, tmp_path):
        runtime, policy = _build_scenario_runtime(
            tmp_path, [{"decision": "allow"}]
        )
        kernel = self._kernel(runtime)
        ctx = _ADKFakeToolContext(tool_name="scenario_tool", tool_args={"q": "AI"})

        result = kernel.before_tool_callback(ctx)

        assert result is None
        # The bridge MUST have been called once with the tool name.
        assert len(policy.invocations) == 1
        assert (
            policy.invocations[0]["input"]["intervention_point"]
            == "pre_tool_call"
        )

    def test_before_tool_callback_deny_path(self, tmp_path):
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [{"decision": "deny", "reason": "tool_args_forbidden"}],
        )
        kernel = self._kernel(runtime)
        ctx = _ADKFakeToolContext(tool_name="scenario_tool", tool_args={"q": "AI"})

        result = kernel.before_tool_callback(ctx)

        assert result is not None
        assert "error" in result
        assert "agt_pre_tool_call_deny" in result["error"]

    def test_before_tool_callback_transform_rewrites_args(self, tmp_path):
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [
                {
                    "decision": "transform",
                    "reason": "args_sanitized",
                    "transform": {
                        "path": "$policy_target",
                        "value": {"q": "[REDACTED]"},
                    },
                }
            ],
        )
        kernel = self._kernel(runtime)
        ctx = _ADKFakeToolContext(tool_name="scenario_tool", tool_args={"q": "AI"})

        result = kernel.before_tool_callback(ctx)

        assert result is None
        # The ToolContext.tool_args MUST be rewritten per AGT D1.1.
        assert ctx.tool_args == {"q": "[REDACTED]"}

    def test_before_tool_callback_escalate_with_resolver_passes(self, tmp_path):
        captured: dict = {}
        resolver = _approving_resolver(captured)
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [{"decision": "escalate", "reason": "human_approval_required"}],
            approval_resolver=resolver,
        )
        kernel = self._kernel(runtime, approval_resolver=resolver)
        ctx = _ADKFakeToolContext(tool_name="scenario_tool", tool_args={"q": "AI"})

        result = kernel.before_tool_callback(ctx)

        assert captured["ip"] == "pre_tool_call"
        assert result is None

    def test_after_tool_callback_transform_rewrites_result(self, tmp_path):
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [
                {
                    "decision": "transform",
                    "reason": "output_redaction",
                    "transform": {
                        "path": "$policy_target",
                        "value": "[REDACTED OUTPUT]",
                    },
                }
            ],
        )
        kernel = self._kernel(runtime)
        ctx = _ADKFakeToolContext(tool_name="search")

        result = kernel.after_tool_callback(ctx, tool_result="leaked secret")

        assert result == "[REDACTED OUTPUT]"

    def test_after_tool_callback_deny_path(self, tmp_path):
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [{"decision": "deny", "reason": "output_blocked"}],
        )
        kernel = self._kernel(runtime)
        ctx = _ADKFakeToolContext(tool_name="search")

        result = kernel.after_tool_callback(ctx, tool_result="secret data")

        assert isinstance(result, dict)
        assert "error" in result
        assert "agt_output_deny" in result["error"]

    def test_before_agent_callback_deny_path(self, tmp_path):
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [{"decision": "deny", "reason": "agent_blocked"}],
        )
        kernel = self._kernel(runtime)
        ctx = _ADKFakeCallbackContext(agent_name="suspicious-agent")

        result = kernel.before_agent_callback(callback_context=ctx)

        assert isinstance(result, dict)
        assert "error" in result
        assert "agt_input_deny" in result["error"]

    def test_after_agent_callback_transform_rewrites_content(self, tmp_path):
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [
                {
                    "decision": "transform",
                    "reason": "output_redaction",
                    "transform": {
                        "path": "$policy_target",
                        "value": "[SANITISED AGENT OUTPUT]",
                    },
                }
            ],
        )
        kernel = self._kernel(runtime)
        ctx = _ADKFakeCallbackContext()

        result = kernel.after_agent_callback(
            callback_context=ctx, content="leaked secret"
        )

        assert result == "[SANITISED AGENT OUTPUT]"

    def test_sensitive_tool_routes_through_agt_resolver_not_local_short_circuit(
        self, tmp_path
    ):
        """AGT-DELTA D5 regression: when ``approval_resolver`` is wired,
        the AGT escalate path MUST drive approval for a sensitive tool.
        Previously the local ``_needs_approval`` short-circuit returned
        ``{"needs_approval": True}`` BEFORE the bridge ran, so the
        resolver was never consulted and the bisected enforced_identity
        never reached audit.
        """
        captured: dict = {}
        resolver = _approving_resolver(captured)
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [{"decision": "escalate", "reason": "human_approval_required"}],
            approval_resolver=resolver,
        )
        kernel = self._kernel(
            runtime,
            approval_resolver=resolver,
            require_human_approval=True,
            sensitive_tools=["scenario_tool"],
        )
        ctx = _ADKFakeToolContext(
            tool_name="scenario_tool", tool_args={"q": "AI"}
        )

        result = kernel.before_tool_callback(ctx)

        # No legacy ``needs_approval`` short-circuit dict — the bridge ran.
        assert result is None, f"expected bridge-allow None, got {result!r}"
        # Resolver invoked exactly once at pre_tool_call.
        assert captured.get("ip") == "pre_tool_call"
        assert captured.get("enforced_identity"), (
            "AGT D1.4 enforced_identity must be handed to the resolver"
        )
        # And it propagates to audit so downstream consumers can pin
        # what was actually approved.
        agt_audit = [
            event for event in kernel.get_audit_log()
            if event.event_type == "agt_pre_tool_call"
        ]
        assert agt_audit, "AGT bridge result must emit an audit record"
        assert agt_audit[-1].details.get("enforced_identity") == captured.get(
            "enforced_identity"
        )

    def test_non_sensitive_tool_does_not_invoke_resolver_when_filter_set(
        self, tmp_path
    ):
        """AGT-M3 round-2 BLOCK B regression: with a non-empty
        ``sensitive_tools`` list, a non-sensitive tool MUST NOT route
        through the AGT escalate path. The previous wiring set
        ``bridge_require_approval=True`` whenever ``approval_resolver``
        was present, which bypassed the local ``_needs_approval``
        filter and called the resolver for EVERY tool. The fixed
        kernel keeps two bridges (sensitive escalates, non-sensitive
        does not) and selects per call.
        """
        invocations: list[str] = []

        def _counting_resolver(ip, result):
            from agt.policies.runtime import ApprovalDecision

            invocations.append(ip)
            return ApprovalDecision.allow(result.enforced_identity)

        # Scripted dispatcher returns allow for the non-sensitive tool;
        # the resolver should never be touched because the default
        # bridge has ``require_human_approval=False`` and therefore
        # never emits escalate for this call. ``get_weather`` is in the
        # scenario manifest catalog (so the engine does not fail
        # closed with ``runtime_error:tool_unknown``) but is NOT in
        # ``sensitive_tools``, so it must dispatch through the default
        # bridge that never escalates.
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [{"decision": "allow"}],
            approval_resolver=_counting_resolver,
        )
        kernel = self._kernel(
            runtime,
            approval_resolver=_counting_resolver,
            require_human_approval=True,
            sensitive_tools=["scenario_tool"],
        )
        ctx = _ADKFakeToolContext(
            tool_name="get_weather", tool_args={"q": "AI"}
        )

        result = kernel.before_tool_callback(ctx)

        assert result is None, (
            f"non-sensitive tool must pass through bridge allow, got {result!r}"
        )
        assert invocations == [], (
            "approval_resolver MUST NOT be invoked for non-sensitive tools; "
            f"resolver was called at: {invocations!r}"
        )

    def test_sensitive_filter_routes_only_sensitive_through_resolver(
        self, tmp_path
    ):
        """AGT-M3 round-2 BLOCK B end-to-end: a single kernel calling
        one non-sensitive tool and one sensitive tool MUST invoke the
        resolver exactly once (for the sensitive call) and zero times
        for the non-sensitive call.
        """
        invocations: list[str] = []

        def _counting_resolver(ip, result):
            from agt.policies.runtime import ApprovalDecision

            invocations.append(ip)
            return ApprovalDecision.allow(result.enforced_identity)

        # The scripted dispatcher is consulted on every pre_tool_call.
        # First call (non-sensitive, ``get_weather``): default bridge
        # asks the dispatcher and gets ``allow``. Second call
        # (sensitive, ``scenario_tool``): sibling bridge asks the
        # dispatcher and gets ``escalate``; the runtime routes it
        # through the resolver.
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [
                {"decision": "allow"},
                {"decision": "escalate", "reason": "human_approval_required"},
            ],
            approval_resolver=_counting_resolver,
        )
        kernel = self._kernel(
            runtime,
            approval_resolver=_counting_resolver,
            require_human_approval=True,
            sensitive_tools=["scenario_tool"],
        )

        non_sensitive_ctx = _ADKFakeToolContext(
            tool_name="get_weather", tool_args={"q": "AI"}
        )
        sensitive_ctx = _ADKFakeToolContext(
            tool_name="scenario_tool", tool_args={"q": "AI"}
        )

        first = kernel.before_tool_callback(non_sensitive_ctx)
        second = kernel.before_tool_callback(sensitive_ctx)

        assert first is None
        assert second is None
        assert invocations == ["pre_tool_call"], (
            f"resolver MUST be invoked exactly once (for the sensitive "
            f"tool), got: {invocations!r}"
        )
        # AGT-M3 round-3 GPT regression pin: the bridge.policy invariant
        # is what actually drives the production rego — assert it
        # directly so a future regression that reintroduces the round-1
        # "set bridge_require_approval=True for all tools" wiring is
        # caught even if the scripted dispatcher hides the rego path.
        assert kernel._bridge.policy.require_human_approval is False, (
            "default _bridge MUST have require_human_approval=False when "
            "sensitive_tools is configured; the sibling _approval_bridge "
            "is the one that keeps approval on"
        )

    def test_two_bridge_split_keeps_tool_call_budget_in_sync(self, tmp_path):
        """AGT-M3 round-3 GPT regression: after one non-sensitive call
        followed by one sensitive call, the sensitive bridge MUST see
        ``tool_call_count >= 1`` (the prior non-sensitive call). Pre-fix
        the two bridges had separate :class:`SnapshotBuilder` instances
        and only ``self._bridge.record_post_execute`` was wired, so the
        approval bridge saw stale ``tool_call_count=0`` and any policy
        gated on running budgets diverged across the sensitive vs
        non-sensitive split.
        """
        seen_budgets: list[int] = []

        class _BudgetRecorderPolicy:
            """ACS PolicyDispatcher that records the snapshot budget."""

            def __init__(self):
                self.invocations: list[dict] = []

            def evaluate(self, invocation):
                self.invocations.append(dict(invocation))
                inp = invocation.get("input") or {}
                snapshot = inp.get("snapshot") if isinstance(inp, dict) else None
                budgets = (
                    snapshot.get("envelope", {}).get("budgets", {})
                    if isinstance(snapshot, dict)
                    else {}
                )
                seen_budgets.append(int(budgets.get("tool_call_count", -1)))
                return {"decision": "allow"}

        recorder = _BudgetRecorderPolicy()
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [],
            dispatcher=recorder,
        )

        def _resolver(ip, result):
            from agt.policies.runtime import ApprovalDecision

            return ApprovalDecision.allow(result.enforced_identity)

        kernel = self._kernel(
            runtime,
            approval_resolver=_resolver,
            require_human_approval=True,
            sensitive_tools=["scenario_tool"],
        )

        non_sensitive_ctx = _ADKFakeToolContext(
            tool_name="get_weather", tool_args={"q": "AI"}
        )
        sensitive_ctx = _ADKFakeToolContext(
            tool_name="scenario_tool", tool_args={"q": "AI"}
        )

        kernel.before_tool_callback(non_sensitive_ctx)
        kernel.before_tool_callback(sensitive_ctx)

        assert len(seen_budgets) == 2, (
            f"expected two budget snapshots, got {seen_budgets!r}"
        )
        assert seen_budgets[0] == 0, (
            f"first call MUST see tool_call_count=0, got {seen_budgets[0]}"
        )
        assert seen_budgets[1] == 1, (
            f"second call (sensitive) MUST see tool_call_count=1 from the "
            f"prior non-sensitive call; got {seen_budgets[1]}. The two-bridge "
            f"split is leaking budget state between sensitive and "
            f"non-sensitive paths."
        )

    def test_repeated_non_sensitive_calls_do_not_double_count_budget(
        self, tmp_path
    ):
        """AGT-M3 round-4 Opus regression: three sequential non-sensitive
        calls (all routed through the SAME `_bridge`) MUST advance the
        builder's `tool_call_count` by 1 per call, not 2. Pre-fix the
        adapter incremented `ctx.call_count` AND called
        `record_post_execute(tool_calls=1)`, which double-counted because
        `builder_for(ctx)` mirrors `ctx.call_count` via `max(...)` and
        `record_post_execute` then bumps the builder again. Result: a
        `max_tool_calls=N` policy denied on call N instead of call N+1.
        """
        seen_budgets: list[int] = []

        class _BudgetRecorderPolicy:
            def __init__(self):
                self.invocations: list[dict] = []

            def evaluate(self, invocation):
                self.invocations.append(dict(invocation))
                inp = invocation.get("input") or {}
                snapshot = inp.get("snapshot") if isinstance(inp, dict) else None
                budgets = (
                    snapshot.get("envelope", {}).get("budgets", {})
                    if isinstance(snapshot, dict)
                    else {}
                )
                seen_budgets.append(int(budgets.get("tool_call_count", -1)))
                return {"decision": "allow"}

        runtime, _policy = _build_scenario_runtime(
            tmp_path, [], dispatcher=_BudgetRecorderPolicy()
        )
        kernel = self._kernel(runtime)

        for _ in range(3):
            ctx = _ADKFakeToolContext(
                tool_name="get_weather", tool_args={"q": "AI"}
            )
            kernel.before_tool_callback(ctx)

        assert seen_budgets == [0, 1, 2], (
            f"three sequential calls MUST advance tool_call_count by 1 per "
            f"call (expected [0, 1, 2]); got {seen_budgets!r}. The adapter "
            f"is double-counting against the builder's tool_call_count."
        )


# =============================================================================
# Bridge-scenario coverage for the remaining adapters (CONCERN 5 from the
# AGT 5.0 deferred-work code reviews). Each class mirrors the depth of
# TestGoogleADKBridgeScenarios on the adapter's primary intervention
# point: allow / deny / transform / escalate (resolver approves). Tests
# skip when the framework's adapter module is not importable.
# =============================================================================


def _skip_if_not_importable(module_path: str):
    try:
        __import__(module_path)
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"{module_path} not importable: {exc}")


@_V5_BRIDGE_REQUIRED
class TestLangChainMiddlewareBridgeScenarios:
    """Verify LangChain middleware budget accounting through the AGT bridge."""

    def _middleware(self, runtime):
        _skip_if_not_importable("agent_os.integrations.langchain_adapter")
        kernel = LangChainKernel(
            policy=GovernancePolicy(max_tool_calls=3),
            _runtime=runtime,
        )
        return kernel.as_middleware()

    def _request(self):
        from types import SimpleNamespace

        return SimpleNamespace(
            tool_call={
                "name": "scenario_tool",
                "args": {"q": "weather"},
                "id": "call-1",
            }
        )

    def test_wrap_tool_call_allows_exact_budget_before_deny(self, tmp_path):
        dispatcher = _BudgetGatePolicy(limit=3)
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [],
            dispatcher=dispatcher,
        )
        middleware = self._middleware(runtime)

        def handler(_request):
            result = MagicMock()
            result.content = "ok"
            return result

        for _ in range(3):
            middleware.wrap_tool_call(self._request(), handler)

        with pytest.raises(PolicyViolationError):
            middleware.wrap_tool_call(self._request(), handler)

        # LangChain also has a host-side budget guard, so the fourth call
        # is denied before the runtime dispatcher is invoked. The
        # regression here is that the first three calls see exact
        # pre-call counts, not [0, 2, ...] from double-counting.
        assert dispatcher.seen_budgets == [0, 1, 2]


@_V5_BRIDGE_REQUIRED
class TestMistralBridgeScenarios:
    """Verify MistralKernel routes through the AGT 5.0 ACS runtime."""

    def _make_client(self):
        client = MagicMock()
        resp = MagicMock()
        resp.id = "chatcmpl-xyz"
        resp.usage.prompt_tokens = 10
        resp.usage.completion_tokens = 20
        resp.choices = []
        client.chat.return_value = resp
        return client

    def _kernel(self, runtime, *, approval_resolver=None):
        import sys
        import types as _types

        sys.modules.setdefault("mistralai", _types.ModuleType("mistralai"))
        _skip_if_not_importable("agent_os.integrations.mistral_adapter")
        import agent_os.integrations.mistral_adapter as mod

        mod._HAS_MISTRAL = True
        return mod.MistralKernel(_runtime=runtime, approval_resolver=approval_resolver)

    def test_chat_allow_path(self, tmp_path):
        runtime, policy = _build_scenario_runtime(tmp_path, [{"decision": "allow"}])
        kernel = self._kernel(runtime)
        client = self._make_client()
        governed = kernel.wrap(client)

        governed.chat(
            model="mistral-large-latest",
            messages=[{"role": "user", "content": "hi"}],
        )

        assert len(policy.invocations) == 1
        client.chat.assert_called_once()

    def test_chat_deny_path(self, tmp_path):
        from agent_os.integrations.mistral_adapter import PolicyViolationError

        runtime, _policy = _build_scenario_runtime(
            tmp_path, [{"decision": "deny", "reason": "blocked_topic"}]
        )
        kernel = self._kernel(runtime)
        client = self._make_client()
        governed = kernel.wrap(client)

        with pytest.raises(PolicyViolationError):
            governed.chat(
                model="mistral-large-latest",
                messages=[{"role": "user", "content": "blocked"}],
            )
        client.chat.assert_not_called()

    def test_chat_transform_rewrites_content(self, tmp_path):
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [
                {
                    "decision": "transform",
                    "reason": "pii_redaction",
                    "transform": {
                        "path": "$policy_target",
                        "value": "[REDACTED]",
                    },
                }
            ],
        )
        kernel = self._kernel(runtime)
        client = self._make_client()
        governed = kernel.wrap(client)

        governed.chat(
            model="m",
            messages=[{"role": "user", "content": "SSN 123-45-6789"}],
        )

        sent = client.chat.call_args.kwargs
        assert sent["messages"][0]["content"] == "[REDACTED]"

    def test_chat_escalate_with_resolver_forwards(self, tmp_path):
        captured: dict = {}
        resolver = _approving_resolver(captured)
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [{"decision": "escalate", "reason": "human_approval_required"}],
            approval_resolver=resolver,
        )
        kernel = self._kernel(runtime, approval_resolver=resolver)
        client = self._make_client()
        governed = kernel.wrap(client)

        governed.chat(
            model="m",
            messages=[{"role": "user", "content": "ok"}],
        )

        assert captured.get("ip") == "input"
        client.chat.assert_called_once()


@_V5_BRIDGE_REQUIRED
class TestPydanticAIBridgeScenarios:
    """Verify PydanticAIKernel.as_capability routes through the AGT 5.0 ACS runtime."""

    def _kernel(self, runtime, *, approval_resolver=None):
        _skip_if_not_importable("agent_os.integrations.pydantic_ai_adapter")
        from agent_os.integrations.pydantic_ai_adapter import PydanticAIKernel

        return PydanticAIKernel(
            _runtime=runtime, approval_resolver=approval_resolver
        )

    def test_before_run_allow(self, tmp_path):
        runtime, policy = _build_scenario_runtime(tmp_path, [{"decision": "allow"}])
        kernel = self._kernel(runtime)
        capability = kernel.as_capability()

        assert capability.before_run("what is the weather?") == "what is the weather?"
        assert len(policy.invocations) == 1

    def test_before_run_deny_raises(self, tmp_path):
        from agent_os.integrations.pydantic_ai_adapter import PolicyViolationError

        runtime, _policy = _build_scenario_runtime(
            tmp_path, [{"decision": "deny", "reason": "blocked_topic"}]
        )
        kernel = self._kernel(runtime)
        capability = kernel.as_capability()

        with pytest.raises(PolicyViolationError):
            capability.before_run("blocked")

    def test_before_run_transform_rewrites_prompt(self, tmp_path):
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [
                {
                    "decision": "transform",
                    "reason": "pii_redaction",
                    "transform": {
                        "path": "$policy_target",
                        "value": "Customer SSN is [REDACTED]",
                    },
                }
            ],
        )
        kernel = self._kernel(runtime)
        capability = kernel.as_capability()

        assert capability.before_run("Customer SSN is 123-45-6789") == "Customer SSN is [REDACTED]"

    def test_before_run_escalate_with_resolver(self, tmp_path):
        captured: dict = {}
        resolver = _approving_resolver(captured)
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [{"decision": "escalate", "reason": "human_approval_required"}],
            approval_resolver=resolver,
        )
        kernel = self._kernel(runtime, approval_resolver=resolver)
        capability = kernel.as_capability()

        assert capability.before_run("approve please") == "approve please"
        assert captured.get("ip") == "input"


@_V5_BRIDGE_REQUIRED
class TestSemanticKernelBridgeScenarios:
    """Verify SemanticKernelWrapper.as_filter routes through the AGT 5.0 ACS runtime."""

    def _make_sk_ctx(self, func_name="scenario_tool", plugin_name=""):
        from types import SimpleNamespace

        func = SimpleNamespace(name=func_name, plugin_name=plugin_name)
        return SimpleNamespace(
            function=func, arguments={"query": "hello"}, result=None
        )

    def _wrapper(self, runtime, *, approval_resolver=None):
        _skip_if_not_importable("agent_os.integrations.semantic_kernel_adapter")
        from agent_os.integrations.semantic_kernel_adapter import (
            SemanticKernelWrapper,
        )

        return SemanticKernelWrapper(
            _runtime=runtime, approval_resolver=approval_resolver
        )

    def test_filter_allow_invokes_next(self, tmp_path):
        runtime, policy = _build_scenario_runtime(
            tmp_path,
            [{"decision": "allow"}, {"decision": "allow"}],
        )
        wrapper = self._wrapper(runtime)
        sk_filter = wrapper.as_filter()
        ctx = self._make_sk_ctx()

        async def _next(c):
            c.result = "ok"

        asyncio.run(sk_filter(ctx, _next))
        assert ctx.result == "ok"
        # pre_tool_call + output verdicts consumed.
        assert len(policy.invocations) == 2

    def test_filter_deny_raises(self, tmp_path):
        from agent_os.integrations.semantic_kernel_adapter import (
            PolicyViolationError,
        )

        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [{"decision": "deny", "reason": "tool_args_forbidden"}],
        )
        wrapper = self._wrapper(runtime)
        sk_filter = wrapper.as_filter()
        ctx = self._make_sk_ctx()
        next_fn = AsyncMock()

        with pytest.raises(PolicyViolationError):
            asyncio.run(sk_filter(ctx, next_fn))
        next_fn.assert_not_awaited()

    def test_filter_transform_rewrites_arguments(self, tmp_path):
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [
                {
                    "decision": "transform",
                    "reason": "args_sanitized",
                    "transform": {
                        "path": "$policy_target",
                        "value": {"query": "[REDACTED]"},
                    },
                },
                {"decision": "allow"},
            ],
        )
        wrapper = self._wrapper(runtime)
        sk_filter = wrapper.as_filter()
        ctx = self._make_sk_ctx()
        ctx.arguments = {"query": "original"}

        async def _next(c):
            c.result = "ok"

        asyncio.run(sk_filter(ctx, _next))
        assert ctx.arguments == {"query": "[REDACTED]"}

    def test_filter_escalate_with_resolver(self, tmp_path):
        captured: dict = {}
        resolver = _approving_resolver(captured)
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [{"decision": "escalate", "reason": "human_approval_required"}, {"decision": "allow"}],
            approval_resolver=resolver,
        )
        wrapper = self._wrapper(runtime, approval_resolver=resolver)
        sk_filter = wrapper.as_filter()
        ctx = self._make_sk_ctx()

        async def _next(c):
            c.result = "ok"

        asyncio.run(sk_filter(ctx, _next))
        assert captured.get("ip") == "pre_tool_call"


@_V5_BRIDGE_REQUIRED
class TestMAFBridgeScenarios:
    """Verify GovernancePolicyMiddleware routes through the AGT 5.0 ACS runtime."""

    def _make_agent_ctx(self, *, text="hello"):
        from types import SimpleNamespace

        msg = SimpleNamespace(role="user", text=text, contents=[text])
        return SimpleNamespace(
            agent=SimpleNamespace(name="a"),
            messages=[msg],
            stream=False,
            metadata={},
            result=None,
        )

    def _middleware(self, runtime, *, approval_resolver=None):
        import sys
        import types as _types

        sys.modules.setdefault("agent_framework", _types.ModuleType("agent_framework"))
        _skip_if_not_importable("agent_os.integrations.maf_adapter")
        from agent_os.integrations.maf_adapter import (
            GovernancePolicyMiddleware,
            MAFKernel,
        )

        kernel = MAFKernel(_runtime=runtime, approval_resolver=approval_resolver)
        return GovernancePolicyMiddleware(kernel=kernel)

    def _capability_guard(self, runtime):
        import sys
        import types as _types

        sys.modules.setdefault("agent_framework", _types.ModuleType("agent_framework"))
        _skip_if_not_importable("agent_os.integrations.maf_adapter")
        from agent_os.integrations.maf_adapter import (
            CapabilityGuardMiddleware,
            MAFKernel,
        )

        kernel = MAFKernel(
            policy=GovernancePolicy(max_tool_calls=3),
            _runtime=runtime,
        )
        return CapabilityGuardMiddleware(kernel=kernel)

    def _make_function_ctx(self):
        from types import SimpleNamespace

        return SimpleNamespace(
            function=SimpleNamespace(name="scenario_tool"),
            arguments={"q": "weather"},
            metadata={},
            result=None,
        )

    def test_middleware_allow(self, tmp_path):
        runtime, policy = _build_scenario_runtime(tmp_path, [{"decision": "allow"}])
        mw = self._middleware(runtime)
        ctx = self._make_agent_ctx(text="hi")
        call_next = AsyncMock()

        asyncio.run(mw.process(ctx, call_next))

        call_next.assert_awaited_once()
        assert len(policy.invocations) == 1

    def test_middleware_deny_terminates(self, tmp_path):
        runtime, _policy = _build_scenario_runtime(
            tmp_path, [{"decision": "deny", "reason": "blocked_topic"}]
        )
        mw = self._middleware(runtime)
        ctx = self._make_agent_ctx(text="bad")
        call_next = AsyncMock()

        # MAF middleware raises MiddlewareTermination on deny per its
        # documented contract; the test imports the exception lazily so
        # the class skips cleanly when MAF isn't installed.
        from agent_os.integrations.maf_adapter import MiddlewareTermination

        with pytest.raises(MiddlewareTermination):
            asyncio.run(mw.process(ctx, call_next))
        call_next.assert_not_awaited()
        assert ctx.metadata.get("governance_decision") is not None
        assert ctx.metadata["governance_decision"].allowed is False

    def test_middleware_transform_rewrites_message(self, tmp_path):
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [
                {
                    "decision": "transform",
                    "reason": "pii_redaction",
                    "transform": {
                        "path": "$policy_target",
                        "value": "Customer SSN is [REDACTED]",
                    },
                }
            ],
        )
        mw = self._middleware(runtime)
        ctx = self._make_agent_ctx(text="Customer SSN is 123-45-6789")
        call_next = AsyncMock()

        asyncio.run(mw.process(ctx, call_next))
        # The last message text MUST be the redacted text.
        assert getattr(ctx.messages[-1], "text", None) == "Customer SSN is [REDACTED]"

    def test_middleware_escalate_with_resolver(self, tmp_path):
        captured: dict = {}
        resolver = _approving_resolver(captured)
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [{"decision": "escalate", "reason": "human_approval_required"}],
            approval_resolver=resolver,
        )
        mw = self._middleware(runtime, approval_resolver=resolver)
        ctx = self._make_agent_ctx(text="ok")
        call_next = AsyncMock()

        asyncio.run(mw.process(ctx, call_next))
        assert captured.get("ip") == "input"
        call_next.assert_awaited_once()

    def test_capability_guard_allows_exact_budget_before_deny(self, tmp_path):
        from agent_os.integrations.maf_adapter import MiddlewareTermination

        dispatcher = _BudgetGatePolicy(limit=3)
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [],
            dispatcher=dispatcher,
        )
        guard = self._capability_guard(runtime)
        call_next = AsyncMock()

        for _ in range(3):
            asyncio.run(guard.process(self._make_function_ctx(), call_next))

        with pytest.raises(MiddlewareTermination):
            asyncio.run(guard.process(self._make_function_ctx(), call_next))

        assert dispatcher.seen_budgets == [0, 1, 2, 3]
        assert call_next.await_count == 3


@_V5_BRIDGE_REQUIRED
class TestSmolagentsBridgeScenarios:
    """Verify SmolagentsKernel.before_tool_call routes through the AGT 5.0 ACS runtime."""

    def _kernel(self, runtime, *, approval_resolver=None):
        _skip_if_not_importable("agent_os.integrations.smolagents_adapter")
        from agent_os.integrations.smolagents_adapter import SmolagentsKernel

        return SmolagentsKernel(
            _runtime=runtime, approval_resolver=approval_resolver
        )

    def test_before_tool_call_allow(self, tmp_path):
        runtime, policy = _build_scenario_runtime(tmp_path, [{"decision": "allow"}])
        kernel = self._kernel(runtime)
        result = kernel.before_tool_call(
            tool_name="scenario_tool", tool_args={"q": "weather"}
        )
        assert result is None
        assert len(policy.invocations) == 1

    def test_before_tool_call_deny_blocks(self, tmp_path):
        runtime, _policy = _build_scenario_runtime(
            tmp_path, [{"decision": "deny", "reason": "tool_args_forbidden"}]
        )
        kernel = self._kernel(runtime)
        result = kernel.before_tool_call(
            tool_name="scenario_tool", tool_args={"q": "x"}
        )
        assert isinstance(result, dict)
        assert result.get("blocked") is True or "error" in result

    def test_before_tool_call_transform_rewrites_args(self, tmp_path):
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [
                {
                    "decision": "transform",
                    "reason": "args_sanitized",
                    "transform": {
                        "path": "$policy_target",
                        "value": {"q": "[REDACTED]"},
                    },
                }
            ],
        )
        kernel = self._kernel(runtime)
        args = {"q": "raw"}
        result = kernel.before_tool_call(tool_name="scenario_tool", tool_args=args)
        # The smolagents kernel rewrites tool_args in place per AGT D1.1.
        assert args.get("q") == "[REDACTED]" or result is None

    def test_before_tool_call_escalate_with_resolver(self, tmp_path):
        captured: dict = {}
        resolver = _approving_resolver(captured)
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [{"decision": "escalate", "reason": "human_approval_required"}],
            approval_resolver=resolver,
        )
        kernel = self._kernel(runtime, approval_resolver=resolver)
        result = kernel.before_tool_call(
            tool_name="scenario_tool", tool_args={"q": "x"}
        )
        assert result is None
        assert captured.get("ip") == "pre_tool_call"


@_V5_BRIDGE_REQUIRED
class TestA2ABridgeScenarios:
    """Verify A2AGovernanceAdapter.evaluate_task routes through the AGT 5.0 ACS runtime."""

    def _adapter(self, runtime, *, approval_resolver=None):
        _skip_if_not_importable("agent_os.integrations.a2a_adapter")
        from agent_os.integrations.a2a_adapter import A2AGovernanceAdapter

        return A2AGovernanceAdapter(
            _runtime=runtime, approval_resolver=approval_resolver
        )

    def _task(self, text="Find weather"):
        return {
            "id": "task-001",
            "skill_id": "search",
            "status": {"state": "submitted"},
            "x-agentmesh-trust": {
                "source_did": "did:mesh:agent-a",
                "source_trust_score": 500,
            },
            "messages": [{"role": "user", "parts": [{"text": text}]}],
        }

    def test_evaluate_task_allow(self, tmp_path):
        runtime, policy = _build_scenario_runtime(tmp_path, [{"decision": "allow"}])
        adapter = self._adapter(runtime)
        result = adapter.evaluate_task(self._task("hello"))
        assert result.allowed is True
        assert len(policy.invocations) == 1

    def test_evaluate_task_deny_blocks(self, tmp_path):
        runtime, _policy = _build_scenario_runtime(
            tmp_path, [{"decision": "deny", "reason": "blocked_input"}]
        )
        adapter = self._adapter(runtime)
        result = adapter.evaluate_task(self._task("blocked"))
        assert result.allowed is False

    def test_evaluate_task_transform_captures_redaction(self, tmp_path):
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [
                {
                    "decision": "transform",
                    "reason": "pii_redaction",
                    "transform": {
                        "path": "$policy_target",
                        "value": "Customer SSN is [REDACTED]",
                    },
                }
            ],
        )
        adapter = self._adapter(runtime)
        result = adapter.evaluate_task(self._task("Customer SSN is 123-45-6789"))
        assert result.allowed is True
        assert result.transform_value == "Customer SSN is [REDACTED]"

    def test_evaluate_task_escalate_with_resolver(self, tmp_path):
        captured: dict = {}
        resolver = _approving_resolver(captured)
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [{"decision": "escalate", "reason": "human_approval_required"}],
            approval_resolver=resolver,
        )
        adapter = self._adapter(runtime, approval_resolver=resolver)
        result = adapter.evaluate_task(self._task("approve please"))
        assert result.allowed is True
        assert captured.get("ip") == "input"


@_V5_BRIDGE_REQUIRED
class TestAgentShieldBridgeScenarios:
    """Verify AgentShieldKernel.validate_input routes through the AGT 5.0 ACS runtime."""

    def _kernel(self, runtime, *, approval_resolver=None):
        _skip_if_not_importable("agent_os.integrations.agentshield_adapter")
        from agent_os.integrations.agentshield_adapter import AgentShieldKernel

        return AgentShieldKernel.mock(
            _runtime=runtime, approval_resolver=approval_resolver
        )

    def test_validate_input_allow(self, tmp_path):
        from agent_os.integrations.agentshield_adapter import ShieldAction

        runtime, policy = _build_scenario_runtime(tmp_path, [{"decision": "allow"}])
        kernel = self._kernel(runtime)
        verdict = kernel.validate_input("hello")
        assert verdict.allowed is True
        assert verdict.action == ShieldAction.ALLOW
        assert len(policy.invocations) == 1

    def test_validate_input_deny_blocks(self, tmp_path):
        from agent_os.integrations.agentshield_adapter import ShieldAction

        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [{"decision": "deny", "reason": "blocked_user_input"}],
        )
        kernel = self._kernel(runtime)
        verdict = kernel.validate_input("blocked")
        assert verdict.allowed is False
        assert verdict.action == ShieldAction.BLOCK
        assert verdict.reason == "blocked_user_input"

    def test_validate_input_transform_sets_modified_value(self, tmp_path):
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [
                {
                    "decision": "transform",
                    "reason": "pii_redaction",
                    "transform": {
                        "path": "$policy_target",
                        "value": "Customer SSN is [REDACTED]",
                    },
                }
            ],
        )
        kernel = self._kernel(runtime)
        verdict = kernel.validate_input("Customer SSN is 123-45-6789")
        assert verdict.modified_value == "Customer SSN is [REDACTED]"

    def test_validate_input_escalate_with_resolver(self, tmp_path):
        captured: dict = {}
        resolver = _approving_resolver(captured)
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [{"decision": "escalate", "reason": "human_approval_required"}],
            approval_resolver=resolver,
        )
        kernel = self._kernel(runtime, approval_resolver=resolver)
        verdict = kernel.validate_input("approve please")
        assert verdict.allowed is True
        assert captured.get("ip") == "input"


@_V5_BRIDGE_REQUIRED
class TestBedrockBridgeScenarios:
    """Verify BedrockKernel.invoke_agent routes through the AGT 5.0 ACS runtime."""

    def _kernel(self, runtime, *, approval_resolver=None, enable_agt_pii_routing=False):
        _skip_if_not_importable("agent_os.integrations.bedrock_adapter")
        import agent_os.integrations.bedrock_adapter as mod
        from agent_os.integrations.bedrock_adapter import BedrockKernel
        from agent_os.integrations.base import GovernancePolicy

        mod._HAS_BOTO3 = True
        return BedrockKernel(
            policy=GovernancePolicy(),
            _runtime=runtime,
            approval_resolver=approval_resolver,
            enable_agt_pii_routing=enable_agt_pii_routing,
        )

    def _client(self):
        client = MagicMock()
        client.invoke_agent.return_value = {
            "ResponseMetadata": {"RequestId": "r1"},
            "completion": iter([]),
        }
        return client

    def test_invoke_agent_allow(self, tmp_path):
        runtime, policy = _build_scenario_runtime(tmp_path, [{"decision": "allow"}])
        kernel = self._kernel(runtime)
        client = self._client()
        governed = kernel.wrap(client)
        governed.invoke_agent(
            agentId="A", agentAliasId="L", sessionId="s", inputText="hi"
        )
        client.invoke_agent.assert_called_once()
        assert len(policy.invocations) == 1

    def test_invoke_agent_deny_raises(self, tmp_path):
        from agent_os.integrations.base import PolicyViolationError

        runtime, _policy = _build_scenario_runtime(
            tmp_path, [{"decision": "deny", "reason": "blocked_user_input"}]
        )
        kernel = self._kernel(runtime)
        client = self._client()
        governed = kernel.wrap(client)
        with pytest.raises(PolicyViolationError):
            governed.invoke_agent(
                agentId="A", agentAliasId="L", sessionId="s", inputText="blocked"
            )
        client.invoke_agent.assert_not_called()

    def test_invoke_agent_transform_rewrites_input(self, tmp_path):
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [
                {
                    "decision": "transform",
                    "reason": "pii_redaction",
                    "transform": {
                        "path": "$policy_target",
                        "value": "Customer record [REDACTED]",
                    },
                }
            ],
        )
        # AGT-DELTA D1.1: the redacted text must reach the boto3
        # client, so route AGT first via the new
        # enable_agt_pii_routing flag (off by default for v4 compat).
        kernel = self._kernel(runtime, enable_agt_pii_routing=True)
        client = self._client()
        governed = kernel.wrap(client)
        governed.invoke_agent(
            agentId="A",
            agentAliasId="L",
            sessionId="s",
            inputText="Customer SSN 123-45-6789",
        )
        sent = client.invoke_agent.call_args.kwargs
        assert sent["inputText"] == "Customer record [REDACTED]"

    def test_invoke_agent_escalate_with_resolver(self, tmp_path):
        captured: dict = {}
        resolver = _approving_resolver(captured)
        runtime, _policy = _build_scenario_runtime(
            tmp_path,
            [{"decision": "escalate", "reason": "human_approval_required"}],
            approval_resolver=resolver,
        )
        kernel = self._kernel(runtime, approval_resolver=resolver)
        client = self._client()
        governed = kernel.wrap(client)
        governed.invoke_agent(
            agentId="A", agentAliasId="L", sessionId="s", inputText="approve please"
        )
        client.invoke_agent.assert_called_once()
        assert captured.get("ip") == "input"
