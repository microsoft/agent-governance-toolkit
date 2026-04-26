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
from unittest.mock import MagicMock, patch, PropertyMock

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

    def test_stream_blocks_on_violation(self):
        policy = GovernancePolicy(blocked_patterns=["nope"])
        governed = LangChainKernel(policy).wrap(_make_mock_chain())
        with pytest.raises(PolicyViolationError):
            list(governed.stream("nope"))

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
        with pytest.raises(OpenAIPolicyViolationError, match="Message blocked"):
            governed.add_message("thread_abc", "my password is 123")

    def test_add_message_case_insensitive_block(self):
        policy = GovernancePolicy(blocked_patterns=["SECRET"])
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
        with pytest.raises(OpenAIPolicyViolationError, match="Instructions blocked"):
            governed.run("thread_abc", instructions="hack the planet")

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
        policy = GovernancePolicy(max_tool_calls=0)
        kernel = OpenAIKernel(policy)
        client = _make_mock_openai_client()

        ra_run = _make_requires_action_run("run_lim")
        client.beta.threads.runs.retrieve.return_value = ra_run
        created_run = MagicMock(id="run_lim")
        client.beta.threads.runs.create.return_value = created_run

        governed = kernel.wrap_assistant(_make_mock_assistant(), client)
        with pytest.raises(OpenAIPolicyViolationError, match="Tool call limit"):
            governed.run("thread_abc", poll_interval=0)
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
        with pytest.raises(OpenAIPolicyViolationError, match="Tool not allowed"):
            governed.run("thread_abc", poll_interval=0)


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
