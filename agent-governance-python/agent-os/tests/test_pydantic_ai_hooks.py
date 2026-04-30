# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for PydanticAI native governance capability (GovernanceCapability).

Validates:
- GovernanceCapability creation via as_capability()
- before_run: prompt content scanning (including empty / long prompts)
- before_tool_execute: tool allowlist, blocked patterns, call limits
- after_tool_execute: audit recording
- after_run: completion recording
- Multiple tool calls in a single execution
- Audit log immutability (returns copy)
- Repr output
- Deprecation warnings on wrap()
"""

import warnings
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from agent_os.integrations.pydantic_ai_adapter import (
    GovernanceCapability,
    PydanticAIKernel,
    wrap,
)
from agent_os.integrations.base import GovernancePolicy, PolicyViolationError


# ── Fixtures ──────────────────────────────────────────────────────


@pytest.fixture
def policy():
    """Create a governance policy for testing."""
    return GovernancePolicy(
        max_tool_calls=5,
        allowed_tools=["search", "read_file"],
        blocked_patterns=["DROP TABLE", "rm -rf"],
    )


@pytest.fixture
def kernel(policy):
    """Create a PydanticAIKernel with test policy."""
    return PydanticAIKernel(policy=policy)


@pytest.fixture
def capability(kernel):
    """Create a GovernanceCapability from the kernel."""
    return kernel.as_capability()


# ── as_capability() factory ──────────────────────────────────────


class TestAsCapability:
    """Tests for the as_capability() factory method."""

    def test_returns_governance_capability(self, kernel):
        cap = kernel.as_capability()
        assert isinstance(cap, GovernanceCapability)

    def test_capability_has_kernel_reference(self, kernel):
        cap = kernel.as_capability()
        assert cap.kernel is kernel

    def test_context_created(self, kernel):
        cap = kernel.as_capability()
        assert cap.context is not None
        assert cap.context.agent_id == "pydantic-ai-hooks"

    def test_audit_log_starts_empty(self, capability):
        assert capability.audit_log == []

    def test_audit_log_returns_copy(self, capability):
        """Mutating the returned list must not affect the internal log."""
        log = capability.audit_log
        log.append({"evil": "entry"})
        assert {"evil": "entry"} not in capability.audit_log


# ── before_run ────────────────────────────────────────────────────


class TestBeforeRun:
    """Tests for the before_run hook."""

    def test_passes_clean_prompt(self, capability):
        result = capability.before_run("Hello, how are you?")
        assert result == "Hello, how are you?"

    def test_blocks_blocked_pattern_in_prompt(self, capability):
        with pytest.raises(PolicyViolationError):
            capability.before_run("Please DROP TABLE users")

    def test_records_audit_on_block(self, capability):
        try:
            capability.before_run("Please DROP TABLE users")
        except PolicyViolationError:
            pass
        assert any(e["event"] == "run_blocked" for e in capability.audit_log)

    def test_records_audit_on_start(self, capability):
        capability.before_run("Hello")
        assert any(e["event"] == "run_start" for e in capability.audit_log)

    def test_empty_prompt_passes(self, capability):
        """An empty string prompt contains no blocked patterns — should pass."""
        result = capability.before_run("")
        assert result == ""
        assert any(e["event"] == "run_start" for e in capability.audit_log)

    def test_long_prompt_passes_when_clean(self, capability):
        """A very long but clean prompt must not be falsely blocked."""
        long_prompt = "Tell me about Python. " * 1000
        result = capability.before_run(long_prompt)
        assert result == long_prompt

    def test_long_prompt_with_blocked_pattern_is_caught(self, capability):
        """Blocked pattern buried in a long prompt must still be caught."""
        long_prompt = ("safe content " * 500) + "DROP TABLE users" + (" more safe" * 500)
        with pytest.raises(PolicyViolationError):
            capability.before_run(long_prompt)

    def test_prompt_returned_unmodified(self, capability):
        """before_run must return the original prompt without transformation."""
        original = "Hello, world!"
        returned = capability.before_run(original)
        assert returned is original or returned == original


# ── before_tool_execute ──────────────────────────────────────────


class TestBeforeToolExecute:
    """Tests for the before_tool_execute hook."""

    def test_allows_approved_tool(self, capability):
        result = capability.before_tool_execute("search", {"query": "Python"})
        assert result == {"query": "Python"}

    def test_blocks_disallowed_tool(self, capability):
        with pytest.raises(PolicyViolationError):
            capability.before_tool_execute("dangerous_exec", {"cmd": "ls"})

    def test_blocks_pattern_in_args(self, capability):
        with pytest.raises(PolicyViolationError):
            capability.before_tool_execute("search", {"query": "rm -rf /"})

    def test_increments_call_count(self, capability):
        capability.before_tool_execute("search", {"query": "test"})
        assert capability.context.call_count == 1

    def test_enforces_max_tool_calls(self, capability):
        for _ in range(5):
            capability.before_tool_execute("search", {"query": "test"})

        with pytest.raises(PolicyViolationError, match="exceeded"):
            capability.before_tool_execute("search", {"query": "test"})

    def test_records_audit_on_block(self, capability):
        try:
            capability.before_tool_execute("dangerous_exec", {})
        except PolicyViolationError:
            pass
        assert any(
            e["event"] == "tool_blocked" and e["tool"] == "dangerous_exec"
            for e in capability.audit_log
        )

    def test_records_audit_on_allow(self, capability):
        capability.before_tool_execute("search", {"query": "test"})
        assert any(
            e["event"] == "tool_allowed" and e["tool"] == "search"
            for e in capability.audit_log
        )

    def test_arguments_returned_unmodified(self, capability):
        args = {"query": "test", "limit": 10}
        result = capability.before_tool_execute("search", args)
        assert result == args

    def test_multiple_tools_in_sequence(self, capability):
        """Multiple allowed tool calls must each be tracked correctly."""
        capability.before_tool_execute("search", {"q": "a"})
        capability.before_tool_execute("read_file", {"path": "/tmp/x"})
        capability.before_tool_execute("search", {"q": "b"})
        assert capability.context.call_count == 3
        allowed_events = [e for e in capability.audit_log if e["event"] == "tool_allowed"]
        assert len(allowed_events) == 3

    def test_call_number_increments_in_audit(self, capability):
        """Audit entries must capture a monotonically increasing call_number."""
        capability.before_tool_execute("search", {"q": "first"})
        capability.before_tool_execute("read_file", {"path": "/tmp/y"})
        allowed = [e for e in capability.audit_log if e["event"] == "tool_allowed"]
        assert allowed[0]["call_number"] == 1
        assert allowed[1]["call_number"] == 2

    def test_empty_arguments_dict_passes(self, capability):
        """Tools invoked with no arguments must be handled without crashing."""
        result = capability.before_tool_execute("search", {})
        assert result == {}


# ── after_tool_execute ───────────────────────────────────────────


class TestAfterToolExecute:
    """Tests for the after_tool_execute hook."""

    def test_returns_result_unchanged(self, capability):
        result = capability.after_tool_execute("search", {"data": [1, 2, 3]})
        assert result == {"data": [1, 2, 3]}

    def test_records_audit(self, capability):
        capability.after_tool_execute("search", "result")
        assert any(
            e["event"] == "tool_executed" and e["tool"] == "search"
            for e in capability.audit_log
        )

    def test_returns_none_result_unchanged(self, capability):
        result = capability.after_tool_execute("read_file", None)
        assert result is None


# ── after_run ─────────────────────────────────────────────────────


class TestAfterRun:
    """Tests for the after_run hook."""

    def test_returns_result(self, capability):
        result = capability.after_run("final result")
        assert result == "final result"

    def test_records_audit(self, capability):
        capability.after_run("result")
        assert any(e["event"] == "run_complete" for e in capability.audit_log)

    def test_returns_none_result_unchanged(self, capability):
        result = capability.after_run(None)
        assert result is None


# ── Full lifecycle ────────────────────────────────────────────────


class TestFullLifecycle:
    """Integration-style test exercising the full lifecycle."""

    def test_complete_run_lifecycle(self, capability):
        prompt = capability.before_run("Search for Python")
        args = capability.before_tool_execute("search", {"query": "Python"})
        capability.after_tool_execute("search", ["result1"])
        capability.after_run(["result1"])

        events = [e["event"] for e in capability.audit_log]
        assert events == ["run_start", "tool_allowed", "tool_executed", "run_complete"]
        assert capability.context.call_count == 1


# ── Deprecation warnings ─────────────────────────────────────────


class TestDeprecationWarnings:
    """Tests that legacy methods emit DeprecationWarning."""

    def test_wrap_method_emits_deprecation(self, kernel):
        mock_agent = MagicMock()
        mock_agent.name = "test"
        mock_agent._function_tools = []

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            kernel.wrap(mock_agent)
            deprecations = [x for x in w if issubclass(x.category, DeprecationWarning)]
            assert len(deprecations) >= 1
            assert "as_capability" in str(deprecations[0].message)

    def test_wrap_function_emits_deprecation(self):
        mock_agent = MagicMock()
        mock_agent.name = "test"
        mock_agent._function_tools = []

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            wrap(mock_agent)
            deprecations = [x for x in w if issubclass(x.category, DeprecationWarning)]
            assert len(deprecations) >= 1
            assert "as_capability" in str(deprecations[0].message)

    def test_wrap_emits_exactly_one_deprecation(self, kernel):
        """Nested wrap calls must not surface duplicate DeprecationWarnings."""
        mock_agent = MagicMock()
        mock_agent.name = "test"
        mock_agent._function_tools = []

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            kernel.wrap(mock_agent)
            deprecations = [x for x in w if issubclass(x.category, DeprecationWarning)]
            assert len(deprecations) == 1


# ── Repr ──────────────────────────────────────────────────────────


class TestRepr:
    """Tests for GovernanceCapability repr."""

    def test_repr(self, capability):
        assert "GovernanceCapability" in repr(capability)
        assert "calls=0" in repr(capability)

    def test_repr_updates_after_calls(self, capability):
        capability.before_tool_execute("search", {"q": "x"})
        assert "calls=1" in repr(capability)
