# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for smolagents native governance callback (GovernanceStepCallback).

Validates:
- GovernanceStepCallback creation via as_step_callback()
- Tool blocklist enforcement
- Tool allowlist enforcement
- Blocked pattern detection in arguments
- Blocked pattern detection in observations
- max_tool_calls enforcement
- Audit trail recording
- Deprecation warnings on wrap()
"""

import warnings
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from agent_os.integrations.smolagents_adapter import (
    GovernanceStepCallback,
    SmolagentsKernel,
)


# ── Fixtures ──────────────────────────────────────────────────────


@pytest.fixture
def kernel():
    """Create a SmolagentsKernel with test configuration."""
    return SmolagentsKernel(
        max_tool_calls=5,
        allowed_tools=["web_search", "read_file"],
        blocked_tools=["exec_code", "shell"],
        blocked_patterns=["DROP TABLE", "rm -rf"],
    )


@pytest.fixture
def callback(kernel):
    """Create a GovernanceStepCallback from the kernel."""
    return kernel.as_step_callback()


@pytest.fixture
def mock_agent():
    """Create a mock smolagents agent."""
    return SimpleNamespace(name="test-agent")


def _make_step(tool_name=None, tool_args=None, observation=None):
    """Create a mock smolagents step."""
    tool_calls = []
    action = None
    if tool_name:
        action = SimpleNamespace(
            tool_name=tool_name,
            tool_arguments=tool_args or {},
        )
    return SimpleNamespace(
        tool_calls=tool_calls,
        action=action,
        observation=observation,
    )


# ── as_step_callback() factory ───────────────────────────────────


class TestAsStepCallback:
    """Tests for the as_step_callback() factory method."""

    def test_returns_governance_callback(self, kernel):
        cb = kernel.as_step_callback()
        assert isinstance(cb, GovernanceStepCallback)

    def test_callback_has_kernel_reference(self, kernel):
        cb = kernel.as_step_callback()
        assert cb.kernel is kernel

    def test_initial_step_count_is_zero(self, kernel):
        cb = kernel.as_step_callback()
        assert cb.step_count == 0


# ── Blocked tools ─────────────────────────────────────────────────


class TestBlockedTools:
    """Tests for tool blocklist enforcement."""

    def test_blocks_blocked_tool(self, callback, mock_agent):
        step = _make_step(tool_name="exec_code")
        with pytest.raises(Exception, match="explicitly blocked"):
            callback(step, mock_agent)

    def test_blocks_shell_tool(self, callback, mock_agent):
        step = _make_step(tool_name="shell")
        with pytest.raises(Exception, match="explicitly blocked"):
            callback(step, mock_agent)


# ── Allowed tools ─────────────────────────────────────────────────


class TestAllowedTools:
    """Tests for tool allowlist enforcement."""

    def test_allows_approved_tool(self, callback, mock_agent):
        step = _make_step(tool_name="web_search")
        callback(step, mock_agent)  # Should not raise
        assert callback.step_count == 1

    def test_blocks_unapproved_tool(self, callback, mock_agent):
        step = _make_step(tool_name="dangerous_tool")
        with pytest.raises(Exception, match="not in the allowed list"):
            callback(step, mock_agent)


# ── Blocked patterns ─────────────────────────────────────────────


class TestBlockedPatterns:
    """Tests for blocked pattern detection."""

    def test_blocks_pattern_in_args(self, callback, mock_agent):
        step = _make_step(
            tool_name="web_search",
            tool_args={"query": "DROP TABLE users"},
        )
        with pytest.raises(Exception, match="Blocked pattern"):
            callback(step, mock_agent)

    def test_blocks_pattern_in_observation(self, callback, mock_agent):
        step = _make_step(observation="Result: some clean output")
        callback(step, mock_agent)  # Step without blocked pattern passes...

        # But a step with tool calls + blocked observation:
        kernel2 = SmolagentsKernel(
            allowed_tools=["web_search"],
            blocked_patterns=["rm -rf"],
        )
        cb2 = kernel2.as_step_callback()
        step2 = SimpleNamespace(
            tool_calls=[],
            action=None,
            observation="Dangerous output: rm -rf /",
        )
        with pytest.raises(Exception, match="Blocked pattern.*observation"):
            cb2(step2, mock_agent)

    def test_clean_args_pass(self, callback, mock_agent):
        step = _make_step(
            tool_name="web_search",
            tool_args={"query": "SELECT * FROM users"},
        )
        callback(step, mock_agent)  # Should not raise
        assert callback.step_count == 1


# ── Call count enforcement ────────────────────────────────────────


class TestCallCount:
    """Tests for max_tool_calls enforcement."""

    def test_enforces_max_tool_calls(self, callback, mock_agent):
        for _ in range(5):
            step = _make_step(tool_name="web_search")
            callback(step, mock_agent)

        # 6th call should be blocked
        step = _make_step(tool_name="web_search")
        with pytest.raises(Exception, match="Tool call limit exceeded"):
            callback(step, mock_agent)


# ── Step counting ─────────────────────────────────────────────────


class TestStepCounting:
    """Tests for step counting."""

    def test_increments_step_count(self, callback, mock_agent):
        # Step with no tool calls
        step = _make_step()
        callback(step, mock_agent)
        assert callback.step_count == 1

        # Step with a tool call
        step = _make_step(tool_name="web_search")
        callback(step, mock_agent)
        assert callback.step_count == 2


# ── Deprecation warnings ─────────────────────────────────────────


class TestDeprecationWarnings:
    """Tests that legacy wrap() emits DeprecationWarning."""

    def test_wrap_emits_deprecation(self, kernel):
        mock_agent = SimpleNamespace(
            name="test",
            toolbox={"tool1": SimpleNamespace(forward=lambda *a, **k: None)},
        )
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            kernel.wrap(mock_agent)
            deprecations = [x for x in w if issubclass(x.category, DeprecationWarning)]
            assert len(deprecations) >= 1
            assert "as_step_callback" in str(deprecations[0].message)


# ── Repr ──────────────────────────────────────────────────────────


class TestRepr:
    """Tests for GovernanceStepCallback repr."""

    def test_repr(self, callback):
        assert "GovernanceStepCallback" in repr(callback)
        assert "steps=0" in repr(callback)
