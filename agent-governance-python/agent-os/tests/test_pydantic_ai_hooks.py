# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for PydanticAI native governance capability (GovernanceCapability).

Validates:
- GovernanceCapability creation via as_capability()
- before_run: prompt content scanning
- before_tool_execute: tool allowlist, blocked patterns, call limits
- after_tool_execute: audit recording
- after_run: completion recording
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


# ── after_run ─────────────────────────────────────────────────────


class TestAfterRun:
    """Tests for the after_run hook."""

    def test_returns_result(self, capability):
        result = capability.after_run("final result")
        assert result == "final result"

    def test_records_audit(self, capability):
        capability.after_run("result")
        assert any(e["event"] == "run_complete" for e in capability.audit_log)


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


# ── Repr ──────────────────────────────────────────────────────────


class TestRepr:
    """Tests for GovernanceCapability repr."""

    def test_repr(self, capability):
        assert "GovernanceCapability" in repr(capability)
        assert "calls=0" in repr(capability)
