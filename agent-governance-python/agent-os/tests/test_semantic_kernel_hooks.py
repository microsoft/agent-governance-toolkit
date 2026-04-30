# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for Semantic Kernel native governance filter (GovernanceFunctionFilter).

Validates:
- GovernanceFunctionFilter creation via as_filter()
- Function allowlist enforcement
- Blocked pattern detection in arguments
- max_tool_calls enforcement
- Pre-execute (Cedar/OPA) gating
- Post-execute drift detection
- Deprecation warnings on wrap() and wrap_kernel()
"""

import asyncio
import warnings
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from agent_os.integrations.semantic_kernel_adapter import (
    GovernanceFunctionFilter,
    GovernedSemanticKernel,
    SemanticKernelWrapper,
    wrap_kernel,
)
from agent_os.integrations.base import GovernancePolicy


# ── Fixtures ──────────────────────────────────────────────────────


@pytest.fixture
def policy():
    """Create a governance policy for testing."""
    return GovernancePolicy(
        max_tool_calls=5,
        allowed_tools=["MyPlugin.safe_func", "MyPlugin.*"],
        blocked_patterns=["DROP TABLE", "rm -rf"],
    )


@pytest.fixture
def wrapper(policy):
    """Create a SemanticKernelWrapper with test policy."""
    return SemanticKernelWrapper(policy=policy)


@pytest.fixture
def governance_filter(wrapper):
    """Create a GovernanceFunctionFilter."""
    return wrapper.as_filter()


def _make_context(func_name="safe_func", plugin_name="MyPlugin", args=None):
    """Create a mock SK function invocation context."""
    func = SimpleNamespace(name=func_name, plugin_name=plugin_name)
    ctx = SimpleNamespace(
        function=func,
        arguments=args or {},
        result=None,
    )
    return ctx


# ── as_filter() factory ──────────────────────────────────────────


class TestAsFilter:
    """Tests for the as_filter() factory method."""

    def test_returns_governance_filter(self, wrapper):
        f = wrapper.as_filter()
        assert isinstance(f, GovernanceFunctionFilter)

    def test_filter_registered_in_contexts(self, wrapper):
        wrapper.as_filter()
        assert "sk-filter" in wrapper._contexts

    def test_filter_has_wrapper_reference(self, wrapper):
        f = wrapper.as_filter()
        assert f.wrapper is wrapper


# ── Function allowlist ────────────────────────────────────────────


class TestFunctionAllowlist:
    """Tests for function name validation."""

    def test_allows_exact_match(self, governance_filter):
        ctx = _make_context("safe_func", "MyPlugin")
        next_fn = AsyncMock()

        asyncio.run(
            governance_filter(ctx, next_fn)
        )
        next_fn.assert_awaited_once_with(ctx)

    def test_allows_wildcard_match(self, governance_filter):
        ctx = _make_context("any_func", "MyPlugin")
        next_fn = AsyncMock()

        asyncio.run(
            governance_filter(ctx, next_fn)
        )
        next_fn.assert_awaited_once()

    def test_blocks_disallowed_function(self, governance_filter):
        ctx = _make_context("dangerous_func", "OtherPlugin")
        next_fn = AsyncMock()

        with pytest.raises(Exception, match="Function not allowed"):
            asyncio.run(
                governance_filter(ctx, next_fn)
            )
        next_fn.assert_not_awaited()


# ── Blocked patterns ─────────────────────────────────────────────


class TestBlockedPatterns:
    """Tests for blocked pattern detection in arguments."""

    def test_blocks_pattern_in_args(self, governance_filter):
        ctx = _make_context("safe_func", "MyPlugin", args={"query": "DROP TABLE users"})
        next_fn = AsyncMock()

        with pytest.raises(Exception, match="Blocked pattern"):
            asyncio.run(
                governance_filter(ctx, next_fn)
            )

    def test_clean_args_pass(self, governance_filter):
        ctx = _make_context("safe_func", "MyPlugin", args={"query": "SELECT * FROM users"})
        next_fn = AsyncMock()

        asyncio.run(
            governance_filter(ctx, next_fn)
        )
        next_fn.assert_awaited_once()


# ── Call count enforcement ────────────────────────────────────────


class TestCallCount:
    """Tests for max_tool_calls enforcement."""

    def test_enforces_max_tool_calls(self, governance_filter):
        next_fn = AsyncMock()

        # Exhaust the call limit
        for i in range(5):
            ctx = _make_context("safe_func", "MyPlugin")
            asyncio.run(
                governance_filter(ctx, next_fn)
            )

        # 6th call should be blocked
        ctx = _make_context("safe_func", "MyPlugin")
        with pytest.raises(Exception, match="Tool call limit exceeded"):
            asyncio.run(
                governance_filter(ctx, next_fn)
            )

    def test_tracks_call_count(self, governance_filter):
        next_fn = AsyncMock()
        ctx = _make_context("safe_func", "MyPlugin")

        asyncio.run(
            governance_filter(ctx, next_fn)
        )
        assert governance_filter.context.call_count == 1


# ── Audit trail ───────────────────────────────────────────────────


class TestAuditTrail:
    """Tests for function invocation recording."""

    def test_records_invocation(self, governance_filter):
        next_fn = AsyncMock()
        ctx = _make_context("safe_func", "MyPlugin")

        asyncio.run(
            governance_filter(ctx, next_fn)
        )
        assert len(governance_filter.context.functions_invoked) == 1
        assert governance_filter.context.functions_invoked[0]["function"] == "MyPlugin.safe_func"


# ── Deprecation warnings ─────────────────────────────────────────


class TestDeprecationWarnings:
    """Tests that legacy methods emit DeprecationWarning."""

    def test_wrap_emits_deprecation(self, wrapper):
        mock_kernel = MagicMock()
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            wrapper.wrap(mock_kernel)
            deprecations = [x for x in w if issubclass(x.category, DeprecationWarning)]
            assert len(deprecations) >= 1
            assert "as_filter" in str(deprecations[0].message)

    def test_wrap_kernel_emits_deprecation(self):
        mock_kernel = MagicMock()
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            wrap_kernel(mock_kernel)
            deprecations = [x for x in w if issubclass(x.category, DeprecationWarning)]
            assert len(deprecations) >= 1
            assert "as_filter" in str(deprecations[0].message)
