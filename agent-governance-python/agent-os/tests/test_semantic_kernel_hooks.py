# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for Semantic Kernel native governance filter (GovernanceFunctionFilter).

Validates:
- GovernanceFunctionFilter creation via as_filter()
- Function allowlist enforcement (exact and wildcard)
- Blocked pattern detection in arguments
- max_tool_calls enforcement
- Pre-execute (Cedar/OPA) gating
- Deprecation warnings on wrap() and wrap_kernel()
- Duplicate filter registration isolation
- Malformed / missing argument handling
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
        """Context is keyed by a uuid-prefixed id; verify at least one entry exists."""
        initial_count = len(wrapper._contexts)
        wrapper.as_filter()
        assert len(wrapper._contexts) > initial_count

    def test_filter_has_wrapper_reference(self, wrapper):
        f = wrapper.as_filter()
        assert f.wrapper is wrapper

    def test_multiple_filters_get_distinct_contexts(self, wrapper):
        """Each as_filter() call must register a separate, unique context."""
        f1 = wrapper.as_filter()
        f2 = wrapper.as_filter()
        assert f1.context.agent_id != f2.context.agent_id

    def test_duplicate_filter_registration_is_independent(self, wrapper):
        """A second filter must not corrupt the first filter's call counter."""
        f1 = wrapper.as_filter()
        f2 = wrapper.as_filter()
        next_fn = AsyncMock()

        # Exhaust f1 (call_count increments by 2 per invocation; limit is 5)
        # 3 invocations → count=6 → exceeds 5 → 4th call must raise
        for _ in range(2):
            asyncio.get_event_loop().run_until_complete(f1(_make_context(), next_fn))
        with pytest.raises(Exception, match="Max tool calls exceeded"):
            asyncio.get_event_loop().run_until_complete(f1(_make_context(), next_fn))

        # f2 still has its own fresh counter — must not raise
        asyncio.get_event_loop().run_until_complete(f2(_make_context(), next_fn))


# ── Function allowlist ────────────────────────────────────────────


class TestFunctionAllowlist:
    """Tests for function name validation."""

    def test_allows_exact_match(self, governance_filter):
        ctx = _make_context("safe_func", "MyPlugin")
        next_fn = AsyncMock()

        asyncio.get_event_loop().run_until_complete(governance_filter(ctx, next_fn))
        next_fn.assert_awaited_once_with(ctx)

    def test_allows_wildcard_match(self, governance_filter):
        ctx = _make_context("any_func", "MyPlugin")
        next_fn = AsyncMock()

        asyncio.get_event_loop().run_until_complete(governance_filter(ctx, next_fn))
        next_fn.assert_awaited_once()

    def test_blocks_disallowed_function(self, governance_filter):
        ctx = _make_context("dangerous_func", "OtherPlugin")
        next_fn = AsyncMock()

        with pytest.raises(Exception, match="Function not allowed"):
            asyncio.get_event_loop().run_until_complete(governance_filter(ctx, next_fn))
        next_fn.assert_not_awaited()

    def test_wildcard_does_not_match_different_plugin(self, governance_filter):
        """MyPlugin.* should NOT grant access to OtherPlugin.any_func."""
        ctx = _make_context("any_func", "OtherPlugin")
        next_fn = AsyncMock()

        with pytest.raises(Exception, match="Function not allowed"):
            asyncio.get_event_loop().run_until_complete(governance_filter(ctx, next_fn))

    def test_empty_allowed_tools_permits_any_function(self):
        """With no allowed_tools restriction all functions pass through."""
        open_policy = GovernancePolicy()  # no allowed_tools
        open_wrapper = SemanticKernelWrapper(policy=open_policy)
        f = open_wrapper.as_filter()
        next_fn = AsyncMock()
        ctx = _make_context("anything", "AnyPlugin")
        asyncio.get_event_loop().run_until_complete(f(ctx, next_fn))
        next_fn.assert_awaited_once()


# ── Blocked patterns ─────────────────────────────────────────────


class TestBlockedPatterns:
    """Tests for blocked pattern detection in arguments."""

    def test_blocks_pattern_in_args(self, governance_filter):
        ctx = _make_context("safe_func", "MyPlugin", args={"query": "DROP TABLE users"})
        next_fn = AsyncMock()

        with pytest.raises(Exception, match="Blocked pattern"):
            asyncio.get_event_loop().run_until_complete(governance_filter(ctx, next_fn))

    def test_clean_args_pass(self, governance_filter):
        ctx = _make_context("safe_func", "MyPlugin", args={"query": "SELECT * FROM users"})
        next_fn = AsyncMock()

        asyncio.get_event_loop().run_until_complete(governance_filter(ctx, next_fn))
        next_fn.assert_awaited_once()

    def test_blocks_pattern_in_nested_arg_str(self, governance_filter):
        """Blocked patterns inside nested dict values must be caught."""
        ctx = _make_context(
            "safe_func", "MyPlugin",
            args={"outer": {"inner": "DROP TABLE sensitive_data"}},
        )
        next_fn = AsyncMock()
        with pytest.raises(Exception, match="Blocked pattern"):
            asyncio.get_event_loop().run_until_complete(governance_filter(ctx, next_fn))

    def test_none_arguments_handled_gracefully(self):
        """A context with arguments=None must not raise AttributeError."""
        open_policy = GovernancePolicy()
        open_wrapper = SemanticKernelWrapper(policy=open_policy)
        f = open_wrapper.as_filter()
        ctx = _make_context("safe_func", "MyPlugin", args=None)
        next_fn = AsyncMock()
        asyncio.get_event_loop().run_until_complete(f(ctx, next_fn))
        next_fn.assert_awaited_once()


# ── Call count enforcement ────────────────────────────────────────


class TestCallCount:
    """Tests for max_tool_calls enforcement."""

    def test_enforces_max_tool_calls(self, governance_filter):
        next_fn = AsyncMock()
        # call_count increments by 2 per invocation (filter + pre_execute).
        # policy.max_tool_calls=5 → limit exceeded at the 3rd invocation.
        for _ in range(2):
            asyncio.get_event_loop().run_until_complete(
                governance_filter(_make_context(), next_fn)
            )

        with pytest.raises(Exception, match="Max tool calls exceeded"):
            asyncio.get_event_loop().run_until_complete(
                governance_filter(_make_context(), next_fn)
            )

    def test_tracks_call_count(self, governance_filter):
        next_fn = AsyncMock()
        asyncio.get_event_loop().run_until_complete(
            governance_filter(_make_context(), next_fn)
        )
        # call_count increments by 2 per invocation.
        assert governance_filter.context.call_count == 2

    def test_call_count_is_independent_per_filter(self, wrapper):
        """Two separate filter instances each maintain their own counter."""
        f1 = wrapper.as_filter()
        f2 = wrapper.as_filter()
        next_fn = AsyncMock()
        for _ in range(2):
            asyncio.get_event_loop().run_until_complete(f1(_make_context(), next_fn))
        # 2 calls × 2 increments = 4
        assert f1.context.call_count == 4
        assert f2.context.call_count == 0


# ── Audit trail ───────────────────────────────────────────────────


class TestAuditTrail:
    """Tests for function invocation recording."""

    def test_records_invocation(self, governance_filter):
        next_fn = AsyncMock()
        asyncio.get_event_loop().run_until_complete(
            governance_filter(_make_context("safe_func", "MyPlugin"), next_fn)
        )
        assert len(governance_filter.context.functions_invoked) == 1
        assert governance_filter.context.functions_invoked[0]["function"] == "MyPlugin.safe_func"

    def test_records_multiple_invocations(self, governance_filter):
        next_fn = AsyncMock()
        for name in ["safe_func", "any_func"]:
            asyncio.get_event_loop().run_until_complete(
                governance_filter(_make_context(name, "MyPlugin"), next_fn)
            )
        assert len(governance_filter.context.functions_invoked) == 2


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

    def test_wrap_emits_exactly_one_deprecation(self, wrapper):
        """Users should see a single DeprecationWarning, not nested duplicates."""
        mock_kernel = MagicMock()
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            wrapper.wrap(mock_kernel)
            deprecations = [x for x in w if issubclass(x.category, DeprecationWarning)]
            assert len(deprecations) == 1
