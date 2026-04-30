# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for native CrewAI GovernanceHooks integration.

Covers:
- GovernanceHooks init, registration, and properties
- before_tool_call governance (allowlist, blocklist, patterns, Cedar)
- after_tool_call governance (output patterns, post_execute)
- before_llm_call governance (input content filter)
- after_llm_call governance (output content filter)
- as_hooks() factory
- Deprecation warnings for wrap()
- Backward compatibility with existing wrap() API
"""

import sys
import types
import warnings
from unittest.mock import MagicMock, patch

import pytest

# ── Stub crewai.hooks before importing the adapter ────────────────
# CrewAI is not installed in the test environment, so we create
# minimal stubs that capture the registered functions.

_registered_hooks: dict[str, list] = {
    "before_tool_call": [],
    "after_tool_call": [],
    "before_llm_call": [],
    "after_llm_call": [],
}


def _make_hook_decorator(hook_type: str):
    """Create a fake CrewAI hook decorator that captures the function."""
    def decorator(fn):
        _registered_hooks[hook_type].append(fn)
        return fn
    return decorator


# Install the crewai.hooks stub module
_hooks_module = types.ModuleType("crewai.hooks")
_hooks_module.before_tool_call = _make_hook_decorator("before_tool_call")
_hooks_module.after_tool_call = _make_hook_decorator("after_tool_call")
_hooks_module.before_llm_call = _make_hook_decorator("before_llm_call")
_hooks_module.after_llm_call = _make_hook_decorator("after_llm_call")

_crewai_module = types.ModuleType("crewai")
sys.modules["crewai"] = _crewai_module
sys.modules["crewai.hooks"] = _hooks_module

# The adapter may have been imported before the stubs were installed (e.g.
# via __init__.py), so _HOOKS_AVAILABLE could already be False.  Force a
# reload so the try/except picks up our stub module.
import importlib
import agent_os.integrations.crewai_adapter as _crewai_adapter_mod

importlib.reload(_crewai_adapter_mod)

from agent_os.integrations.crewai_adapter import (
    CrewAIKernel,
    GovernanceHooks,
    GovernancePolicy,
    PolicyViolationError,
)


# ── Fixtures ──────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _clear_hooks():
    """Clear the global hook registry between tests."""
    for key in _registered_hooks:
        _registered_hooks[key].clear()
    yield
    for key in _registered_hooks:
        _registered_hooks[key].clear()


def _make_tool_context(
    tool_name="search",
    tool_input=None,
    agent_name="researcher",
    tool_result=None,
):
    """Create a mock ToolCallHookContext."""
    ctx = MagicMock()
    ctx.tool_name = tool_name
    ctx.tool_input = tool_input or {"query": "hello"}
    agent = MagicMock()
    agent.role = agent_name
    agent.name = agent_name
    ctx.agent = agent
    ctx.task = MagicMock()
    ctx.crew = MagicMock()
    ctx.tool_result = tool_result
    return ctx


def _make_llm_context(messages=None, response=None, iterations=1):
    """Create a mock LLMCallHookContext."""
    ctx = MagicMock()
    ctx.messages = messages or [{"role": "user", "content": "Hello"}]
    ctx.agent = MagicMock()
    ctx.agent.role = "researcher"
    ctx.task = MagicMock()
    ctx.crew = MagicMock()
    ctx.llm = MagicMock()
    ctx.iterations = iterations
    ctx.response = response
    return ctx


# ═══════════════════════════════════════════════════════════════════
# Test GovernanceHooks Init
# ═══════════════════════════════════════════════════════════════════

class TestGovernanceHooksInit:
    """Tests for GovernanceHooks initialization and properties."""

    def test_as_hooks_returns_hooks_instance(self):
        """as_hooks() returns a GovernanceHooks instance."""
        kernel = CrewAIKernel(GovernancePolicy())
        hooks = kernel.as_hooks()
        assert isinstance(hooks, GovernanceHooks)

    def test_as_hooks_custom_name(self):
        """as_hooks() accepts a custom name."""
        kernel = CrewAIKernel(GovernancePolicy())
        hooks = kernel.as_hooks(name="prod-guard")
        assert "prod-guard" in repr(hooks)

    def test_kernel_property(self):
        """GovernanceHooks.kernel returns the parent kernel."""
        kernel = CrewAIKernel(GovernancePolicy())
        hooks = kernel.as_hooks()
        assert hooks.kernel is kernel

    def test_context_property(self):
        """GovernanceHooks.context returns an ExecutionContext."""
        kernel = CrewAIKernel(GovernancePolicy())
        hooks = kernel.as_hooks()
        assert hooks.context is not None

    def test_is_registered(self):
        """GovernanceHooks.is_registered is True after registration."""
        kernel = CrewAIKernel(GovernancePolicy())
        hooks = kernel.as_hooks()
        assert hooks.is_registered is True

    def test_repr(self):
        """repr shows name and registration status."""
        kernel = CrewAIKernel(GovernancePolicy())
        hooks = kernel.as_hooks(name="test")
        assert "name='test'" in repr(hooks)
        assert "registered=True" in repr(hooks)

    def test_unregister(self):
        """unregister() clears the registered state."""
        kernel = CrewAIKernel(GovernancePolicy())
        hooks = kernel.as_hooks()
        hooks.unregister()
        assert hooks.is_registered is False

    def test_context_has_correct_policy(self):
        """The context inherits the kernel's policy settings."""
        policy = GovernancePolicy(blocked_patterns=["secret"])
        kernel = CrewAIKernel(policy)
        hooks = kernel.as_hooks()
        assert hooks.context.policy.blocked_patterns == ["secret"]

    def test_hooks_registered_with_crewai(self):
        """All four hook types are registered with CrewAI."""
        kernel = CrewAIKernel(GovernancePolicy())
        kernel.as_hooks()
        assert len(_registered_hooks["before_tool_call"]) == 1
        assert len(_registered_hooks["after_tool_call"]) == 1
        assert len(_registered_hooks["before_llm_call"]) == 1
        assert len(_registered_hooks["after_llm_call"]) == 1


# ═══════════════════════════════════════════════════════════════════
# Test before_tool_call
# ═══════════════════════════════════════════════════════════════════

class TestBeforeToolCall:
    """Tests for before_tool_call governance hook."""

    def test_allowed_tool_passes(self):
        """Tool in allowed_tools list passes governance."""
        kernel = CrewAIKernel(GovernancePolicy(allowed_tools=["search"]))
        kernel.as_hooks()
        hook_fn = _registered_hooks["before_tool_call"][0]
        ctx = _make_tool_context(tool_name="search")
        result = hook_fn(ctx)
        assert result is None  # None = allow

    def test_tool_not_in_allowed_list_blocked(self):
        """Tool NOT in allowed_tools list is blocked."""
        kernel = CrewAIKernel(GovernancePolicy(allowed_tools=["search"]))
        kernel.as_hooks()
        hook_fn = _registered_hooks["before_tool_call"][0]
        ctx = _make_tool_context(tool_name="delete_database")
        result = hook_fn(ctx)
        assert result is False

    def test_blocked_tool_name_via_pattern(self):
        """Tool matching a blocked pattern is blocked."""
        kernel = CrewAIKernel(GovernancePolicy(blocked_patterns=["rm_rf"]))
        kernel.as_hooks()
        hook_fn = _registered_hooks["before_tool_call"][0]
        ctx = _make_tool_context(tool_name="rm_rf")
        result = hook_fn(ctx)
        assert result is False

    def test_blocked_pattern_in_args(self):
        """Blocked pattern in tool args blocks the call."""
        kernel = CrewAIKernel(GovernancePolicy(blocked_patterns=["DROP TABLE"]))
        kernel.as_hooks()
        hook_fn = _registered_hooks["before_tool_call"][0]
        ctx = _make_tool_context(tool_input={"query": "DROP TABLE users"})
        result = hook_fn(ctx)
        assert result is False

    def test_blocked_pattern_in_tool_name(self):
        """Blocked pattern matching tool name blocks the call."""
        kernel = CrewAIKernel(GovernancePolicy(blocked_patterns=["hack"]))
        kernel.as_hooks()
        hook_fn = _registered_hooks["before_tool_call"][0]
        ctx = _make_tool_context(tool_name="hack_system")
        result = hook_fn(ctx)
        assert result is False

    def test_call_count_incremented(self):
        """Each allowed tool call increments the call count."""
        kernel = CrewAIKernel(GovernancePolicy())
        hooks = kernel.as_hooks()
        hook_fn = _registered_hooks["before_tool_call"][0]
        ctx = _make_tool_context()
        hook_fn(ctx)
        assert hooks.context.call_count == 1
        hook_fn(ctx)
        assert hooks.context.call_count == 2

    def test_max_tool_calls_blocks(self):
        """Exceeding max_tool_calls blocks further calls."""
        kernel = CrewAIKernel(GovernancePolicy(max_tool_calls=2))
        hooks = kernel.as_hooks()
        hook_fn = _registered_hooks["before_tool_call"][0]
        ctx = _make_tool_context()

        assert hook_fn(ctx) is None  # call 1 OK
        assert hook_fn(ctx) is None  # call 2 OK
        assert hook_fn(ctx) is False  # call 3 blocked

    def test_cedar_deny_blocks_tool(self):
        """Cedar evaluator deny blocks tool call."""
        evaluator = MagicMock()
        evaluator.evaluate.return_value = MagicMock(allowed=False, reason="Cedar denied")
        kernel = CrewAIKernel(GovernancePolicy(), evaluator=evaluator)
        kernel.as_hooks()
        hook_fn = _registered_hooks["before_tool_call"][0]
        ctx = _make_tool_context()
        result = hook_fn(ctx)
        assert result is False

    def test_no_policy_restrictions_allows_all(self):
        """Default policy allows all tools."""
        kernel = CrewAIKernel(GovernancePolicy())
        kernel.as_hooks()
        hook_fn = _registered_hooks["before_tool_call"][0]
        ctx = _make_tool_context(tool_name="anything")
        result = hook_fn(ctx)
        assert result is None


# ═══════════════════════════════════════════════════════════════════
# Test after_tool_call
# ═══════════════════════════════════════════════════════════════════

class TestAfterToolCall:
    """Tests for after_tool_call governance hook."""

    def test_clean_output_passes(self):
        """Tool output without blocked patterns passes."""
        kernel = CrewAIKernel(GovernancePolicy(blocked_patterns=["SECRET"]))
        kernel.as_hooks()
        hook_fn = _registered_hooks["after_tool_call"][0]
        ctx = _make_tool_context(tool_result="normal result")
        result = hook_fn(ctx)
        assert result is None

    def test_blocked_pattern_in_output_raises(self):
        """Blocked pattern in tool output raises PolicyViolationError."""
        kernel = CrewAIKernel(GovernancePolicy(blocked_patterns=["SECRET"]))
        kernel.as_hooks()
        hook_fn = _registered_hooks["after_tool_call"][0]
        ctx = _make_tool_context(tool_result="Contains SECRET data")
        with pytest.raises(PolicyViolationError, match="SECRET"):
            hook_fn(ctx)

    def test_none_output_passes(self):
        """None tool result is allowed."""
        kernel = CrewAIKernel(GovernancePolicy(blocked_patterns=["bad"]))
        kernel.as_hooks()
        hook_fn = _registered_hooks["after_tool_call"][0]
        ctx = _make_tool_context(tool_result=None)
        result = hook_fn(ctx)
        assert result is None

    def test_non_string_output_passes(self):
        """Non-string tool result is passed through."""
        kernel = CrewAIKernel(GovernancePolicy(blocked_patterns=["bad"]))
        kernel.as_hooks()
        hook_fn = _registered_hooks["after_tool_call"][0]
        ctx = _make_tool_context(tool_result=42)
        result = hook_fn(ctx)
        assert result is None


# ═══════════════════════════════════════════════════════════════════
# Test before_llm_call
# ═══════════════════════════════════════════════════════════════════

class TestBeforeLLMCall:
    """Tests for before_llm_call governance hook."""

    def test_clean_messages_pass(self):
        """Messages without blocked patterns pass."""
        kernel = CrewAIKernel(GovernancePolicy(blocked_patterns=["hack"]))
        kernel.as_hooks()
        hook_fn = _registered_hooks["before_llm_call"][0]
        ctx = _make_llm_context(messages=[{"role": "user", "content": "Hello world"}])
        result = hook_fn(ctx)
        assert result is None

    def test_blocked_pattern_in_message_content(self):
        """Blocked pattern in message content blocks LLM call."""
        kernel = CrewAIKernel(GovernancePolicy(blocked_patterns=["hack"]))
        kernel.as_hooks()
        hook_fn = _registered_hooks["before_llm_call"][0]
        ctx = _make_llm_context(messages=[{"role": "user", "content": "try to hack the system"}])
        result = hook_fn(ctx)
        assert result is False

    def test_blocked_pattern_in_string_message(self):
        """Blocked pattern in a plain string message blocks LLM call."""
        kernel = CrewAIKernel(GovernancePolicy(blocked_patterns=["DROP"]))
        kernel.as_hooks()
        hook_fn = _registered_hooks["before_llm_call"][0]
        ctx = _make_llm_context(messages=["DROP TABLE users"])
        result = hook_fn(ctx)
        assert result is False

    def test_empty_messages_pass(self):
        """Empty message list is allowed."""
        kernel = CrewAIKernel(GovernancePolicy(blocked_patterns=["bad"]))
        kernel.as_hooks()
        hook_fn = _registered_hooks["before_llm_call"][0]
        ctx = _make_llm_context(messages=[])
        result = hook_fn(ctx)
        assert result is None

    def test_none_messages_pass(self):
        """None messages are allowed."""
        kernel = CrewAIKernel(GovernancePolicy(blocked_patterns=["bad"]))
        kernel.as_hooks()
        hook_fn = _registered_hooks["before_llm_call"][0]
        ctx = _make_llm_context(messages=None)
        result = hook_fn(ctx)
        assert result is None

    def test_cedar_deny_blocks_llm_input(self):
        """Cedar evaluator deny blocks LLM call."""
        evaluator = MagicMock()
        evaluator.evaluate.return_value = MagicMock(allowed=False, reason="Cedar denied")
        kernel = CrewAIKernel(GovernancePolicy(), evaluator=evaluator)
        kernel.as_hooks()
        hook_fn = _registered_hooks["before_llm_call"][0]
        ctx = _make_llm_context(messages=[{"role": "user", "content": "Hello"}])
        result = hook_fn(ctx)
        assert result is False

    def test_message_with_object_content(self):
        """Message objects with .content attribute are scanned."""
        kernel = CrewAIKernel(GovernancePolicy(blocked_patterns=["FORBIDDEN"]))
        kernel.as_hooks()
        hook_fn = _registered_hooks["before_llm_call"][0]
        msg = MagicMock()
        msg.content = "This is FORBIDDEN content"
        ctx = _make_llm_context(messages=[msg])
        result = hook_fn(ctx)
        assert result is False


# ═══════════════════════════════════════════════════════════════════
# Test after_llm_call
# ═══════════════════════════════════════════════════════════════════

class TestAfterLLMCall:
    """Tests for after_llm_call governance hook."""

    def test_clean_response_passes(self):
        """Clean LLM response passes through."""
        kernel = CrewAIKernel(GovernancePolicy(blocked_patterns=["SECRET"]))
        kernel.as_hooks()
        hook_fn = _registered_hooks["after_llm_call"][0]
        ctx = _make_llm_context(response="Normal response text")
        result = hook_fn(ctx)
        assert result is None

    def test_blocked_pattern_in_response_raises(self):
        """Blocked pattern in LLM response raises PolicyViolationError."""
        kernel = CrewAIKernel(GovernancePolicy(blocked_patterns=["SECRET"]))
        kernel.as_hooks()
        hook_fn = _registered_hooks["after_llm_call"][0]
        ctx = _make_llm_context(response="Contains SECRET data")
        with pytest.raises(PolicyViolationError, match="SECRET"):
            hook_fn(ctx)

    def test_none_response_passes(self):
        """None response is allowed."""
        kernel = CrewAIKernel(GovernancePolicy(blocked_patterns=["bad"]))
        kernel.as_hooks()
        hook_fn = _registered_hooks["after_llm_call"][0]
        ctx = _make_llm_context(response=None)
        result = hook_fn(ctx)
        assert result is None

    def test_empty_response_passes(self):
        """Empty/whitespace response is allowed."""
        kernel = CrewAIKernel(GovernancePolicy(blocked_patterns=["bad"]))
        kernel.as_hooks()
        hook_fn = _registered_hooks["after_llm_call"][0]
        ctx = _make_llm_context(response="   ")
        result = hook_fn(ctx)
        assert result is None

    def test_non_string_response_passes(self):
        """Non-string response is passed through."""
        kernel = CrewAIKernel(GovernancePolicy(blocked_patterns=["bad"]))
        kernel.as_hooks()
        hook_fn = _registered_hooks["after_llm_call"][0]
        ctx = _make_llm_context(response=42)
        result = hook_fn(ctx)
        assert result is None


# ═══════════════════════════════════════════════════════════════════
# Test as_hooks() Integration
# ═══════════════════════════════════════════════════════════════════

class TestAsHooksIntegration:
    """Tests for the as_hooks() factory and integration patterns."""

    def test_tool_then_llm_flow(self):
        """Full flow: tool call followed by LLM call, both governed."""
        kernel = CrewAIKernel(GovernancePolicy(
            blocked_patterns=["DANGER"],
            allowed_tools=["search"],
        ))
        kernel.as_hooks()

        bt_fn = _registered_hooks["before_tool_call"][0]
        at_fn = _registered_hooks["after_tool_call"][0]
        bl_fn = _registered_hooks["before_llm_call"][0]
        al_fn = _registered_hooks["after_llm_call"][0]

        # Tool call OK
        tool_ctx = _make_tool_context(tool_name="search")
        assert bt_fn(tool_ctx) is None
        tool_ctx.tool_result = "safe result"
        assert at_fn(tool_ctx) is None

        # LLM call OK
        llm_ctx = _make_llm_context(
            messages=[{"role": "user", "content": "summarize results"}],
            response="Here is the summary",
        )
        assert bl_fn(llm_ctx) is None
        assert al_fn(llm_ctx) is None

    def test_cedar_evaluator_passed_through(self):
        """Cedar evaluator on kernel is used for tool pre_execute."""
        evaluator = MagicMock()
        evaluator.evaluate.return_value = MagicMock(allowed=True, reason="")
        kernel = CrewAIKernel(GovernancePolicy(), evaluator=evaluator)
        kernel.as_hooks()
        hook_fn = _registered_hooks["before_tool_call"][0]
        ctx = _make_tool_context()
        result = hook_fn(ctx)
        assert result is None  # permitted

    def test_multiple_hooks_independent(self):
        """Multiple as_hooks() calls create independent registrations."""
        k1 = CrewAIKernel(GovernancePolicy(allowed_tools=["a"]))
        k2 = CrewAIKernel(GovernancePolicy(allowed_tools=["b"]))
        k1.as_hooks(name="h1")
        k2.as_hooks(name="h2")
        # Both should be registered (2 each)
        assert len(_registered_hooks["before_tool_call"]) == 2

    def test_shared_kernel_state(self):
        """Multiple hooks from same kernel share call_count."""
        kernel = CrewAIKernel(GovernancePolicy())
        hooks1 = kernel.as_hooks(name="h1")
        hook_fn = _registered_hooks["before_tool_call"][0]
        ctx = _make_tool_context()
        hook_fn(ctx)
        assert hooks1.context.call_count == 1


# ═══════════════════════════════════════════════════════════════════
# Test Deprecation Warnings
# ═══════════════════════════════════════════════════════════════════

class TestDeprecationWarnings:
    """Tests that wrap() emit DeprecationWarning."""

    def test_wrap_emits_deprecation_warning(self):
        """CrewAIKernel.wrap() emits a DeprecationWarning."""
        kernel = CrewAIKernel(GovernancePolicy())
        crew = MagicMock()
        crew.id = "test-crew"
        crew.agents = []
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            kernel.wrap(crew)
            deprecation_warnings = [x for x in w if issubclass(x.category, DeprecationWarning)]
            assert len(deprecation_warnings) >= 1
            assert "as_hooks()" in str(deprecation_warnings[0].message)

    def test_module_wrap_emits_deprecation_warning(self):
        """Module-level wrap() emits a DeprecationWarning."""
        from agent_os.integrations.crewai_adapter import wrap
        crew = MagicMock()
        crew.id = "test-crew"
        crew.agents = []
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            wrap(crew)
            deprecation_warnings = [x for x in w if issubclass(x.category, DeprecationWarning)]
            assert len(deprecation_warnings) >= 1
            assert "as_hooks()" in str(deprecation_warnings[0].message)


# ═══════════════════════════════════════════════════════════════════
# Test Backward Compatibility
# ═══════════════════════════════════════════════════════════════════

class TestBackwardCompatibility:
    """Tests that the legacy wrap() API still works."""

    def test_wrap_kickoff_still_works(self):
        """Legacy wrap() + kickoff() still returns results."""
        kernel = CrewAIKernel(GovernancePolicy())
        crew = MagicMock()
        crew.id = "crew-42"
        crew.kickoff.return_value = "crew-result"
        crew.agents = []

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            governed = kernel.wrap(crew)
            result = governed.kickoff({"topic": "AI"})
            assert result == "crew-result"

    def test_wrap_blocks_on_policy_violation(self):
        """Legacy wrap() blocks on blocked pattern."""
        policy = GovernancePolicy(blocked_patterns=["hack"])
        kernel = CrewAIKernel(policy)
        crew = MagicMock()
        crew.id = "crew-42"
        crew.agents = []

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            governed = kernel.wrap(crew)
            with pytest.raises(PolicyViolationError):
                governed.kickoff({"input": "hack the system"})

    def test_unwrap_still_works(self):
        """unwrap() returns the original crew object."""
        kernel = CrewAIKernel(GovernancePolicy())
        crew = MagicMock()
        crew.id = "crew-42"
        crew.agents = []

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            governed = kernel.wrap(crew)
            assert kernel.unwrap(governed) is crew


