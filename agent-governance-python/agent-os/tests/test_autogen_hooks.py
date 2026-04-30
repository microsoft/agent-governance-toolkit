# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for AutoGen native GovernanceInterventionHandler.

Verifies that the ``GovernanceInterventionHandler`` correctly enforces
governance policies via AutoGen's native ``on_send``, ``on_publish``,
and ``on_response`` hooks, including:

* Tool call governance (allowlist, blocked patterns, max calls)
* Content filtering (blocked patterns, PII detection)
* Cedar/OPA policy evaluation integration
* Output governance and drift detection
* Deprecation warnings on legacy ``govern()`` / ``wrap()``
* Backward compatibility with legacy monkey-patching

These tests stub the ``autogen_core`` module to run without AutoGen
installed.
"""

import asyncio
import importlib
import re
import sys
import types
import warnings
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest


# ── Stub the autogen_core module before importing the adapter ────

class _DropMessage:
    """Sentinel for dropping messages in the intervention handler."""
    pass


class _FunctionCall:
    """Stub FunctionCall matching AutoGen v0.4+ signature."""

    def __init__(self, *, id: str = "fc-1", name: str = "", arguments: str = ""):
        self.id = id
        self.name = name
        self.arguments = arguments


# Build the stub module hierarchy
_autogen_core_mod = types.ModuleType("autogen_core")
_autogen_core_mod.DropMessage = _DropMessage
_autogen_core_mod.FunctionCall = _FunctionCall

_intervention_mod = types.ModuleType("autogen_core.intervention")


class _DefaultInterventionHandler:
    """Stub for DefaultInterventionHandler."""
    pass


_intervention_mod.DefaultInterventionHandler = _DefaultInterventionHandler

sys.modules.setdefault("autogen_core", _autogen_core_mod)
sys.modules.setdefault("autogen_core.intervention", _intervention_mod)

# Also stub llama_index so the module graph loads cleanly
for _m in [
    "llama_index", "llama_index.core", "llama_index.core.base",
    "llama_index.core.base.response", "llama_index.core.base.response.schema",
    "llama_index.core.indices", "llama_index.core.indices.prompt_helper",
    "llama_index.core.settings",
]:
    sys.modules.setdefault(_m, types.ModuleType(_m))

# Force-reload the adapter so it picks up our stubs
if "agent_os.integrations.autogen_adapter" in sys.modules:
    del sys.modules["agent_os.integrations.autogen_adapter"]
if "agent_os.integrations" in sys.modules:
    del sys.modules["agent_os.integrations"]

from agent_os.integrations.autogen_adapter import (
    AutoGenKernel,
    GovernanceInterventionHandler,
    _FUNCTION_CALL_AVAILABLE,
    _INTERVENTION_AVAILABLE,
)
from agent_os.integrations.base import GovernancePolicy, PolicyViolationError


# ═══════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════

def _run(coro):
    """Run an async coroutine synchronously."""
    return asyncio.get_event_loop().run_until_complete(coro)


def _make_kernel(**kwargs) -> AutoGenKernel:
    """Create a kernel with sensible test defaults."""
    return AutoGenKernel(**kwargs)


def _make_handler(
    policy: Optional[GovernancePolicy] = None, **kwargs
) -> GovernanceInterventionHandler:
    """Create a handler from a kernel with the given policy."""
    kernel = _make_kernel(policy=policy, **kwargs)
    return GovernanceInterventionHandler(kernel, **{
        k: v for k, v in kwargs.items()
        if k in ("name",)
    })


# ═══════════════════════════════════════════════════════════════════
# Test: Module-level detection
# ═══════════════════════════════════════════════════════════════════

class TestModuleDetection:
    """Verify that the adapter detects autogen_core availability."""

    def test_intervention_available(self):
        """The stub should make _INTERVENTION_AVAILABLE true."""
        assert _INTERVENTION_AVAILABLE is True

    def test_function_call_available(self):
        """The stub should make _FUNCTION_CALL_AVAILABLE true."""
        assert _FUNCTION_CALL_AVAILABLE is True


# ═══════════════════════════════════════════════════════════════════
# Test: as_handler() factory
# ═══════════════════════════════════════════════════════════════════

class TestAsHandler:
    """Verify as_handler() factory method."""

    def test_returns_handler(self):
        """as_handler() should return a GovernanceInterventionHandler."""
        kernel = _make_kernel()
        handler = kernel.as_handler()
        assert isinstance(handler, GovernanceInterventionHandler)

    def test_custom_name(self):
        """as_handler() should accept custom name."""
        kernel = _make_kernel()
        handler = kernel.as_handler(name="prod-governance")
        assert "prod-governance" in repr(handler)

    def test_handler_has_kernel(self):
        """Handler should reference the creating kernel."""
        kernel = _make_kernel()
        handler = kernel.as_handler()
        assert handler.kernel is kernel

    def test_handler_has_context(self):
        """Handler should have an execution context."""
        kernel = _make_kernel()
        handler = kernel.as_handler()
        assert handler.context is not None

    def test_as_handler_raises_without_autogen(self):
        """as_handler() should raise when autogen_core is missing."""
        import agent_os.integrations.autogen_adapter as mod
        original = mod._INTERVENTION_AVAILABLE
        try:
            mod._INTERVENTION_AVAILABLE = False
            kernel = _make_kernel()
            with pytest.raises(RuntimeError, match="autogen_core is not available"):
                kernel.as_handler()
        finally:
            mod._INTERVENTION_AVAILABLE = original


# ═══════════════════════════════════════════════════════════════════
# Test: on_send — FunctionCall governance
# ═══════════════════════════════════════════════════════════════════

class TestOnSendToolCalls:
    """Verify on_send() tool-call governance."""

    def test_allow_tool_call(self):
        """Allowed tool call passes through."""
        handler = _make_handler(policy=GovernancePolicy(
            allowed_tools=["search", "calculator"],
        ))
        fc = _FunctionCall(name="search", arguments='{"q": "hello"}')
        result = _run(handler.on_send(fc))
        assert result is fc

    def test_block_tool_not_in_allowlist(self):
        """Tool not in allowlist is dropped."""
        handler = _make_handler(policy=GovernancePolicy(
            allowed_tools=["search"],
        ))
        fc = _FunctionCall(name="execute_sql", arguments='{"sql": "SELECT 1"}')
        result = _run(handler.on_send(fc))
        assert result is _DropMessage

    def test_block_tool_name_pattern(self):
        """Blocked pattern in tool name causes drop."""
        handler = _make_handler(policy=GovernancePolicy(
            blocked_patterns=["delete"],
        ))
        fc = _FunctionCall(name="delete_user", arguments='{}')
        result = _run(handler.on_send(fc))
        assert result is _DropMessage

    def test_block_tool_args_pattern(self):
        """Blocked pattern in tool arguments causes drop."""
        handler = _make_handler(policy=GovernancePolicy(
            blocked_patterns=["DROP TABLE"],
        ))
        fc = _FunctionCall(name="sql_query", arguments="DROP TABLE users")
        result = _run(handler.on_send(fc))
        assert result is _DropMessage

    def test_allow_clean_tool_call(self):
        """Tool call with no violations passes through."""
        handler = _make_handler(policy=GovernancePolicy(
            blocked_patterns=["DROP TABLE"],
        ))
        fc = _FunctionCall(name="sql_query", arguments="SELECT * FROM users")
        result = _run(handler.on_send(fc))
        assert result is fc

    def test_max_tool_calls_exceeded(self):
        """Exceeding max tool calls drops the message."""
        handler = _make_handler(policy=GovernancePolicy(
            max_tool_calls=2,
        ))
        fc1 = _FunctionCall(name="t1", arguments="")
        fc2 = _FunctionCall(name="t2", arguments="")
        fc3 = _FunctionCall(name="t3", arguments="")

        assert _run(handler.on_send(fc1)) is fc1
        assert _run(handler.on_send(fc2)) is fc2
        assert _run(handler.on_send(fc3)) is _DropMessage

    def test_call_count_increments(self):
        """Call count should increment for each allowed tool call."""
        handler = _make_handler()
        fc = _FunctionCall(name="t1", arguments="")
        _run(handler.on_send(fc))
        _run(handler.on_send(fc))
        assert handler.context.call_count == 2

    def test_no_allowlist_allows_all(self):
        """Without an allowlist, all tools are allowed."""
        handler = _make_handler()
        fc = _FunctionCall(name="anything", arguments="")
        result = _run(handler.on_send(fc))
        assert result is fc


# ═══════════════════════════════════════════════════════════════════
# Test: on_send — content governance
# ═══════════════════════════════════════════════════════════════════

class TestOnSendContent:
    """Verify on_send() content governance for non-FunctionCall messages."""

    def test_allow_clean_string(self):
        """Clean string message passes through."""
        handler = _make_handler(policy=GovernancePolicy(
            blocked_patterns=["password"],
        ))
        result = _run(handler.on_send("Hello world"))
        assert result == "Hello world"

    def test_block_string_pattern(self):
        """Blocked pattern in string message causes drop."""
        handler = _make_handler(policy=GovernancePolicy(
            blocked_patterns=["DROP TABLE"],
        ))
        result = _run(handler.on_send("Let's DROP TABLE users"))
        assert result is _DropMessage

    def test_block_dict_content_pattern(self):
        """Blocked pattern in dict content causes drop."""
        handler = _make_handler(policy=GovernancePolicy(
            blocked_patterns=["secret"],
        ))
        result = _run(handler.on_send({"content": "This is a secret plan"}))
        assert result is _DropMessage

    def test_allow_dict_clean(self):
        """Clean dict message passes through."""
        handler = _make_handler(policy=GovernancePolicy(
            blocked_patterns=["DROP TABLE"],
        ))
        result = _run(handler.on_send({"content": "Hello world"}))
        assert result == {"content": "Hello world"}

    def test_block_pii_ssn(self):
        """SSN pattern in content causes drop."""
        handler = _make_handler()
        result = _run(handler.on_send("My SSN is 123-45-6789"))
        assert result is _DropMessage

    def test_block_pii_email(self):
        """Email pattern in content causes drop."""
        handler = _make_handler()
        result = _run(handler.on_send("Contact me at user@example.com"))
        assert result is _DropMessage

    def test_block_pii_api_key(self):
        """API key pattern in content causes drop."""
        handler = _make_handler()
        result = _run(handler.on_send("api_key=sk-abc123def456"))
        assert result is _DropMessage

    def test_object_with_content_attr(self):
        """Object with a content attribute is scanned."""
        handler = _make_handler(policy=GovernancePolicy(
            blocked_patterns=["malicious"],
        ))
        msg = MagicMock()
        msg.content = "This is malicious code"
        result = _run(handler.on_send(msg))
        assert result is _DropMessage


# ═══════════════════════════════════════════════════════════════════
# Test: on_publish — broadcast governance
# ═══════════════════════════════════════════════════════════════════

class TestOnPublish:
    """Verify on_publish() broadcast governance."""

    def test_allow_clean_publish(self):
        """Clean published message passes through."""
        handler = _make_handler(policy=GovernancePolicy(
            blocked_patterns=["blocked"],
        ))
        result = _run(handler.on_publish("Hello all agents"))
        assert result == "Hello all agents"

    def test_block_publish_pattern(self):
        """Blocked pattern in published message causes drop."""
        handler = _make_handler(policy=GovernancePolicy(
            blocked_patterns=["blocked"],
        ))
        result = _run(handler.on_publish("This is blocked content"))
        assert result is _DropMessage

    def test_block_publish_pii(self):
        """PII in published message causes drop."""
        handler = _make_handler()
        result = _run(handler.on_publish("SSN: 123-45-6789"))
        assert result is _DropMessage

    def test_allow_empty_message(self):
        """Empty message passes through."""
        handler = _make_handler()
        result = _run(handler.on_publish(""))
        assert result == ""

    def test_publish_dict_content(self):
        """Dict content is scanned."""
        handler = _make_handler(policy=GovernancePolicy(
            blocked_patterns=["danger"],
        ))
        result = _run(handler.on_publish({"content": "danger zone"}))
        assert result is _DropMessage


# ═══════════════════════════════════════════════════════════════════
# Test: on_response — output governance
# ═══════════════════════════════════════════════════════════════════

class TestOnResponse:
    """Verify on_response() output governance."""

    def test_allow_clean_response(self):
        """Clean response passes through."""
        handler = _make_handler(policy=GovernancePolicy(
            blocked_patterns=["blocked"],
        ))
        result = _run(handler.on_response("The answer is 42"))
        assert result == "The answer is 42"

    def test_block_response_pattern(self):
        """Blocked pattern in response causes drop."""
        handler = _make_handler(policy=GovernancePolicy(
            blocked_patterns=["blocked"],
        ))
        result = _run(handler.on_response("This is blocked output"))
        assert result is _DropMessage

    def test_response_calls_post_execute(self):
        """on_response should invoke post_execute for drift detection."""
        handler = _make_handler()
        with patch.object(
            handler._kernel, "post_execute", return_value=(True, None)
        ) as mock_post:
            _run(handler.on_response("some response"))
            mock_post.assert_called_once()

    def test_response_drift_blocks(self):
        """post_execute returning (False, reason) should drop."""
        handler = _make_handler()
        with patch.object(
            handler._kernel, "post_execute",
            return_value=(False, "drift detected"),
        ):
            result = _run(handler.on_response("drifted output"))
            assert result is _DropMessage


# ═══════════════════════════════════════════════════════════════════
# Test: Cedar/OPA integration
# ═══════════════════════════════════════════════════════════════════

class TestCedarIntegration:
    """Verify Cedar/OPA policy evaluation via pre_execute."""

    def test_cedar_deny_blocks_tool(self):
        """Cedar deny on pre_execute should drop the FunctionCall."""
        handler = _make_handler()
        with patch.object(
            handler._kernel, "pre_execute",
            return_value=(False, "cedar: action denied"),
        ):
            fc = _FunctionCall(name="search", arguments="")
            result = _run(handler.on_send(fc))
            assert result is _DropMessage

    def test_cedar_allow_passes_tool(self):
        """Cedar allow on pre_execute should pass the FunctionCall."""
        handler = _make_handler()
        with patch.object(
            handler._kernel, "pre_execute",
            return_value=(True, None),
        ):
            fc = _FunctionCall(name="search", arguments="")
            result = _run(handler.on_send(fc))
            assert result is fc

    def test_cedar_receives_tool_context(self):
        """pre_execute should receive tool_name and tool_args."""
        handler = _make_handler()
        received_ctx = {}

        def capture_pre_execute(ctx, details):
            received_ctx.update(details)
            return True, None

        with patch.object(
            handler._kernel, "pre_execute", side_effect=capture_pre_execute
        ):
            fc = _FunctionCall(name="do_search", arguments='{"q":"test"}')
            _run(handler.on_send(fc))
            assert received_ctx["tool_name"] == "do_search"
            assert received_ctx["tool_args"] == '{"q":"test"}'


# ═══════════════════════════════════════════════════════════════════
# Test: Deprecation warnings
# ═══════════════════════════════════════════════════════════════════

class TestDeprecationWarnings:
    """Verify that legacy methods emit deprecation warnings."""

    def test_wrap_warns(self):
        """wrap() should emit DeprecationWarning."""
        kernel = _make_kernel()
        agent = MagicMock()
        agent.name = "test-agent"
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            kernel.wrap(agent)
            dep_warnings = [x for x in w if issubclass(x.category, DeprecationWarning)]
            assert len(dep_warnings) >= 1
            assert "as_handler()" in str(dep_warnings[0].message)

    def test_govern_warns(self):
        """govern() should emit DeprecationWarning."""
        kernel = _make_kernel()
        agent = MagicMock()
        agent.name = "test-agent"
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            kernel.govern(agent)
            dep_warnings = [x for x in w if issubclass(x.category, DeprecationWarning)]
            assert len(dep_warnings) >= 1
            assert "as_handler()" in str(dep_warnings[0].message)

    def test_module_govern_warns(self):
        """Module-level govern() should emit DeprecationWarning."""
        from agent_os.integrations.autogen_adapter import govern
        agent = MagicMock()
        agent.name = "test-agent"
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            govern(agent)
            dep_warnings = [x for x in w if issubclass(x.category, DeprecationWarning)]
            assert len(dep_warnings) >= 1
            assert "as_handler()" in str(dep_warnings[0].message)


# ═══════════════════════════════════════════════════════════════════
# Test: Legacy backward compatibility
# ═══════════════════════════════════════════════════════════════════

class TestLegacyBackwardCompat:
    """Verify that the legacy govern() still works functionally."""

    def test_govern_patches_initiate_chat(self):
        """Legacy govern() should monkey-patch initiate_chat."""
        kernel = _make_kernel()
        agent = MagicMock()
        agent.name = "test-agent"
        original_chat = agent.initiate_chat

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            kernel.govern(agent)

        # initiate_chat should be patched
        assert agent.initiate_chat is not original_chat

    def test_govern_patches_generate_reply(self):
        """Legacy govern() should monkey-patch generate_reply."""
        kernel = _make_kernel()
        agent = MagicMock()
        agent.name = "test-agent"
        original_reply = agent.generate_reply

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            kernel.govern(agent)

        assert agent.generate_reply is not original_reply

    def test_unwrap_restores_methods(self):
        """unwrap() should restore original methods."""
        kernel = _make_kernel()
        agent = MagicMock()
        agent.name = "test-agent"
        original_chat = agent.initiate_chat

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            kernel.govern(agent)

        kernel.unwrap(agent)
        assert agent.initiate_chat is original_chat

    def test_govern_blocks_pattern_in_chat(self):
        """Legacy govern should block patterns in initiate_chat."""
        kernel = _make_kernel(policy=GovernancePolicy(
            blocked_patterns=["DROP TABLE"],
        ))
        agent = MagicMock()
        agent.name = "test-agent"

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            kernel.govern(agent)

        with pytest.raises(PolicyViolationError):
            agent.initiate_chat(MagicMock(), message="DROP TABLE users")

    def test_signal_sigstop(self):
        """SIGSTOP should block governed agent operations."""
        kernel = _make_kernel()
        agent = MagicMock()
        agent.name = "test-agent"

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            kernel.govern(agent)

        kernel.signal("test-agent", "SIGSTOP")

        with pytest.raises(PolicyViolationError, match="SIGSTOP"):
            agent.initiate_chat(MagicMock(), message="hello")

    def test_signal_sigcont_resumes(self):
        """SIGCONT should resume a stopped agent."""
        kernel = _make_kernel()
        agent = MagicMock()
        agent.name = "test-agent"

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            kernel.govern(agent)

        kernel.signal("test-agent", "SIGSTOP")
        kernel.signal("test-agent", "SIGCONT")

        # Should NOT raise — agent is resumed
        agent.initiate_chat(MagicMock(), message="hello")

    def test_health_check_returns_dict(self):
        """health_check() should return status dict."""
        kernel = _make_kernel()
        health = kernel.health_check()
        assert health["status"] == "healthy"
        assert health["backend"] == "autogen"


# ═══════════════════════════════════════════════════════════════════
# Test: Content extraction helper
# ═══════════════════════════════════════════════════════════════════

class TestExtractContent:
    """Verify the static _extract_content helper."""

    def test_string(self):
        assert GovernanceInterventionHandler._extract_content("hello") == "hello"

    def test_dict_with_content(self):
        assert GovernanceInterventionHandler._extract_content(
            {"content": "hi"}
        ) == "hi"

    def test_dict_without_content(self):
        assert GovernanceInterventionHandler._extract_content(
            {"role": "user"}
        ) == ""

    def test_object_with_content(self):
        obj = MagicMock()
        obj.content = "from object"
        assert GovernanceInterventionHandler._extract_content(obj) == "from object"

    def test_none(self):
        assert GovernanceInterventionHandler._extract_content(None) == ""

    def test_int(self):
        # Integer has no content attr and is not a str/dict
        assert GovernanceInterventionHandler._extract_content(42) == ""
