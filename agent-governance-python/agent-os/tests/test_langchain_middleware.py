# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for LangChain GovernanceMiddleware (native AgentMiddleware).

Covers:
- GovernanceMiddleware.wrap_tool_call  (tool-level governance)
- GovernanceMiddleware.wrap_model_call (model-level governance)
- LangChainKernel.as_middleware()      (factory method)
- Deprecation warnings on wrap() and module-level wrap()
- Backward compatibility of existing wrap() API

Run with: python -m pytest tests/test_langchain_middleware.py -v --tb=short
"""

import warnings
from datetime import datetime, timedelta
from unittest.mock import MagicMock

import pytest

from agent_os.integrations.langchain_adapter import (
    GovernanceMiddleware,
    LangChainKernel,
    PolicyViolationError,
    wrap as module_wrap,
)
from agent_os.integrations.base import GovernancePolicy


# =============================================================================
# Helpers
# =============================================================================


def _make_kernel(**policy_kw) -> LangChainKernel:
    """Create a LangChainKernel with the given policy overrides."""
    return LangChainKernel(policy=GovernancePolicy(**policy_kw))


def _make_tool_request(name="get_weather", args=None):
    """Create a mock LangChain ToolCallRequest."""
    req = MagicMock()
    req.tool_call = {
        "name": name,
        "args": args or {"city": "NY"},
        "id": "call_001",
    }
    return req


def _make_model_request(messages=None, tools=None):
    """Create a mock LangChain ModelRequest."""
    req = MagicMock()
    if messages is None:
        msg = MagicMock()
        msg.content = "Hello, what is the weather?"
        messages = [msg]
    req.messages = messages
    req.tools = tools or []
    req.system_message = MagicMock()
    req.system_message.content_blocks = []
    return req


def _make_tool_result(content="sunny, 72F"):
    """Create a mock tool result (ToolMessage)."""
    result = MagicMock()
    result.content = content
    return result


def _make_model_response(content="The weather is sunny."):
    """Create a mock model response."""
    resp = MagicMock()
    resp.message = MagicMock()
    resp.message.content = content
    return resp


# =============================================================================
# GovernanceMiddleware — Construction / Properties
# =============================================================================


class TestGovernanceMiddlewareInit:
    """Tests for GovernanceMiddleware construction and properties."""

    def test_as_middleware_returns_middleware_instance(self):
        kernel = _make_kernel()
        mw = kernel.as_middleware()
        assert isinstance(mw, GovernanceMiddleware)

    def test_as_middleware_custom_name(self):
        kernel = _make_kernel()
        mw = kernel.as_middleware(name="custom")
        assert mw._name == "custom"

    def test_kernel_property(self):
        kernel = _make_kernel()
        mw = kernel.as_middleware()
        assert mw.kernel is kernel

    def test_context_property(self):
        kernel = _make_kernel()
        mw = kernel.as_middleware()
        assert mw.context is not None
        assert mw.context.agent_id == "langchain-middleware-governance"

    def test_repr(self):
        kernel = _make_kernel()
        mw = kernel.as_middleware()
        r = repr(mw)
        assert "GovernanceMiddleware" in r
        assert "governance" in r

    def test_context_has_correct_policy(self):
        kernel = _make_kernel(max_tokens=2048)
        mw = kernel.as_middleware()
        assert mw.context.policy.max_tokens == 2048

    def test_multiple_middleware_are_independent(self):
        kernel = _make_kernel()
        mw1 = kernel.as_middleware(name="mw1")
        mw2 = kernel.as_middleware(name="mw2")
        assert mw1._name != mw2._name
        assert mw1.context.agent_id != mw2.context.agent_id


# =============================================================================
# GovernanceMiddleware.wrap_tool_call
# =============================================================================


class TestWrapToolCall:
    """Tests for tool-level governance via wrap_tool_call."""

    def test_allowed_tool_passes(self):
        """Tool execution succeeds when policy allows it."""
        kernel = _make_kernel()
        mw = kernel.as_middleware()
        request = _make_tool_request("get_weather", {"city": "Seattle"})
        handler = MagicMock(return_value=_make_tool_result("rainy, 55F"))

        result = mw.wrap_tool_call(request, handler)

        handler.assert_called_once_with(request)
        assert result.content == "rainy, 55F"

    def test_blocked_pattern_in_args_raises(self):
        """Tool args containing a blocked pattern trigger denial."""
        kernel = _make_kernel(blocked_patterns=["DROP TABLE"])
        mw = kernel.as_middleware()
        request = _make_tool_request("sql_query", {"query": "DROP TABLE users"})
        handler = MagicMock()

        with pytest.raises(PolicyViolationError, match="Blocked pattern"):
            mw.wrap_tool_call(request, handler)

        handler.assert_not_called()

    def test_blocked_tool_name_raises(self):
        """Tool whose name matches a blocked pattern is denied."""
        kernel = _make_kernel(blocked_patterns=["delete_all"])
        mw = kernel.as_middleware()
        request = _make_tool_request("delete_all_records")
        handler = MagicMock()

        with pytest.raises(PolicyViolationError, match="delete_all"):
            mw.wrap_tool_call(request, handler)

    def test_allowed_tools_enforcement(self):
        """Tool not in the allowlist is denied."""
        kernel = _make_kernel(allowed_tools=["get_weather", "search"])
        mw = kernel.as_middleware()
        request = _make_tool_request("execute_code")
        handler = MagicMock()

        with pytest.raises(PolicyViolationError, match="not in allowed list"):
            mw.wrap_tool_call(request, handler)

    def test_allowed_tools_pass_when_listed(self):
        """Tool in the allowlist is permitted."""
        kernel = _make_kernel(allowed_tools=["get_weather", "search"])
        mw = kernel.as_middleware()
        request = _make_tool_request("get_weather")
        handler = MagicMock(return_value=_make_tool_result())

        result = mw.wrap_tool_call(request, handler)
        handler.assert_called_once()
        assert result is not None

    def test_tool_invocation_recorded(self):
        """Tool invocations are logged to the audit trail."""
        kernel = _make_kernel()
        mw = kernel.as_middleware()
        request = _make_tool_request("calculator", {"expr": "2+2"})
        handler = MagicMock(return_value=_make_tool_result("4"))

        mw.wrap_tool_call(request, handler)

        assert len(kernel._tool_invocations) == 1
        assert kernel._tool_invocations[0]["tool_name"] == "calculator"

    def test_post_execute_blocks_on_output_violation(self):
        """Post-execution check catches blocked patterns in tool output."""
        kernel = _make_kernel(blocked_patterns=["secret_key"])
        mw = kernel.as_middleware()
        request = _make_tool_request("read_config")
        handler = MagicMock(
            return_value=_make_tool_result("api_secret_key=abc123")
        )

        with pytest.raises(PolicyViolationError, match="secret_key"):
            mw.wrap_tool_call(request, handler)

    def test_tool_exception_records_error(self):
        """Tool exceptions are recorded in the kernel's last_error."""
        kernel = _make_kernel()
        mw = kernel.as_middleware()
        request = _make_tool_request("failing_tool")
        handler = MagicMock(side_effect=RuntimeError("tool crashed"))

        with pytest.raises(RuntimeError, match="tool crashed"):
            mw.wrap_tool_call(request, handler)

        assert kernel._last_error == "tool crashed"

    def test_call_count_incremented(self):
        """Each tool call increments the execution context call count."""
        kernel = _make_kernel()
        mw = kernel.as_middleware()
        handler = MagicMock(return_value=_make_tool_result())

        mw.wrap_tool_call(_make_tool_request(), handler)
        mw.wrap_tool_call(_make_tool_request(), handler)

        # post_execute increments call_count
        assert mw.context.call_count == 2

    def test_max_tool_calls_blocks_after_limit(self):
        """Tool calls are blocked after max_tool_calls is reached."""
        kernel = _make_kernel(max_tool_calls=1)
        mw = kernel.as_middleware()
        handler = MagicMock(return_value=_make_tool_result())

        # First call succeeds — post_execute increments to 1
        mw.wrap_tool_call(_make_tool_request(), handler)

        # Second call blocked by pre_execute check
        with pytest.raises(PolicyViolationError, match="Max tool calls"):
            mw.wrap_tool_call(_make_tool_request(), handler)

    def test_non_dict_tool_call_handled(self):
        """Gracefully handles non-dict tool_call attribute."""
        kernel = _make_kernel()
        mw = kernel.as_middleware()
        request = MagicMock()
        request.tool_call = "plain_string_tool"
        handler = MagicMock(return_value=_make_tool_result())

        result = mw.wrap_tool_call(request, handler)
        handler.assert_called_once()

    def test_missing_tool_call_attr_handled(self):
        """Gracefully handles request without tool_call attribute."""
        kernel = _make_kernel()
        mw = kernel.as_middleware()
        request = MagicMock(spec=[])  # no attributes
        handler = MagicMock(return_value=_make_tool_result())

        result = mw.wrap_tool_call(request, handler)
        handler.assert_called_once()


# =============================================================================
# GovernanceMiddleware.wrap_model_call
# =============================================================================


class TestWrapModelCall:
    """Tests for model-level governance via wrap_model_call."""

    def test_allowed_model_call_passes(self):
        """Model call succeeds when policy allows the input."""
        kernel = _make_kernel()
        mw = kernel.as_middleware()
        request = _make_model_request()
        handler = MagicMock(return_value=_make_model_response())

        result = mw.wrap_model_call(request, handler)

        handler.assert_called_once_with(request)
        assert result.message.content == "The weather is sunny."

    def test_blocked_pattern_in_model_input_raises(self):
        """Blocked pattern in input messages triggers denial."""
        kernel = _make_kernel(blocked_patterns=["password"])
        mw = kernel.as_middleware()
        msg = MagicMock()
        msg.content = "My password is hunter2"
        request = _make_model_request(messages=[msg])
        handler = MagicMock()

        with pytest.raises(PolicyViolationError, match="password"):
            mw.wrap_model_call(request, handler)

        handler.assert_not_called()

    def test_blocked_pattern_in_model_output_raises(self):
        """Blocked pattern in model output triggers post-execution denial."""
        kernel = _make_kernel(blocked_patterns=["SSN"])
        mw = kernel.as_middleware()
        request = _make_model_request()
        handler = MagicMock(
            return_value=_make_model_response("Your SSN is 123-45-6789")
        )

        with pytest.raises(PolicyViolationError, match="SSN"):
            mw.wrap_model_call(request, handler)

    def test_model_call_with_list_content(self):
        """Model call with list-type content blocks works correctly."""
        kernel = _make_kernel()
        mw = kernel.as_middleware()
        msg = MagicMock()
        msg.content = [
            {"type": "text", "text": "What is the weather?"},
            {"type": "image", "url": "http://example.com/img.png"},
        ]
        request = _make_model_request(messages=[msg])
        handler = MagicMock(return_value=_make_model_response())

        result = mw.wrap_model_call(request, handler)
        handler.assert_called_once()

    def test_model_call_blocked_in_list_content(self):
        """Blocked pattern in list content blocks triggers denial."""
        kernel = _make_kernel(blocked_patterns=["secret"])
        mw = kernel.as_middleware()
        msg = MagicMock()
        msg.content = [{"type": "text", "text": "Reveal the secret code"}]
        request = _make_model_request(messages=[msg])
        handler = MagicMock()

        with pytest.raises(PolicyViolationError, match="secret"):
            mw.wrap_model_call(request, handler)

    def test_model_exception_records_error(self):
        """Model call exceptions are recorded in the kernel."""
        kernel = _make_kernel()
        mw = kernel.as_middleware()
        request = _make_model_request()
        handler = MagicMock(side_effect=RuntimeError("API error"))

        with pytest.raises(RuntimeError, match="API error"):
            mw.wrap_model_call(request, handler)

        assert kernel._last_error == "API error"

    def test_empty_messages_pass(self):
        """Model call with no messages passes without content check."""
        kernel = _make_kernel(blocked_patterns=["secret"])
        mw = kernel.as_middleware()
        request = _make_model_request(messages=[])
        handler = MagicMock(return_value=_make_model_response("safe output"))

        result = mw.wrap_model_call(request, handler)
        handler.assert_called_once()

    def test_none_messages_pass(self):
        """Model call with None messages attribute passes."""
        kernel = _make_kernel()
        mw = kernel.as_middleware()
        request = MagicMock()
        request.messages = None
        handler = MagicMock(return_value=_make_model_response("result"))

        result = mw.wrap_model_call(request, handler)
        handler.assert_called_once()

    def test_model_response_non_string_content(self):
        """Model response with non-string content is handled gracefully."""
        kernel = _make_kernel()
        mw = kernel.as_middleware()
        request = _make_model_request()
        resp = MagicMock()
        resp.message = MagicMock()
        resp.message.content = [{"type": "tool_use", "name": "search"}]
        handler = MagicMock(return_value=resp)

        result = mw.wrap_model_call(request, handler)
        handler.assert_called_once()
        # Should not raise — non-string content is skipped


# =============================================================================
# LangChainKernel.as_middleware() integration
# =============================================================================


class TestAsMiddlewareIntegration:
    """Tests for the as_middleware() factory and combined flows."""

    def test_tool_then_model_flow(self):
        """End-to-end: tool call followed by model call both pass."""
        kernel = _make_kernel()
        mw = kernel.as_middleware()

        # Tool call
        tool_req = _make_tool_request("search", {"query": "AI safety"})
        tool_handler = MagicMock(
            return_value=_make_tool_result("AI safety research")
        )
        mw.wrap_tool_call(tool_req, tool_handler)

        # Model call
        model_req = _make_model_request()
        model_handler = MagicMock(
            return_value=_make_model_response("Here are the results.")
        )
        mw.wrap_model_call(model_req, model_handler)

        assert mw.context.call_count >= 2

    def test_cedar_evaluator_passed_through(self):
        """Cedar evaluator on the kernel is accessible via the middleware."""
        mock_evaluator = MagicMock()
        kernel = LangChainKernel(evaluator=mock_evaluator)
        mw = kernel.as_middleware()
        assert mw.kernel._evaluator is mock_evaluator

    def test_as_middleware_returns_new_instance_each_call(self):
        """Each call to as_middleware() returns a fresh middleware."""
        kernel = _make_kernel()
        mw1 = kernel.as_middleware()
        mw2 = kernel.as_middleware()
        assert mw1 is not mw2

    def test_shared_kernel_state(self):
        """Multiple middleware instances share the kernel's audit state."""
        kernel = _make_kernel()
        mw1 = kernel.as_middleware(name="mw1")
        mw2 = kernel.as_middleware(name="mw2")

        tool_handler = MagicMock(return_value=_make_tool_result())
        mw1.wrap_tool_call(_make_tool_request("tool_a"), tool_handler)
        mw2.wrap_tool_call(_make_tool_request("tool_b"), tool_handler)

        # Both recorded on the shared kernel
        assert len(kernel._tool_invocations) == 2


# =============================================================================
# Deprecation warnings
# =============================================================================


class TestDeprecationWarnings:
    """Verify that deprecated APIs emit DeprecationWarnings."""

    def test_wrap_emits_deprecation_warning(self):
        """LangChainKernel.wrap() emits a DeprecationWarning."""
        kernel = _make_kernel()
        chain = MagicMock()
        chain.invoke = MagicMock(return_value="result")
        chain.name = "test-chain"

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            kernel.wrap(chain)

        dep_warnings = [x for x in w if issubclass(x.category, DeprecationWarning)]
        assert len(dep_warnings) >= 1
        assert "as_middleware" in str(dep_warnings[0].message)

    def test_module_wrap_emits_deprecation_warning(self):
        """Module-level wrap() emits a DeprecationWarning."""
        chain = MagicMock()
        chain.invoke = MagicMock(return_value="result")
        chain.name = "test-chain"

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            module_wrap(chain)

        dep_warnings = [x for x in w if issubclass(x.category, DeprecationWarning)]
        # Should get at least 1 from module_wrap, and 1 from the inner .wrap()
        assert len(dep_warnings) >= 1


# =============================================================================
# Backward compatibility — existing wrap() still works
# =============================================================================


class TestBackwardCompatibility:
    """Ensure the deprecated wrap() API still functions correctly."""

    def test_wrap_invoke_still_works(self):
        """Deprecated wrap().invoke() still executes and returns results."""
        kernel = _make_kernel()
        chain = MagicMock()
        chain.invoke = MagicMock(return_value="invoke-result")
        chain.name = "legacy-chain"

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            governed = kernel.wrap(chain)

        result = governed.invoke("hello")
        assert result == "invoke-result"
        chain.invoke.assert_called_once_with("hello")

    def test_wrap_blocks_on_policy_violation(self):
        """Deprecated wrap() still enforces policy."""
        kernel = _make_kernel(blocked_patterns=["DROP TABLE"])
        chain = MagicMock()
        chain.invoke = MagicMock(return_value="ok")
        chain.name = "legacy-chain"

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            governed = kernel.wrap(chain)

        with pytest.raises(PolicyViolationError, match="Blocked pattern"):
            governed.invoke("please DROP TABLE users")

    def test_unwrap_still_works(self):
        """Deprecated unwrap() returns the original object."""
        kernel = _make_kernel()
        chain = MagicMock()
        chain.name = "chain"

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            governed = kernel.wrap(chain)

        assert kernel.unwrap(governed) is chain


# =============================================================================
# Health check
# =============================================================================


class TestHealthCheck:
    """Health check is unaffected by middleware changes."""

    def test_health_check_returns_healthy(self):
        kernel = _make_kernel()
        result = kernel.health_check()
        assert result["status"] == "healthy"
        assert result["backend"] == "langchain"
        assert result["backend_connected"] is True

    def test_health_check_degraded_after_error(self):
        kernel = _make_kernel()
        kernel._last_error = "something failed"
        result = kernel.health_check()
        assert result["status"] == "degraded"
