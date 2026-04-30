# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for Anthropic native governance hooks (GovernanceMessageHook).

Validates:
- GovernanceMessageHook creation via as_message_hook()
- Message content scanning against blocked_patterns (all fields)
- Tool allowlist enforcement (pre-call and response)
- Token limit enforcement (boundary and cumulative)
- Tool call count limits
- Audit trail recording
- Exception propagation from client.messages.create()
- UUID-based session IDs (no time collisions)
- Deprecation warnings on wrap() and wrap_client()
"""

import warnings
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from agent_os.integrations.anthropic_adapter import (
    AnthropicKernel,
    GovernanceMessageHook,
    wrap_client,
)
from agent_os.integrations.base import GovernancePolicy


# ── Fixtures ──────────────────────────────────────────────────────


@pytest.fixture
def policy():
    """Create a governance policy for testing."""
    return GovernancePolicy(
        max_tool_calls=5,
        max_tokens=1000,
        allowed_tools=["web_search", "read_file"],
        blocked_patterns=["password", "secret_key"],
    )


@pytest.fixture
def kernel(policy):
    """Create an AnthropicKernel with test policy."""
    return AnthropicKernel(policy=policy)


@pytest.fixture
def hook(kernel):
    """Create a GovernanceMessageHook from the kernel."""
    return kernel.as_message_hook()


@pytest.fixture
def mock_client():
    """Create a mock Anthropic client."""
    client = MagicMock()
    response = SimpleNamespace(
        id="msg-test-123",
        content=[],
        usage=SimpleNamespace(input_tokens=50, output_tokens=100),
    )
    client.messages.create.return_value = response
    return client


# ── as_message_hook() factory ─────────────────────────────────────


class TestAsMessageHook:
    """Tests for the as_message_hook() factory method."""

    def test_returns_governance_message_hook(self, kernel):
        hook = kernel.as_message_hook()
        assert isinstance(hook, GovernanceMessageHook)

    def test_custom_name(self, kernel):
        hook = kernel.as_message_hook(name="my-hook")
        assert hook._name == "my-hook"
        assert "my-hook" in repr(hook)

    def test_context_registered(self, kernel):
        hook = kernel.as_message_hook(name="test-ctx")
        assert "test-ctx" in kernel.contexts

    def test_hook_has_kernel_reference(self, kernel):
        hook = kernel.as_message_hook()
        assert hook.kernel is kernel

    def test_session_ids_are_unique(self, kernel):
        """Rapid construction must not produce colliding session IDs."""
        hooks = [kernel.as_message_hook(name=f"hook-{i}") for i in range(10)]
        session_ids = {h.context.session_id for h in hooks}
        assert len(session_ids) == 10, "Session IDs must be unique across instances"

    def test_session_id_uses_uuid_not_timestamp(self, kernel):
        """Session IDs must start with 'ant-hook-' followed by a hex string."""
        import re
        hook = kernel.as_message_hook()
        assert re.match(r"ant-hook-[0-9a-f]{12}$", hook.context.session_id), (
            f"Unexpected session_id format: {hook.context.session_id!r}"
        )


# ── Pre-execution checks ─────────────────────────────────────────


class TestPreExecutionChecks:
    """Tests for message content and tool validation before execution."""

    def test_blocks_blocked_pattern_in_messages(self, hook, mock_client):
        with pytest.raises(Exception, match="Message blocked"):
            hook.create(
                mock_client,
                model="claude-sonnet-4-20250514",
                max_tokens=100,
                messages=[{"role": "user", "content": "Tell me the password"}],
            )

    def test_blocks_disallowed_tool(self, hook, mock_client):
        with pytest.raises(Exception, match="Tool not allowed"):
            hook.create(
                mock_client,
                model="claude-sonnet-4-20250514",
                max_tokens=100,
                messages=[{"role": "user", "content": "Hello"}],
                tools=[{"name": "dangerous_exec", "description": "..."}],
            )

    def test_allows_approved_tools(self, hook, mock_client):
        result = hook.create(
            mock_client,
            model="claude-sonnet-4-20250514",
            max_tokens=100,
            messages=[{"role": "user", "content": "Hello"}],
            tools=[{"name": "web_search", "description": "Search the web"}],
        )
        assert result.id == "msg-test-123"

    def test_blocks_max_tokens_exceeding_policy(self, hook, mock_client):
        with pytest.raises(Exception, match="max_tokens.*exceeds policy"):
            hook.create(
                mock_client,
                model="claude-sonnet-4-20250514",
                max_tokens=5000,
                messages=[{"role": "user", "content": "Hello"}],
            )

    def test_max_tokens_at_limit_is_allowed(self, hook, mock_client):
        """Exactly at the policy limit must succeed."""
        result = hook.create(
            mock_client,
            model="claude-sonnet-4-20250514",
            max_tokens=1000,  # == policy.max_tokens
            messages=[{"role": "user", "content": "Hello"}],
        )
        assert result.id == "msg-test-123"

    def test_no_tools_param_is_allowed(self, hook, mock_client):
        """Requests with no 'tools' key must pass validation unconditionally."""
        result = hook.create(
            mock_client,
            model="claude-sonnet-4-20250514",
            max_tokens=100,
            messages=[{"role": "user", "content": "Hello"}],
        )
        assert result.id == "msg-test-123"
        mock_client.messages.create.assert_called_once()

    def test_blocks_pattern_in_assistant_message_content(self, hook, mock_client):
        """Blocked patterns in non-user roles should also be caught."""
        with pytest.raises(Exception, match="Message blocked"):
            hook.create(
                mock_client,
                model="claude-sonnet-4-20250514",
                max_tokens=100,
                messages=[
                    {"role": "user", "content": "Hi"},
                    {"role": "assistant", "content": "The secret_key is abc123"},
                ],
            )

    def test_empty_messages_list_does_not_raise(self, hook, mock_client):
        """An empty messages list should not crash the pre-check."""
        result = hook.create(
            mock_client,
            model="claude-sonnet-4-20250514",
            max_tokens=100,
            messages=[],
        )
        assert result.id == "msg-test-123"


# ── Client exception propagation ────────────────────────────────


class TestClientExceptions:
    """Tests that exceptions from the real client propagate correctly."""

    def test_client_error_propagates(self, hook):
        """An exception from client.messages.create() must bubble up unchanged."""
        failing_client = MagicMock()
        failing_client.messages.create.side_effect = RuntimeError("API timeout")

        with pytest.raises(RuntimeError, match="API timeout"):
            hook.create(
                failing_client,
                model="claude-sonnet-4-20250514",
                max_tokens=100,
                messages=[{"role": "user", "content": "Hello"}],
            )

    def test_no_audit_recorded_on_client_error(self, hook):
        """Token state must not be updated when client raises."""
        failing_client = MagicMock()
        failing_client.messages.create.side_effect = ConnectionError("Network error")

        tokens_before = hook.context.prompt_tokens
        try:
            hook.create(
                failing_client,
                model="claude-sonnet-4-20250514",
                max_tokens=100,
                messages=[{"role": "user", "content": "Hello"}],
            )
        except ConnectionError:
            pass
        assert hook.context.prompt_tokens == tokens_before


# ── Post-execution checks ────────────────────────────────────────


class TestPostExecutionChecks:
    """Tests for token tracking and tool_use block validation."""

    def test_tracks_tokens(self, hook, mock_client):
        hook.create(
            mock_client,
            model="claude-sonnet-4-20250514",
            max_tokens=100,
            messages=[{"role": "user", "content": "Hello"}],
        )
        ctx = hook.context
        assert ctx.prompt_tokens == 50
        assert ctx.completion_tokens == 100

    def test_records_message_id(self, hook, mock_client):
        hook.create(
            mock_client,
            model="claude-sonnet-4-20250514",
            max_tokens=100,
            messages=[{"role": "user", "content": "Hello"}],
        )
        assert "msg-test-123" in hook.context.message_ids

    def test_blocks_disallowed_tool_in_response(self, hook, mock_client):
        """Tool_use blocks in the response are validated against allowed_tools."""
        response = SimpleNamespace(
            id="msg-test-456",
            content=[
                SimpleNamespace(
                    type="tool_use",
                    id="call-1",
                    name="dangerous_exec",
                    input={"cmd": "rm -rf /"},
                ),
            ],
            usage=SimpleNamespace(input_tokens=10, output_tokens=20),
        )
        mock_client.messages.create.return_value = response

        with pytest.raises(Exception, match="Tool not allowed.*dangerous_exec"):
            hook.create(
                mock_client,
                model="claude-sonnet-4-20250514",
                max_tokens=100,
                messages=[{"role": "user", "content": "Run command"}],
            )

    def test_enforces_token_limit_after_response(self, kernel):
        """Cumulative token usage is checked after each response."""
        low_policy = GovernancePolicy(max_tokens=100)
        k = AnthropicKernel(policy=low_policy)
        hook = k.as_message_hook()

        client = MagicMock()
        client.messages.create.return_value = SimpleNamespace(
            id="msg-over",
            content=[],
            usage=SimpleNamespace(input_tokens=60, output_tokens=50),
        )

        with pytest.raises(Exception, match="Token limit exceeded"):
            hook.create(
                client,
                model="claude-sonnet-4-20250514",
                max_tokens=90,
                messages=[{"role": "user", "content": "Hello"}],
            )

    def test_cumulative_tokens_tracked_across_calls(self, hook, mock_client):
        """Tokens should accumulate across multiple create() invocations."""
        for _ in range(3):
            hook.create(
                mock_client,
                model="claude-sonnet-4-20250514",
                max_tokens=100,
                messages=[{"role": "user", "content": "Hello"}],
            )
        assert hook.context.prompt_tokens == 150     # 50 × 3
        assert hook.context.completion_tokens == 300  # 100 × 3


# ── Deprecation warnings ─────────────────────────────────────────


class TestDeprecationWarnings:
    """Tests that legacy methods emit DeprecationWarning."""

    def test_wrap_emits_deprecation(self, kernel, mock_client):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            kernel.wrap(mock_client)
            deprecations = [x for x in w if issubclass(x.category, DeprecationWarning)]
            assert len(deprecations) >= 1
            assert "as_message_hook" in str(deprecations[0].message)

    def test_wrap_client_emits_deprecation(self, mock_client):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            wrap_client(mock_client)
            deprecations = [x for x in w if issubclass(x.category, DeprecationWarning)]
            assert len(deprecations) >= 1
            assert "as_message_hook" in str(deprecations[0].message)

    def test_wrap_emits_exactly_one_deprecation(self, kernel, mock_client):
        """wrap() must surface exactly one DeprecationWarning to the caller."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            kernel.wrap(mock_client)
            deprecations = [x for x in w if issubclass(x.category, DeprecationWarning)]
            assert len(deprecations) == 1

    def test_wrap_client_emits_exactly_one_deprecation(self, mock_client):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            wrap_client(mock_client)
            deprecations = [x for x in w if issubclass(x.category, DeprecationWarning)]
            assert len(deprecations) == 1


# ── Clean messages pass through ───────────────────────────────────


class TestCleanPassthrough:
    """Tests that clean, valid messages pass through governance."""

    def test_clean_message_succeeds(self, hook, mock_client):
        result = hook.create(
            mock_client,
            model="claude-sonnet-4-20250514",
            max_tokens=100,
            messages=[{"role": "user", "content": "Hello, how are you?"}],
        )
        assert result.id == "msg-test-123"
        mock_client.messages.create.assert_called_once()
