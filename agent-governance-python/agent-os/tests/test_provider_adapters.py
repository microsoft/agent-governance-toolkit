# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for Anthropic, Gemini, and Mistral governance adapters.

All tests use mocks — no real API calls are made.
"""

from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock, patch

import pytest

from agent_os.integrations.base import GovernancePolicy

# ---------------------------------------------------------------------------
# Ensure optional SDK imports don't block test collection.  We mock the
# third-party libraries so tests run without installing them.
# ---------------------------------------------------------------------------

# --- Anthropic mock ---
_anthropic_mod = types.ModuleType("anthropic")
sys.modules.setdefault("anthropic", _anthropic_mod)

# --- google.generativeai mock ---
_google = types.ModuleType("google")
_google.__path__ = []  # package
_genai = types.ModuleType("google.generativeai")
sys.modules.setdefault("google", _google)
sys.modules.setdefault("google.generativeai", _genai)

# --- mistralai mock ---
_mistral_mod = types.ModuleType("mistralai")
sys.modules.setdefault("mistralai", _mistral_mod)

import agent_os.integrations.anthropic_adapter as _anthropic_adapter_mod
import agent_os.integrations.gemini_adapter as _gemini_adapter_mod

_anthropic_adapter_mod._HAS_ANTHROPIC = True
_gemini_adapter_mod._HAS_GENAI = True

from agent_os.integrations.anthropic_adapter import (  # noqa: E402
    AnthropicKernel,
    GovernedAnthropicClient,
    PolicyViolationError as AnthropicPolicyViolation,
    RequestCancelledException,
)
from agent_os.integrations.gemini_adapter import (  # noqa: E402
    GeminiKernel,
    GovernedGeminiModel,
    PolicyViolationError as GeminiPolicyViolation,
)
import agent_os.integrations.mistral_adapter as _mistral_adapter_mod

_mistral_adapter_mod._HAS_MISTRAL = True

from agent_os.integrations.mistral_adapter import (  # noqa: E402
    GovernedMistralClient,
    MistralKernel,
    PolicyViolationError as MistralPolicyViolation,
)


# ============================================================================
# Helpers
# ============================================================================


def _make_anthropic_response(
    input_tokens: int = 10,
    output_tokens: int = 20,
    content_blocks: list | None = None,
    response_id: str = "msg_abc123",
) -> MagicMock:
    resp = MagicMock()
    resp.id = response_id
    resp.usage.input_tokens = input_tokens
    resp.usage.output_tokens = output_tokens
    resp.content = content_blocks or []
    return resp


def _make_gemini_response(
    prompt_tokens: int = 10,
    candidate_tokens: int = 20,
    candidates: list | None = None,
) -> MagicMock:
    resp = MagicMock()
    resp.usage_metadata.prompt_token_count = prompt_tokens
    resp.usage_metadata.candidates_token_count = candidate_tokens
    resp.candidates = candidates or []
    return resp


def _make_mistral_response(
    prompt_tokens: int = 10,
    completion_tokens: int = 20,
    choices: list | None = None,
    response_id: str = "chatcmpl-xyz",
) -> MagicMock:
    resp = MagicMock()
    resp.id = response_id
    resp.usage.prompt_tokens = prompt_tokens
    resp.usage.completion_tokens = completion_tokens
    resp.choices = choices or []
    return resp


# ============================================================================
# Anthropic Adapter Tests
# ============================================================================


class TestAnthropicKernel:
    """Tests for the Anthropic Claude governance adapter."""

    def test_wrap_and_unwrap(self) -> None:
        """wrap() returns a governed client; unwrap() returns the original."""
        client = MagicMock()
        kernel = AnthropicKernel()
        governed = kernel.wrap(client)

        assert isinstance(governed, GovernedAnthropicClient)
        assert kernel.unwrap(governed) is client
        assert kernel.unwrap("plain") == "plain"

    def test_messages_create_happy_path(self) -> None:
        """A normal messages.create call should succeed and track tokens."""
        client = MagicMock()
        client.messages.create.return_value = _make_anthropic_response()

        kernel = AnthropicKernel()
        governed = kernel.wrap(client)
        resp = governed.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            messages=[{"role": "user", "content": "Hello"}],
        )

        assert resp.id == "msg_abc123"
        usage = governed.get_token_usage()
        assert usage["prompt_tokens"] == 10
        assert usage["completion_tokens"] == 20
        assert usage["total_tokens"] == 30

    def test_blocked_pattern_rejects_message(self) -> None:
        """Messages matching blocked patterns should be rejected."""
        policy = GovernancePolicy(blocked_patterns=["password"])
        kernel = AnthropicKernel(policy=policy)
        governed = kernel.wrap(MagicMock())

        with pytest.raises(AnthropicPolicyViolation, match="blocked"):
            governed.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=100,
                messages=[{"role": "user", "content": "my password is secret"}],
            )

    def test_max_tokens_policy_enforcement(self) -> None:
        """Requesting more tokens than the policy allows should fail."""
        policy = GovernancePolicy(max_tokens=100)
        kernel = AnthropicKernel(policy=policy)
        governed = kernel.wrap(MagicMock())

        with pytest.raises(AnthropicPolicyViolation, match="max_tokens"):
            governed.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=200,
                messages=[{"role": "user", "content": "Hello"}],
            )

    def test_cumulative_token_limit(self) -> None:
        """Exceeding the cumulative token limit should raise."""
        policy = GovernancePolicy(max_tokens=50)
        client = MagicMock()
        client.messages.create.return_value = _make_anthropic_response(
            input_tokens=30, output_tokens=25
        )

        kernel = AnthropicKernel(policy=policy)
        governed = kernel.wrap(client)

        with pytest.raises(AnthropicPolicyViolation, match="Token limit"):
            governed.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=50,
                messages=[{"role": "user", "content": "Hello"}],
            )

    def test_tool_call_validation(self) -> None:
        """Tool use blocks with disallowed tools should be rejected."""
        policy = GovernancePolicy(allowed_tools=["safe_tool"])
        client = MagicMock()

        tool_block = MagicMock()
        tool_block.type = "tool_use"
        tool_block.name = "dangerous_tool"
        tool_block.id = "tu_1"
        tool_block.input = {}

        client.messages.create.return_value = _make_anthropic_response(
            content_blocks=[tool_block]
        )

        kernel = AnthropicKernel(policy=policy)
        governed = kernel.wrap(client)

        with pytest.raises(AnthropicPolicyViolation, match="not allowed"):
            governed.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1024,
                messages=[{"role": "user", "content": "Use a tool"}],
            )

    def test_tool_definition_validation(self) -> None:
        """Passing disallowed tool definitions should be rejected."""
        policy = GovernancePolicy(allowed_tools=["safe_tool"])
        kernel = AnthropicKernel(policy=policy)
        governed = kernel.wrap(MagicMock())

        with pytest.raises(AnthropicPolicyViolation, match="not allowed"):
            governed.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=100,
                messages=[{"role": "user", "content": "Hello"}],
                tools=[{"name": "bad_tool", "description": "bad", "input_schema": {}}],
            )

    def test_sigkill_cancellation(self) -> None:
        """Cancelled request IDs should be tracked."""
        kernel = AnthropicKernel()
        governed = kernel.wrap(MagicMock())

        governed.sigkill("msg_123")
        assert kernel.is_cancelled("msg_123")
        assert not kernel.is_cancelled("msg_456")

    def test_health_check_healthy(self) -> None:
        """Health check should report healthy status."""
        kernel = AnthropicKernel()
        health = kernel.health_check()
        assert health["status"] == "healthy"
        assert health["backend"] == "anthropic"

    def test_health_check_degraded(self) -> None:
        """Health check should report degraded when last_error is set."""
        kernel = AnthropicKernel()
        kernel._last_error = "API error"
        health = kernel.health_check()
        assert health["status"] == "degraded"

    def test_audit_context(self) -> None:
        """Execution context should accumulate audit data."""
        client = MagicMock()
        client.messages.create.return_value = _make_anthropic_response()

        kernel = AnthropicKernel()
        governed = kernel.wrap(client)
        governed.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            messages=[{"role": "user", "content": "Hello"}],
        )

        ctx = governed.get_context()
        assert len(ctx.message_ids) == 1
        assert ctx.message_ids[0] == "msg_abc123"

    def test_api_error_sets_last_error(self) -> None:
        """Backend errors should be recorded for health reporting."""
        client = MagicMock()
        client.messages.create.side_effect = RuntimeError("Connection failed")

        kernel = AnthropicKernel()
        governed = kernel.wrap(client)

        with pytest.raises(RuntimeError):
            governed.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1024,
                messages=[{"role": "user", "content": "Hello"}],
            )

        assert kernel._last_error == "Connection failed"


# ============================================================================
# Gemini Adapter Tests
# ============================================================================


class TestGeminiKernel:
    """Tests for the Google Gemini governance adapter."""

    def test_wrap_and_unwrap(self) -> None:
        """wrap() returns a governed model; unwrap() returns the original."""
        model = MagicMock()
        model.model_name = "gemini-pro"
        kernel = GeminiKernel()
        governed = kernel.wrap(model)

        assert isinstance(governed, GovernedGeminiModel)
        assert kernel.unwrap(governed) is model
        assert kernel.unwrap("plain") == "plain"

    def test_generate_content_happy_path(self) -> None:
        """A normal generate_content call should succeed and track tokens."""
        model = MagicMock()
        model.model_name = "gemini-pro"
        model.generate_content.return_value = _make_gemini_response()

        kernel = GeminiKernel()
        governed = kernel.wrap(model)
        resp = governed.generate_content("Hello, Gemini!")

        model.generate_content.assert_called_once_with("Hello, Gemini!")
        usage = governed.get_token_usage()
        assert usage["prompt_tokens"] == 10
        assert usage["completion_tokens"] == 20

    def test_blocked_pattern_rejects_content(self) -> None:
        """Content matching blocked patterns should be rejected."""
        policy = GovernancePolicy(blocked_patterns=["secret"])
        kernel = GeminiKernel(policy=policy)
        governed = kernel.wrap(MagicMock(model_name="gemini-pro"))

        with pytest.raises(GeminiPolicyViolation, match="blocked"):
            governed.generate_content("Tell me the secret code")

    def test_cumulative_token_limit(self) -> None:
        """Exceeding the cumulative token limit should raise."""
        policy = GovernancePolicy(max_tokens=40)
        model = MagicMock(model_name="gemini-pro")
        model.generate_content.return_value = _make_gemini_response(
            prompt_tokens=25, candidate_tokens=20
        )

        kernel = GeminiKernel(policy=policy)
        governed = kernel.wrap(model)

        with pytest.raises(GeminiPolicyViolation, match="Token limit"):
            governed.generate_content("Hello")

    def test_function_call_validation(self) -> None:
        """Function calls with disallowed tools should be rejected."""
        policy = GovernancePolicy(allowed_tools=["safe_fn"])
        model = MagicMock(model_name="gemini-pro")

        fn_call = MagicMock()
        fn_call.name = "bad_fn"
        fn_call.args = {}

        part = MagicMock()
        part.function_call = fn_call

        content = MagicMock()
        content.parts = [part]

        candidate = MagicMock()
        candidate.content = content

        model.generate_content.return_value = _make_gemini_response(
            candidates=[candidate]
        )

        kernel = GeminiKernel(policy=policy)
        governed = kernel.wrap(model)

        with pytest.raises(GeminiPolicyViolation, match="not allowed"):
            governed.generate_content("Do something")

    def test_health_check(self) -> None:
        """Health check should report healthy status."""
        kernel = GeminiKernel()
        health = kernel.health_check()
        assert health["status"] == "healthy"
        assert health["backend"] == "gemini"

    def test_health_check_degraded(self) -> None:
        """Health check should report degraded when last_error is set."""
        kernel = GeminiKernel()
        kernel._last_error = "Quota exceeded"
        health = kernel.health_check()
        assert health["status"] == "degraded"

    def test_audit_context(self) -> None:
        """Execution context should accumulate audit data."""
        model = MagicMock(model_name="gemini-pro")
        model.generate_content.return_value = _make_gemini_response()

        kernel = GeminiKernel()
        governed = kernel.wrap(model)
        governed.generate_content("Hello")

        ctx = governed.get_context()
        assert len(ctx.generation_ids) == 1
        assert ctx.model_name == "gemini-pro"

    def test_api_error_sets_last_error(self) -> None:
        """Backend errors should be recorded for health reporting."""
        model = MagicMock(model_name="gemini-pro")
        model.generate_content.side_effect = RuntimeError("Quota exceeded")

        kernel = GeminiKernel()
        governed = kernel.wrap(model)

        with pytest.raises(RuntimeError):
            governed.generate_content("Hello")

        assert kernel._last_error == "Quota exceeded"

    def test_tool_call_limit(self) -> None:
        """Exceeding tool call limit should raise."""
        policy = GovernancePolicy(max_tool_calls=1, allowed_tools=[])

        fn_call = MagicMock()
        fn_call.name = "some_fn"
        fn_call.args = {}

        part1 = MagicMock()
        part1.function_call = fn_call
        part2 = MagicMock()
        part2.function_call = fn_call

        content = MagicMock()
        content.parts = [part1, part2]

        candidate = MagicMock()
        candidate.content = content

        model = MagicMock(model_name="gemini-pro")
        model.generate_content.return_value = _make_gemini_response(
            candidates=[candidate]
        )

        kernel = GeminiKernel(policy=policy)
        governed = kernel.wrap(model)

        with pytest.raises(GeminiPolicyViolation, match="Tool call limit"):
            governed.generate_content("Hello")


# ============================================================================
# Mistral Adapter Tests
# ============================================================================


class TestMistralKernel:
    """Tests for the Mistral AI governance adapter."""

    def test_wrap_and_unwrap(self) -> None:
        """wrap() returns a governed client; unwrap() returns the original."""
        client = MagicMock()
        kernel = MistralKernel()
        governed = kernel.wrap(client)

        assert isinstance(governed, GovernedMistralClient)
        assert kernel.unwrap(governed) is client
        assert kernel.unwrap("plain") == "plain"

    def test_chat_happy_path(self) -> None:
        """A normal chat call should succeed and track tokens."""
        client = MagicMock()
        client.chat.return_value = _make_mistral_response()

        kernel = MistralKernel()
        governed = kernel.wrap(client)
        resp = governed.chat(
            model="mistral-large-latest",
            messages=[{"role": "user", "content": "Hello"}],
        )

        assert resp.id == "chatcmpl-xyz"
        usage = governed.get_token_usage()
        assert usage["prompt_tokens"] == 10
        assert usage["completion_tokens"] == 20

    def test_blocked_pattern_rejects_message(self) -> None:
        """Messages matching blocked patterns should be rejected."""
        policy = GovernancePolicy(blocked_patterns=["password"])
        kernel = MistralKernel(policy=policy)
        governed = kernel.wrap(MagicMock())

        with pytest.raises(MistralPolicyViolation, match="blocked"):
            governed.chat(
                model="mistral-large-latest",
                messages=[{"role": "user", "content": "my password is xyz"}],
            )

    def test_max_tokens_policy_enforcement(self) -> None:
        """Requesting more tokens than the policy allows should fail."""
        policy = GovernancePolicy(max_tokens=100)
        kernel = MistralKernel(policy=policy)
        governed = kernel.wrap(MagicMock())

        with pytest.raises(MistralPolicyViolation, match="max_tokens"):
            governed.chat(
                model="mistral-large-latest",
                max_tokens=200,
                messages=[{"role": "user", "content": "Hello"}],
            )

    def test_cumulative_token_limit(self) -> None:
        """Exceeding the cumulative token limit should raise."""
        policy = GovernancePolicy(max_tokens=40)
        client = MagicMock()
        client.chat.return_value = _make_mistral_response(
            prompt_tokens=25, completion_tokens=20
        )

        kernel = MistralKernel(policy=policy)
        governed = kernel.wrap(client)

        with pytest.raises(MistralPolicyViolation, match="Token limit"):
            governed.chat(
                model="mistral-large-latest",
                messages=[{"role": "user", "content": "Hello"}],
            )

    def test_tool_call_validation(self) -> None:
        """Tool calls with disallowed tools should be rejected."""
        policy = GovernancePolicy(allowed_tools=["safe_tool"])
        client = MagicMock()

        fn_mock = MagicMock()
        fn_mock.name = "bad_tool"
        fn_mock.arguments = "{}"

        tc = MagicMock()
        tc.id = "call_1"
        tc.function = fn_mock

        msg = MagicMock()
        msg.tool_calls = [tc]

        choice = MagicMock()
        choice.message = msg

        client.chat.return_value = _make_mistral_response(choices=[choice])

        kernel = MistralKernel(policy=policy)
        governed = kernel.wrap(client)

        with pytest.raises(MistralPolicyViolation, match="not allowed"):
            governed.chat(
                model="mistral-large-latest",
                messages=[{"role": "user", "content": "Use a tool"}],
            )

    def test_tool_definition_validation(self) -> None:
        """Passing disallowed tool definitions should be rejected."""
        policy = GovernancePolicy(allowed_tools=["safe_tool"])
        kernel = MistralKernel(policy=policy)
        governed = kernel.wrap(MagicMock())

        with pytest.raises(MistralPolicyViolation, match="not allowed"):
            governed.chat(
                model="mistral-large-latest",
                messages=[{"role": "user", "content": "Hello"}],
                tools=[{"function": {"name": "bad_tool"}, "type": "function"}],
            )

    def test_health_check(self) -> None:
        """Health check should report healthy status."""
        kernel = MistralKernel()
        health = kernel.health_check()
        assert health["status"] == "healthy"
        assert health["backend"] == "mistral"

    def test_health_check_degraded(self) -> None:
        """Health check should report degraded when last_error is set."""
        kernel = MistralKernel()
        kernel._last_error = "Rate limit"
        health = kernel.health_check()
        assert health["status"] == "degraded"

    def test_audit_context(self) -> None:
        """Execution context should accumulate audit data."""
        client = MagicMock()
        client.chat.return_value = _make_mistral_response()

        kernel = MistralKernel()
        governed = kernel.wrap(client)
        governed.chat(
            model="mistral-large-latest",
            messages=[{"role": "user", "content": "Hello"}],
        )

        ctx = governed.get_context()
        assert len(ctx.chat_ids) == 1

    def test_api_error_sets_last_error(self) -> None:
        """Backend errors should be recorded for health reporting."""
        client = MagicMock()
        client.chat.side_effect = RuntimeError("Connection refused")

        kernel = MistralKernel()
        governed = kernel.wrap(client)

        with pytest.raises(RuntimeError):
            governed.chat(
                model="mistral-large-latest",
                messages=[{"role": "user", "content": "Hello"}],
            )

        assert kernel._last_error == "Connection refused"

    def test_tool_call_limit(self) -> None:
        """Exceeding tool call limit should raise."""
        policy = GovernancePolicy(max_tool_calls=1, allowed_tools=[])
        client = MagicMock()

        fn_mock1 = MagicMock()
        fn_mock1.name = "fn_a"
        fn_mock1.arguments = "{}"
        fn_mock2 = MagicMock()
        fn_mock2.name = "fn_b"
        fn_mock2.arguments = "{}"

        tc1 = MagicMock()
        tc1.id = "call_1"
        tc1.function = fn_mock1
        tc2 = MagicMock()
        tc2.id = "call_2"
        tc2.function = fn_mock2

        msg = MagicMock()
        msg.tool_calls = [tc1, tc2]

        choice = MagicMock()
        choice.message = msg

        client.chat.return_value = _make_mistral_response(choices=[choice])

        kernel = MistralKernel(policy=policy)
        governed = kernel.wrap(client)

        with pytest.raises(MistralPolicyViolation, match="Tool call limit"):
            governed.chat(
                model="mistral-large-latest",
                messages=[{"role": "user", "content": "Hello"}],
            )
