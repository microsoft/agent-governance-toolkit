# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests that require_human_approval is enforced across ALL adapters.

Ensures the security fix for issue #282 — human approval was only enforced
in the OpenAI adapter. Now it's enforced in BaseIntegration.pre_execute()
and PolicyInterceptor.intercept(), covering all adapters automatically.

All tests use mocks — no real API calls are made.
"""

from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock

import pytest

from agent_os.integrations.base import (
    GovernancePolicy,
    PolicyInterceptor,
    ToolCallRequest,
)

# ---------------------------------------------------------------------------
# Mock third-party SDK modules so tests run without installing them.
# ---------------------------------------------------------------------------

# --- crewai mock ---
_crewai = types.ModuleType("crewai")
sys.modules.setdefault("crewai", _crewai)

# --- langchain mocks ---
for mod_name in ("langchain", "langchain.agents", "langchain.chains"):
    sys.modules.setdefault(mod_name, types.ModuleType(mod_name))

# --- autogen mock ---
sys.modules.setdefault("autogen", types.ModuleType("autogen"))

# --- google.generativeai mock ---
_google = types.ModuleType("google")
_google.__path__ = []
_genai = types.ModuleType("google.generativeai")
sys.modules.setdefault("google", _google)
sys.modules.setdefault("google.generativeai", _genai)

# --- anthropic mock ---
sys.modules.setdefault("anthropic", types.ModuleType("anthropic"))

# --- mistralai mock ---
sys.modules.setdefault("mistralai", types.ModuleType("mistralai"))

# Now import the adapters (after mocks are in place)
import agent_os.integrations.anthropic_adapter as _anthropic_mod
import agent_os.integrations.gemini_adapter as _gemini_mod

_anthropic_mod._HAS_ANTHROPIC = True
_gemini_mod._HAS_GENAI = True

import agent_os.integrations.mistral_adapter as _mistral_mod

_mistral_mod._HAS_MISTRAL = True

from agent_os.integrations.langchain_adapter import LangChainKernel
from agent_os.integrations.langchain_adapter import PolicyViolationError as LangChainPolicyViolation
from agent_os.integrations.crewai_adapter import CrewAIKernel
from agent_os.integrations.autogen_adapter import AutoGenKernel
from agent_os.integrations.gemini_adapter import GeminiKernel
from agent_os.integrations.anthropic_adapter import AnthropicKernel
from agent_os.integrations.mistral_adapter import MistralKernel
from agent_os.exceptions import PolicyViolationError


# ============================================================================
# PolicyInterceptor — tool-call-level enforcement
# ============================================================================


class TestPolicyInterceptorHumanApproval:
    """PolicyInterceptor.intercept() should deny when require_human_approval is True."""

    def test_intercept_blocks_when_approval_required(self):
        policy = GovernancePolicy(require_human_approval=True)
        interceptor = PolicyInterceptor(policy)
        request = ToolCallRequest(tool_name="web_search", arguments={"q": "test"})
        result = interceptor.intercept(request)
        assert not result.allowed
        assert "human approval" in result.reason

    def test_intercept_allows_when_approval_not_required(self):
        policy = GovernancePolicy(require_human_approval=False)
        interceptor = PolicyInterceptor(policy)
        request = ToolCallRequest(tool_name="web_search", arguments={"q": "test"})
        result = interceptor.intercept(request)
        assert result.allowed


# ============================================================================
# LangChain Adapter
# ============================================================================


class TestLangChainHumanApproval:
    """LangChain adapter should block execution when require_human_approval is True."""

    def test_invoke_blocked(self):
        policy = GovernancePolicy(require_human_approval=True)
        kernel = LangChainKernel(policy=policy)

        chain = MagicMock()
        chain.name = "test-chain"
        governed = kernel.wrap(chain)

        with pytest.raises(LangChainPolicyViolation, match="human approval"):
            governed.invoke({"input": "hello"})

    def test_run_blocked(self):
        policy = GovernancePolicy(require_human_approval=True)
        kernel = LangChainKernel(policy=policy)

        agent = MagicMock()
        agent.name = "test-agent"
        governed = kernel.wrap(agent)

        with pytest.raises(LangChainPolicyViolation, match="human approval"):
            governed.run("hello")

    def test_batch_blocked(self):
        policy = GovernancePolicy(require_human_approval=True)
        kernel = LangChainKernel(policy=policy)

        chain = MagicMock()
        chain.name = "test-chain"
        governed = kernel.wrap(chain)

        with pytest.raises(LangChainPolicyViolation, match="human approval"):
            governed.batch([{"input": "a"}, {"input": "b"}])

    def test_stream_blocked(self):
        policy = GovernancePolicy(require_human_approval=True)
        kernel = LangChainKernel(policy=policy)

        chain = MagicMock()
        chain.name = "test-chain"
        governed = kernel.wrap(chain)

        with pytest.raises(LangChainPolicyViolation, match="human approval"):
            list(governed.stream({"input": "hello"}))

    def test_invoke_allowed_without_approval(self):
        """Sanity check: without require_human_approval, invoke should work."""
        policy = GovernancePolicy(require_human_approval=False)
        kernel = LangChainKernel(policy=policy)

        chain = MagicMock()
        chain.name = "test-chain"
        chain.invoke.return_value = "result"
        governed = kernel.wrap(chain)

        result = governed.invoke({"input": "hello"})
        assert result == "result"


# ============================================================================
# AutoGen Adapter
# ============================================================================


class TestAutoGenHumanApproval:
    """AutoGen adapter should block execution when require_human_approval is True."""

    def test_initiate_chat_blocked(self):
        policy = GovernancePolicy(require_human_approval=True)
        kernel = AutoGenKernel(policy=policy)

        agent = MagicMock()
        agent.name = "assistant"
        recipient = MagicMock()
        recipient.name = "user_proxy"

        kernel.govern(agent)

        with pytest.raises(PolicyViolationError, match="human approval"):
            agent.initiate_chat(recipient, message="hello")

    def test_receive_blocked(self):
        policy = GovernancePolicy(require_human_approval=True)
        kernel = AutoGenKernel(policy=policy)

        agent = MagicMock()
        agent.name = "assistant"
        sender = MagicMock()

        kernel.govern(agent)

        with pytest.raises(PolicyViolationError, match="human approval"):
            agent.receive("hello", sender)

    def test_generate_reply_blocked(self):
        policy = GovernancePolicy(require_human_approval=True)
        kernel = AutoGenKernel(policy=policy)

        agent = MagicMock()
        agent.name = "assistant"

        kernel.govern(agent)

        result = agent.generate_reply(messages=["hello"])
        assert "BLOCKED" in result
        assert "human approval" in result

    def test_initiate_chat_allowed_without_approval(self):
        """Sanity check: without require_human_approval, initiate_chat should work."""
        policy = GovernancePolicy(require_human_approval=False)
        kernel = AutoGenKernel(policy=policy)

        agent = MagicMock()
        agent.name = "assistant"
        recipient = MagicMock()

        kernel.govern(agent)
        agent.initiate_chat(recipient, message="hello")


# ============================================================================
# Gemini Adapter
# ============================================================================


class TestGeminiHumanApproval:
    """Gemini adapter should block execution when require_human_approval is True."""

    def test_generate_content_blocked(self):
        policy = GovernancePolicy(require_human_approval=True)
        kernel = GeminiKernel(policy=policy)

        model = MagicMock()
        model.model_name = "gemini-pro"
        governed = kernel.wrap(model)

        from agent_os.integrations.gemini_adapter import (
            PolicyViolationError as GeminiPolicyViolation,
        )

        with pytest.raises(GeminiPolicyViolation, match="human approval"):
            governed.generate_content("hello")


# ============================================================================
# Anthropic Adapter
# ============================================================================


class TestAnthropicHumanApproval:
    """Anthropic adapter should block execution when require_human_approval is True."""

    def test_messages_create_blocked(self):
        policy = GovernancePolicy(require_human_approval=True)
        kernel = AnthropicKernel(policy=policy)

        client = MagicMock()
        governed = kernel.wrap(client)

        from agent_os.integrations.anthropic_adapter import (
            PolicyViolationError as AnthropicPolicyViolation,
        )

        with pytest.raises(AnthropicPolicyViolation, match="human approval"):
            governed.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=1024,
                messages=[{"role": "user", "content": "Hello"}],
            )


# ============================================================================
# Mistral Adapter
# ============================================================================


class TestMistralHumanApproval:
    """Mistral adapter should block execution when require_human_approval is True."""

    def test_chat_blocked(self):
        policy = GovernancePolicy(require_human_approval=True)
        kernel = MistralKernel(policy=policy)

        client = MagicMock()
        governed = kernel.wrap(client)

        from agent_os.integrations.mistral_adapter import (
            PolicyViolationError as MistralPolicyViolation,
        )

        with pytest.raises(MistralPolicyViolation, match="human approval"):
            governed.chat(
                model="mistral-large-latest",
                messages=[{"role": "user", "content": "Hello"}],
            )
