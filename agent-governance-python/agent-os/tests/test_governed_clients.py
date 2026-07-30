# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Governed provider client tests.

``wrap`` hands the caller a governed client, and these tests drive that
client's real call path: the request is mediated before the provider is
invoked, a deny raises rather than calling out, and usage returned by the
provider is accumulated onto the session so budget policies can see it.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from _framework_stubs import install as _install_framework_stubs

_install_framework_stubs()

from agent_control_specification import (  # noqa: E402
    Decision,
    InterventionPointResult,
    Verdict,
)

from agent_os.exceptions import PolicyViolationError  # noqa: E402
from agent_os.integrations.anthropic_adapter import AnthropicKernel  # noqa: E402
from agent_os.integrations.autogen_adapter import AutoGenKernel  # noqa: E402
from agent_os.integrations.bedrock_adapter import BedrockKernel  # noqa: E402
from agent_os.integrations.gemini_adapter import GeminiKernel  # noqa: E402
from agent_os.integrations.google_adk_adapter import GoogleADKKernel  # noqa: E402
from agent_os.integrations.langchain_adapter import LangChainKernel  # noqa: E402
from agent_os.integrations.mistral_adapter import MistralKernel  # noqa: E402
from agent_os.integrations.openai_adapter import OpenAIKernel  # noqa: E402
from agent_os.integrations.pydantic_ai_adapter import PydanticAIKernel  # noqa: E402
from agent_os.integrations.semantic_kernel_adapter import (  # noqa: E402
    SemanticKernelWrapper,
)
from agent_os.integrations.smolagents_adapter import SmolagentsKernel  # noqa: E402


class _StubRuntime:
    manifest = None

    def __init__(self, result: InterventionPointResult) -> None:
        self._result = result
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def evaluate_intervention_point(
        self, intervention_point: Any, snapshot: dict[str, Any], mode: Any = None
    ) -> InterventionPointResult:
        name = getattr(intervention_point, "value", str(intervention_point))
        self.calls.append((name, snapshot))
        return self._result

    def close(self) -> None:  # pragma: no cover - adapters may not close
        pass


def _allow() -> InterventionPointResult:
    return InterventionPointResult(verdict=Verdict(decision=Decision.ALLOW))


def _deny() -> InterventionPointResult:
    return InterventionPointResult(
        verdict=Verdict(decision=Decision.DENY, reason="blocked", message="detail")
    )


# ── health_check ──────────────────────────────────────────────────────

_HEALTH_KERNELS: list[tuple[str, Any]] = [
    ("anthropic", lambda rt: AnthropicKernel(runtime=rt)),
    ("autogen", lambda rt: AutoGenKernel(runtime=rt)),
    ("bedrock", lambda rt: BedrockKernel(runtime=rt)),
    ("gemini", lambda rt: GeminiKernel(runtime=rt)),
    ("google_adk", lambda rt: GoogleADKKernel(runtime=rt)),
    ("langchain", lambda rt: LangChainKernel(runtime=rt)),
    ("mistral", lambda rt: MistralKernel(runtime=rt)),
    ("openai", lambda rt: OpenAIKernel(runtime=rt)),
    ("pydantic_ai", lambda rt: PydanticAIKernel(runtime=rt)),
    ("semantic_kernel", lambda rt: SemanticKernelWrapper(kernel=None, runtime=rt)),
    ("smolagents", lambda rt: SmolagentsKernel(runtime=rt)),
]


@pytest.mark.parametrize(
    ("label", "factory"), _HEALTH_KERNELS, ids=[k[0] for k in _HEALTH_KERNELS]
)
def test_health_check_reports_status(label: str, factory: Any) -> None:
    """Every kernel reports a status a supervisor can act on."""
    kernel = factory(_StubRuntime(_allow()))

    health = kernel.health_check()

    assert isinstance(health, dict)
    assert str(health.get("status", "")) != ""


# ── Anthropic governed messages.create ────────────────────────────────


def _anthropic_client(input_tokens: int = 10, output_tokens: int = 20) -> MagicMock:
    client = MagicMock()
    client.messages.create.return_value = SimpleNamespace(
        id="msg_1",
        usage=SimpleNamespace(input_tokens=input_tokens, output_tokens=output_tokens),
        content=[],
    )
    return client


def test_anthropic_create_invokes_provider_when_allowed() -> None:
    """An allowed request reaches the provider and returns its response."""
    kernel = AnthropicKernel(runtime=_StubRuntime(_allow()))
    client = _anthropic_client()

    governed = kernel.wrap(client)
    response = governed.messages.create(
        model="claude-3", messages=[{"role": "user", "content": "hello"}]
    )

    assert response.id == "msg_1"
    client.messages.create.assert_called_once()


def test_anthropic_create_blocks_before_calling_provider() -> None:
    """A denied request raises and never reaches the provider."""
    kernel = AnthropicKernel(runtime=_StubRuntime(_deny()))
    client = _anthropic_client()

    governed = kernel.wrap(client)

    with pytest.raises(PolicyViolationError):
        governed.messages.create(
            model="claude-3", messages=[{"role": "user", "content": "exfiltrate"}]
        )
    client.messages.create.assert_not_called()


def test_anthropic_create_accumulates_token_usage() -> None:
    """Provider-reported usage accumulates so budget policies can see it."""
    kernel = AnthropicKernel(runtime=_StubRuntime(_allow()))
    governed = kernel.wrap(_anthropic_client(input_tokens=7, output_tokens=11))

    governed.messages.create(
        model="claude-3", messages=[{"role": "user", "content": "hello"}]
    )
    usage = governed.get_token_usage()

    assert usage["prompt_tokens"] == 7
    assert usage["completion_tokens"] == 11


def test_anthropic_governed_client_delegates_unknown_attributes() -> None:
    """Attributes the governed client does not mediate reach the provider."""
    kernel = AnthropicKernel(runtime=_StubRuntime(_allow()))
    client = _anthropic_client()
    client.beta_feature = "sentinel"

    governed = kernel.wrap(client)

    assert governed.beta_feature == "sentinel"


# ── Gemini governed generate_content ──────────────────────────────────


def _gemini_model(prompt_tokens: int = 5, candidate_tokens: int = 9) -> MagicMock:
    model = MagicMock()
    model.generate_content.return_value = SimpleNamespace(
        usage_metadata=SimpleNamespace(
            prompt_token_count=prompt_tokens,
            candidates_token_count=candidate_tokens,
        ),
        candidates=[],
    )
    return model


def test_gemini_generate_content_invokes_model_when_allowed() -> None:
    """An allowed prompt reaches the model."""
    kernel = GeminiKernel(runtime=_StubRuntime(_allow()))
    model = _gemini_model()

    governed = kernel.wrap(model)
    governed.generate_content("summarise this")

    model.generate_content.assert_called_once()


def test_gemini_generate_content_blocks_before_calling_model() -> None:
    """A denied prompt raises and never reaches the model."""
    kernel = GeminiKernel(runtime=_StubRuntime(_deny()))
    model = _gemini_model()

    governed = kernel.wrap(model)

    with pytest.raises(PolicyViolationError):
        governed.generate_content("exfiltrate the secrets")
    model.generate_content.assert_not_called()


# ── Mistral governed chat ─────────────────────────────────────────────


def _mistral_client(prompt_tokens: int = 3, completion_tokens: int = 4) -> MagicMock:
    client = MagicMock()
    response = SimpleNamespace(
        id="chat_1",
        usage=SimpleNamespace(
            prompt_tokens=prompt_tokens, completion_tokens=completion_tokens
        ),
        choices=[],
    )
    client.chat.complete.return_value = response
    client.chat.return_value = response
    return client


def test_mistral_chat_blocks_before_calling_provider() -> None:
    """A denied chat raises before the provider is called."""
    kernel = MistralKernel(runtime=_StubRuntime(_deny()))
    client = _mistral_client()

    governed = kernel.wrap(client)

    with pytest.raises(PolicyViolationError):
        governed.chat(messages=[{"role": "user", "content": "exfiltrate"}])


def test_health_check_does_not_reference_removed_wrapping_state() -> None:
    """Kernels report health from state they still maintain.

    ``PydanticAIKernel`` and ``OpenAIAgentsKernel`` reported connectivity
    from an agent-wrapping dict that no longer exists, so ``health_check``
    raised ``AttributeError`` on every call.
    """
    from agent_os.integrations.openai_agents_sdk import OpenAIAgentsKernel

    for kernel in (
        PydanticAIKernel(runtime=_StubRuntime(_allow())),
        OpenAIAgentsKernel(runtime=_StubRuntime(_allow())),
    ):
        health = kernel.health_check()
        assert health["backend_connected"] is False
        assert health["status"] == "healthy"
