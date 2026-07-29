# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Interception tests for the governed proxies and framework hooks.

``test_adapter_enforcement`` drives the kernels' evaluation seam directly.
These tests drive the surfaces a framework actually calls: the governed
client returned by ``wrap``, the AutoGen intervention handler, the Google
ADK tool callback, and the LlamaIndex stream replay. Those are the paths
where a verdict turns into a blocked side effect, so they are asserted
here rather than assumed.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from _framework_stubs import DropMessage, FunctionCall
from _framework_stubs import install as _install_framework_stubs

_install_framework_stubs()

from agt.policies import PolicyEvaluation  # noqa: E402
from agt.policies.result import TransformResult  # noqa: E402

from agent_os.integrations.anthropic_adapter import AnthropicKernel  # noqa: E402
from agent_os.integrations.autogen_adapter import (  # noqa: E402
    AutoGenKernel,
    GovernanceInterventionHandler,
)
from agent_os.integrations.bedrock_adapter import BedrockKernel  # noqa: E402
from agent_os.integrations.gemini_adapter import GeminiKernel  # noqa: E402
from agent_os.integrations.google_adk_adapter import GoogleADKKernel  # noqa: E402
from agent_os.integrations.langgraph_adapter import LangGraphKernel  # noqa: E402
from agent_os.integrations.llamaindex_adapter import LlamaIndexKernel  # noqa: E402
from agent_os.integrations.maf_adapter import MAFKernel  # noqa: E402
from agent_os.integrations.mistral_adapter import MistralKernel  # noqa: E402
from agent_os.integrations.openai_adapter import OpenAIKernel  # noqa: E402
from agent_os.integrations.semantic_kernel_adapter import (  # noqa: E402
    SemanticKernelWrapper,
)


class _StubRuntime:
    manifest = None

    def __init__(self, result: PolicyEvaluation) -> None:
        self._result = result
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def evaluate(
        self, intervention_point: str, snapshot: dict[str, Any]
    ) -> PolicyEvaluation:
        name = getattr(intervention_point, "value", str(intervention_point))
        self.calls.append((name, snapshot))
        return self._result.model_copy(update={"intervention_point": name})

    def close(self) -> None:  # pragma: no cover - adapters may not close
        pass


def _allow() -> PolicyEvaluation:
    return PolicyEvaluation(verdict="allow")


def _deny() -> PolicyEvaluation:
    return PolicyEvaluation(verdict="deny", reason_code="blocked", message="detail")


def _named(name: str = "agent-1") -> MagicMock:
    """A framework object whose identity attributes are valid agent ids."""
    obj = MagicMock()
    obj.name = name
    obj.id = name
    obj.agent_id = name
    return obj


# ── wrap/unwrap round trip ────────────────────────────────────────────

def _wrap_anthropic(kernel: Any, target: Any) -> Any:
    return kernel.wrap(target)


def _wrap_openai(kernel: Any, target: Any) -> Any:
    return kernel.wrap(target, client=MagicMock())


_WRAPPERS: list[tuple[str, Any, Any]] = [
    ("anthropic", lambda rt: AnthropicKernel(runtime=rt), _wrap_anthropic),
    ("autogen", lambda rt: AutoGenKernel(runtime=rt), _wrap_anthropic),
    ("bedrock", lambda rt: BedrockKernel(runtime=rt), _wrap_anthropic),
    ("gemini", lambda rt: GeminiKernel(runtime=rt), _wrap_anthropic),
    ("google_adk", lambda rt: GoogleADKKernel(runtime=rt), _wrap_anthropic),
    ("langgraph", lambda rt: LangGraphKernel(runtime=rt), _wrap_anthropic),
    ("llamaindex", lambda rt: LlamaIndexKernel(runtime=rt), _wrap_anthropic),
    ("maf", lambda rt: MAFKernel(runtime=rt), _wrap_anthropic),
    ("mistral", lambda rt: MistralKernel(runtime=rt), _wrap_anthropic),
    ("openai", lambda rt: OpenAIKernel(runtime=rt), _wrap_openai),
    (
        "semantic_kernel",
        lambda rt: SemanticKernelWrapper(kernel=None, runtime=rt),
        _wrap_anthropic,
    ),
]


@pytest.mark.parametrize(
    ("label", "kernel_factory", "wrap"), _WRAPPERS, ids=[w[0] for w in _WRAPPERS]
)
def test_wrap_returns_proxy_and_unwrap_restores_original(
    label: str, kernel_factory: Any, wrap: Any
) -> None:
    """``unwrap`` restores the original object a governed handle was built from.

    Some adapters return a proxy and others attach governance in place, so
    the contract asserted here is the round trip rather than the identity.
    """
    kernel = kernel_factory(_StubRuntime(_allow()))
    target = _named(f"agent-{label}")

    governed = wrap(kernel, target)

    assert kernel.unwrap(governed) is target


@pytest.mark.parametrize(
    ("label", "kernel_factory", "wrap"), _WRAPPERS, ids=[w[0] for w in _WRAPPERS]
)
def test_governed_proxy_delegates_unknown_attributes(
    label: str, kernel_factory: Any, wrap: Any
) -> None:
    """Attributes the proxy does not govern still reach the wrapped object."""
    kernel = kernel_factory(_StubRuntime(_allow()))
    target = _named(f"agent-{label}")
    target.some_passthrough_attribute = "sentinel"

    governed = wrap(kernel, target)

    assert governed.some_passthrough_attribute == "sentinel"


# ── AutoGen intervention handler ──────────────────────────────────────


@pytest.fixture()
def autogen_handler() -> Any:
    def _build(result: PolicyEvaluation) -> tuple[Any, _StubRuntime]:
        runtime = _StubRuntime(result)
        kernel = AutoGenKernel(runtime=runtime)
        return GovernanceInterventionHandler(kernel, name="test"), runtime

    return _build


@pytest.mark.asyncio
async def test_autogen_on_send_allows_permitted_message(autogen_handler: Any) -> None:
    """An allowed message is forwarded unchanged."""
    handler, runtime = autogen_handler(_allow())
    message = MagicMock()
    message.content = "hello"

    result = await handler.on_send(message)

    assert result is message
    assert runtime.calls


@pytest.mark.asyncio
async def test_autogen_on_send_drops_denied_message(autogen_handler: Any) -> None:
    """A denied message is dropped instead of forwarded."""
    handler, _ = autogen_handler(_deny())
    message = MagicMock()
    message.content = "exfiltrate"

    result = await handler.on_send(message)

    assert result is DropMessage


@pytest.mark.asyncio
async def test_autogen_on_send_drops_denied_function_call(
    autogen_handler: Any,
) -> None:
    """A denied tool call is dropped at the pre_tool_call point."""
    handler, runtime = autogen_handler(_deny())

    result = await handler.on_send(FunctionCall(name="shell", arguments='{"c":"rm"}'))

    assert result is DropMessage
    assert any(point == "pre_tool_call" for point, _ in runtime.calls)


@pytest.mark.asyncio
async def test_autogen_on_send_applies_transform_to_content(
    autogen_handler: Any,
) -> None:
    """A transform verdict rewrites the message before it is forwarded."""
    handler, _ = autogen_handler(
        PolicyEvaluation(
            verdict="transform",
            reason_code="redact",
            transform=TransformResult(path="input.body", value="[redacted]"),
        )
    )
    message = MagicMock()
    message.content = "please summarise the meeting"

    result = await handler.on_send(message)

    assert result is message
    assert message.content == "[redacted]"


@pytest.mark.asyncio
async def test_autogen_on_send_counts_allowed_tool_calls(
    autogen_handler: Any,
) -> None:
    """Allowed tool calls advance the handler's budget counter."""
    handler, _ = autogen_handler(_allow())

    await handler.on_send(FunctionCall(name="search"))
    await handler.on_send(FunctionCall(name="search"))

    assert handler.context.call_count == 2


# ── Google ADK tool callback ──────────────────────────────────────────


def test_google_adk_before_tool_callback_blocks_denied_tool() -> None:
    """The ADK callback returns a refusal payload for a denied tool."""
    violations: list[Any] = []
    kernel = GoogleADKKernel(
        runtime=_StubRuntime(_deny()), on_violation=violations.append
    )
    tool_context = MagicMock()
    tool_context.function_call_id = "c1"

    result = kernel.before_tool_callback(
        tool_context, tool=_named("shell"), args={"cmd": "rm -rf /"}
    )

    assert result is not None
    assert violations


def test_google_adk_before_tool_callback_allows_permitted_tool() -> None:
    """The ADK callback returns ``None`` so an allowed tool proceeds."""
    kernel = GoogleADKKernel(runtime=_StubRuntime(_allow()))
    tool_context = MagicMock()
    tool_context.function_call_id = "c1"

    result = kernel.before_tool_callback(
        tool_context, tool=_named("search"), args={"q": "hello"}
    )

    assert result is None


@pytest.mark.asyncio
async def test_autogen_on_send_drops_pii_even_when_policy_allows(
    autogen_handler: Any,
) -> None:
    """The defensive PII scan drops a message the manifest would permit."""
    handler, _ = autogen_handler(_allow())
    message = MagicMock()
    message.content = "my card is 4111111111111111"

    result = await handler.on_send(message)

    assert result is DropMessage
