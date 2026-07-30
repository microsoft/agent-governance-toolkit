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
from unittest.mock import MagicMock, patch

import pytest

from _framework_stubs import DropMessage, FunctionCall
from _framework_stubs import install as _install_framework_stubs

_install_framework_stubs()

from agent_control_specification import (  # noqa: E402
    Decision,
    InterventionPointResult,
    Transform,
    Verdict,
)

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
    def _build(result: InterventionPointResult) -> tuple[Any, _StubRuntime]:
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
        InterventionPointResult(
            verdict=Verdict(
                decision=Decision.TRANSFORM,
                reason="redact",
                transform=Transform(path="input.body", value="[redacted]"),
            )
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


# ── Output verdict enforcement at the post_execute seam ───────────────
#
# Four adapter call sites evaluated the output intervention point via
# ``kernel.post_execute(...)`` and discarded the returned (allowed, reason)
# tuple, so an output deny still disclosed the response and an output
# transform was silently dropped. These tests pin the fixed behaviour on
# the surfaces a caller actually drives: the deprecated Anthropic wrap
# proxy, the recommended Anthropic message hook, and the AutoGen legacy
# ``govern()`` patches for ``initiate_chat`` and ``receive``.

from agent_os.exceptions import PolicyViolationError  # noqa: E402

_SECRET = "SECRET-TOKEN-XYZ-99"


class _PerPointRuntime(_StubRuntime):
    """A stub runtime that answers per intervention point, allowing elsewhere."""

    def __init__(self, overrides: dict[str, InterventionPointResult]) -> None:
        super().__init__(_allow())
        self._overrides = overrides

    async def evaluate_intervention_point(
        self, intervention_point: Any, snapshot: dict[str, Any], mode: Any = None
    ) -> InterventionPointResult:
        name = getattr(intervention_point, "value", str(intervention_point))
        self.calls.append((name, snapshot))
        return self._overrides.get(name, self._result)


def _output_transform() -> InterventionPointResult:
    return InterventionPointResult(
        verdict=Verdict(
            decision=Decision.TRANSFORM,
            reason="redact",
            transform=Transform(path="output.content", value="[redacted]"),
        )
    )


class _AnthropicResponse:
    """A minimal Anthropic-shaped response carrying a secret payload."""

    def __init__(self, text: str) -> None:
        self.id = "msg-1"
        self.content: list[Any] = []
        self.usage = None
        self._text = text

    def __str__(self) -> str:
        return self._text


def _anthropic_client(text: str) -> MagicMock:
    client = MagicMock()
    client.messages.create.return_value = _AnthropicResponse(text)
    return client


def test_anthropic_wrap_blocks_denied_output() -> None:
    """The governed proxy must not disclose a response the output point denies."""
    kernel = AnthropicKernel(runtime=_PerPointRuntime({"output": _deny()}))
    governed = kernel.wrap(_anthropic_client(_SECRET))

    with pytest.raises(PolicyViolationError) as excinfo:
        governed.messages.create(
            model="m", messages=[{"role": "user", "content": "hi"}]
        )

    assert _SECRET not in str(excinfo.value)
    assert "blocked by policy" in str(excinfo.value)


def test_anthropic_hook_create_blocks_denied_output() -> None:
    """The message hook must not disclose a response the output point denies."""
    kernel = AnthropicKernel(runtime=_PerPointRuntime({"output": _deny()}))
    hook = kernel.as_message_hook()

    with pytest.raises(PolicyViolationError) as excinfo:
        hook.create(
            _anthropic_client(_SECRET),
            model="m",
            messages=[{"role": "user", "content": "hi"}],
        )

    assert _SECRET not in str(excinfo.value)
    assert "blocked by policy" in str(excinfo.value)


def test_anthropic_hook_refuses_output_transform_it_cannot_apply() -> None:
    """``post_execute`` answers with a tuple, so it has nowhere to carry the
    replacement; the response must be refused rather than forwarded as-is."""
    kernel = AnthropicKernel(
        runtime=_PerPointRuntime({"output": _output_transform()})
    )
    hook = kernel.as_message_hook()

    with pytest.raises(PolicyViolationError) as excinfo:
        hook.create(
            _anthropic_client(_SECRET),
            model="m",
            messages=[{"role": "user", "content": "hi"}],
        )

    assert _SECRET not in str(excinfo.value)
    assert "transform_not_applicable" in str(excinfo.value)


class _ChattyAgent:
    """Minimal AutoGen-shaped agent whose calls return a fixed reply."""

    def __init__(self, reply: str, name: str = "agent-1") -> None:
        self.name = name
        self._reply = reply

    def initiate_chat(self, recipient: Any, message: Any = None, **kwargs: Any) -> Any:
        return self._reply

    def generate_reply(self, messages: Any = None, sender: Any = None, **kwargs: Any) -> Any:
        return self._reply

    def receive(self, message: Any, sender: Any, **kwargs: Any) -> Any:
        return self._reply


def test_autogen_initiate_chat_blocks_denied_output() -> None:
    """A denied chat result raises instead of being returned to the caller."""
    kernel = AutoGenKernel(runtime=_PerPointRuntime({"output": _deny()}))
    agent = _ChattyAgent(_SECRET)
    kernel.govern(agent)

    with pytest.raises(PolicyViolationError) as excinfo:
        agent.initiate_chat(_named("peer"), message="hello")

    assert _SECRET not in str(excinfo.value)


def test_autogen_receive_blocks_denied_output() -> None:
    """A denied receive result raises instead of being returned to the caller."""
    kernel = AutoGenKernel(runtime=_PerPointRuntime({"output": _deny()}))
    agent = _ChattyAgent(_SECRET)
    kernel.govern(agent)

    with pytest.raises(PolicyViolationError) as excinfo:
        agent.receive("hello", _named("peer"))

    assert _SECRET not in str(excinfo.value)


def test_autogen_initiate_chat_refuses_output_transform_it_cannot_apply() -> None:
    """``post_execute`` cannot carry the replacement, so the result is refused."""
    kernel = AutoGenKernel(
        runtime=_PerPointRuntime({"output": _output_transform()})
    )
    agent = _ChattyAgent(_SECRET)
    kernel.govern(agent)

    with pytest.raises(PolicyViolationError) as excinfo:
        agent.initiate_chat(_named("peer"), message="hello")

    assert _SECRET not in str(excinfo.value)
    assert "transform_not_applicable" in str(excinfo.value)


def test_autogen_allowed_output_is_returned_unchanged() -> None:
    """The consumed verdict must not turn allows into blocks."""
    kernel = AutoGenKernel(runtime=_PerPointRuntime({}))
    agent = _ChattyAgent("all good")
    kernel.govern(agent)

    assert agent.initiate_chat(_named("peer"), message="hello") == "all good"
    assert agent.receive("hello", _named("peer")) == "all good"


def test_anthropic_allowed_output_is_returned_unchanged() -> None:
    """The consumed verdict must not turn allows into blocks."""
    kernel = AnthropicKernel(runtime=_PerPointRuntime({}))
    hook = kernel.as_message_hook()
    client = _anthropic_client("all good")

    response = hook.create(
        client, model="m", messages=[{"role": "user", "content": "hi"}]
    )

    assert str(response) == "all good"


def test_autogen_output_deny_without_reason_gets_public_message() -> None:
    """A deny whose reason is None must not surface "None" to callers."""
    kernel = AutoGenKernel(runtime=_PerPointRuntime({"output": _deny()}))
    agent = _ChattyAgent(_SECRET)
    kernel.govern(agent)

    with patch.object(kernel, "post_execute", return_value=(False, None)):
        with pytest.raises(PolicyViolationError) as excinfo:
            agent.initiate_chat(_named("peer"), message="hello")

    assert "None" not in str(excinfo.value)
    assert "denied by output policy" in str(excinfo.value)


def test_anthropic_hook_output_deny_without_reason_gets_public_message() -> None:
    """The anthropic hook path must also normalize a None deny reason."""
    kernel = AnthropicKernel(runtime=_PerPointRuntime({"output": _deny()}))
    hook = kernel.as_message_hook()

    with patch.object(kernel, "post_execute", return_value=(False, None)):
        with pytest.raises(PolicyViolationError) as excinfo:
            hook.create(
                _anthropic_client(_SECRET),
                model="m",
                messages=[{"role": "user", "content": "hi"}],
            )

    assert "None" not in str(excinfo.value)
    assert "denied by output policy" in str(excinfo.value)
