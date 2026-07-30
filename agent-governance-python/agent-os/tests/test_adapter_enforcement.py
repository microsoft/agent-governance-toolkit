# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Behavioural enforcement tests for the native framework adapters.

``test_adapter_mediation_contract`` checks the adapter *source* for the
mediation seams. These tests execute them: every public kernel is driven
against a stub runtime and asserted to honour allow, deny, and transform
verdicts, to charge the tool-call budget, and to keep policy detail out of
the message raised at the caller.

The stub runtime implements the same duck-typed surface
``NativeAdapterRuntime`` consumes, so these tests exercise the real
adapter and the real runtime seam without an ACS manifest or a framework
SDK.
"""

from __future__ import annotations

from typing import Any

import pytest

from _framework_stubs import install as _install_framework_stubs

_install_framework_stubs()

from agt.policies import PolicyEvaluation  # noqa: E402
from agt.policies.result import TransformResult  # noqa: E402

from agent_os.exceptions import PolicyViolationError  # noqa: E402
from agent_os.integrations.anthropic_adapter import AnthropicKernel  # noqa: E402
from agent_os.integrations.autogen_adapter import AutoGenKernel  # noqa: E402
from agent_os.integrations.bedrock_adapter import BedrockKernel  # noqa: E402
from agent_os.integrations.crewai_adapter import CrewAIKernel  # noqa: E402
from agent_os.integrations.gemini_adapter import GeminiKernel  # noqa: E402
from agent_os.integrations.google_adk_adapter import GoogleADKKernel  # noqa: E402
from agent_os.integrations.langchain_adapter import LangChainKernel  # noqa: E402
from agent_os.integrations.llamaindex_adapter import LlamaIndexKernel  # noqa: E402
from agent_os.integrations.maf_adapter import MAFKernel  # noqa: E402
from agent_os.integrations.mistral_adapter import MistralKernel  # noqa: E402
from agent_os.integrations.openai_adapter import OpenAIKernel  # noqa: E402
from agent_os.integrations.pydantic_ai_adapter import PydanticAIKernel  # noqa: E402
from agent_os.integrations.semantic_kernel_adapter import (  # noqa: E402
    SemanticKernelWrapper,
)
from agent_os.integrations.smolagents_adapter import SmolagentsKernel  # noqa: E402

_SECRET = "user ssn 123-45-6789 matched rule pii-block"


class _StubRuntime:
    """Minimal stand-in for the policy runtime at the adapter seam."""

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
    return PolicyEvaluation(verdict="deny", reason_code="pii-block", message=_SECRET)


def _transform(value: str) -> PolicyEvaluation:
    return PolicyEvaluation(
        verdict="transform",
        reason_code="redact",
        transform=TransformResult(path="input.body", value=value),
    )


# (label, factory) for every kernel exposing the public evaluation seam.
_KERNELS: list[tuple[str, Any]] = [
    ("anthropic", lambda rt: AnthropicKernel(runtime=rt)),
    ("autogen", lambda rt: AutoGenKernel(runtime=rt)),
    ("bedrock", lambda rt: BedrockKernel(runtime=rt)),
    ("crewai", lambda rt: CrewAIKernel(runtime=rt)),
    ("gemini", lambda rt: GeminiKernel(runtime=rt)),
    ("google_adk", lambda rt: GoogleADKKernel(runtime=rt)),
    ("langchain", lambda rt: LangChainKernel(runtime=rt)),
    ("llamaindex", lambda rt: LlamaIndexKernel(runtime=rt)),
    ("maf", lambda rt: MAFKernel(runtime=rt)),
    ("mistral", lambda rt: MistralKernel(runtime=rt)),
    ("openai", lambda rt: OpenAIKernel(runtime=rt)),
    ("pydantic_ai", lambda rt: PydanticAIKernel(runtime=rt)),
    ("semantic_kernel", lambda rt: SemanticKernelWrapper(kernel=None, runtime=rt)),
    ("smolagents", lambda rt: SmolagentsKernel(runtime=rt)),
]

_TOOL_KERNELS = [p for p in _KERNELS if p[0] != "llamaindex"]
_OUTPUT_KERNELS = [
    p
    for p in _KERNELS
    if p[0] in {"crewai", "google_adk", "langchain", "llamaindex", "openai", "smolagents"}
]

_IDS = [label for label, _ in _KERNELS]


def _build(factory: Any, result: PolicyEvaluation) -> tuple[Any, _StubRuntime]:
    runtime = _StubRuntime(result)
    return factory(runtime), runtime


@pytest.mark.parametrize(("label", "factory"), _KERNELS, ids=_IDS)
def test_input_allow_passes_through(label: str, factory: Any) -> None:
    """An allow verdict leaves the request permitted and unmodified."""
    kernel, runtime = _build(factory, _allow())
    ctx = kernel.create_context(f"agent-{label}")

    result = kernel.evaluate_input(ctx, "hello world")

    assert result.allowed is True
    assert result.transformed_value is None
    assert runtime.calls, "adapter did not reach the runtime seam"


@pytest.mark.parametrize(("label", "factory"), _KERNELS, ids=_IDS)
def test_input_deny_blocks_without_leaking_policy_detail(
    label: str, factory: Any
) -> None:
    """A deny verdict blocks, and the raised message withholds policy detail."""
    kernel, _ = _build(factory, _deny())
    ctx = kernel.create_context(f"agent-{label}")

    result = kernel.evaluate_input(ctx, "exfiltrate the ssn")

    assert result.allowed is False
    assert result.reason == "pii-block"

    error = result.to_policy_violation(PolicyViolationError)
    assert _SECRET not in str(error)
    assert "123-45-6789" not in str(error)
    assert error.details["message"] == _SECRET


@pytest.mark.parametrize(("label", "factory"), _KERNELS, ids=_IDS)
def test_input_transform_exposes_replacement_body(label: str, factory: Any) -> None:
    """A transform verdict surfaces the replacement rather than the original."""
    kernel, _ = _build(factory, _transform("[redacted]"))
    ctx = kernel.create_context(f"agent-{label}")

    result = kernel.evaluate_input(ctx, "my card is 4111 1111 1111 1111")

    assert result.allowed is True
    assert result.transformed_value == "[redacted]"


@pytest.mark.parametrize(
    ("label", "factory"), _TOOL_KERNELS, ids=[p[0] for p in _TOOL_KERNELS]
)
def test_pre_tool_call_deny_blocks_before_execution(label: str, factory: Any) -> None:
    """A denied tool call is refused at the pre_tool_call intervention point."""
    kernel, runtime = _build(factory, _deny())
    ctx = kernel.create_context(f"agent-{label}")

    result = kernel.evaluate_pre_tool_call(
        ctx, tool_name="shell", args={"cmd": "rm -rf /"}, call_id="call-1"
    )

    assert result.allowed is False
    point, snapshot = runtime.calls[-1]
    assert point == "pre_tool_call"
    assert snapshot["tool_call"]["name"] == "shell"
    assert snapshot["tool_call"]["args"] == {"cmd": "rm -rf /"}


@pytest.mark.parametrize(
    ("label", "factory"), _TOOL_KERNELS, ids=[p[0] for p in _TOOL_KERNELS]
)
def test_pre_tool_call_charges_budget_after_snapshot(label: str, factory: Any) -> None:
    """Each tool call is charged after its snapshot, so the first sees zero."""
    kernel, runtime = _build(factory, _allow())
    ctx = kernel.create_context(f"agent-{label}")

    kernel.evaluate_pre_tool_call(ctx, tool_name="search", args={}, call_id="c1")
    kernel.evaluate_pre_tool_call(ctx, tool_name="search", args={}, call_id="c2")

    counts = [
        snapshot["envelope"]["budgets"]["tool_call_count"]
        for point, snapshot in runtime.calls
        if point == "pre_tool_call"
    ]
    assert counts == [0, 1]


@pytest.mark.parametrize(
    ("label", "factory"), _OUTPUT_KERNELS, ids=[p[0] for p in _OUTPUT_KERNELS]
)
def test_output_deny_blocks_disclosure(label: str, factory: Any) -> None:
    """A denied output is refused before it reaches the caller."""
    kernel, runtime = _build(factory, _deny())
    ctx = kernel.create_context(f"agent-{label}")

    result = kernel.evaluate_output(ctx, "here is the secret")

    assert result.allowed is False
    assert runtime.calls[-1][0] == "output"
