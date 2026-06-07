# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Source-level mediation contracts for public framework adapters.

These tests intentionally avoid importing optional framework SDKs. They
guard the adapter source seams that must route public model, tool, stream,
and output paths through AGT/ACS mediation before side effects or disclosure.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_os import integrations


INTEGRATIONS_DIR = Path(__file__).resolve().parents[1] / "src" / "agent_os" / "integrations"


V5_BRIDGE_CONTRACTS: dict[str, tuple[str, tuple[str, ...]]] = {
    "A2AGovernanceAdapter": ("a2a_adapter.py", ("_bridge.evaluate_input(",)),
    "AgentShieldKernel": (
        "agentshield_adapter.py",
        (
            "_bridge.evaluate_input(",
            "_bridge.evaluate_pre_tool_call(",
            "_bridge.evaluate_output(",
        ),
    ),
    "AnthropicKernel": (
        "anthropic_adapter.py",
        ("_bridge.evaluate_input(", "_bridge.evaluate_pre_tool_call("),
    ),
    "AutoGenKernel": (
        "autogen_adapter.py",
        ("_bridge.evaluate_input(", "_bridge.evaluate_pre_tool_call("),
    ),
    "BedrockKernel": (
        "bedrock_adapter.py",
        ("_bridge.evaluate_input(", "_bridge.evaluate_pre_tool_call("),
    ),
    "CrewAIKernel": (
        "crewai_adapter.py",
        (
            "_bridge.evaluate_input(",
            "_bridge.evaluate_pre_tool_call(",
            "_bridge.evaluate_output(",
        ),
    ),
    "GeminiKernel": (
        "gemini_adapter.py",
        ("_bridge.evaluate_input(", "_bridge.evaluate_pre_tool_call("),
    ),
    "GoogleADKKernel": (
        "google_adk_adapter.py",
        (
            "_bridge.evaluate_input(",
            "_bridge.evaluate_pre_tool_call(",
            "_bridge.evaluate_output(",
        ),
    ),
    "GuardrailsKernel": (
        "guardrails_adapter.py",
        ("_bridge.evaluate_input(", "_bridge.evaluate_output("),
    ),
    "LangChainKernel": (
        "langchain_adapter.py",
        (
            "_bridge.evaluate_input(",
            "_bridge.evaluate_pre_tool_call(",
            "_bridge.evaluate_output(",
        ),
    ),
    "LlamaIndexKernel": (
        "llamaindex_adapter.py",
        ("_bridge.evaluate_input(", "_bridge.evaluate_output("),
    ),
    "MAFKernel": (
        "maf_adapter.py",
        ("_bridge.evaluate_input(", "_bridge.evaluate_pre_tool_call("),
    ),
    "MistralKernel": (
        "mistral_adapter.py",
        ("_bridge.evaluate_input(", "_bridge.evaluate_pre_tool_call("),
    ),
    "OpenAIKernel": (
        "openai_adapter.py",
        (
            "_bridge.evaluate_input(",
            "_bridge.evaluate_pre_tool_call(",
            "_bridge.evaluate_output(",
        ),
    ),
    "PydanticAIKernel": (
        "pydantic_ai_adapter.py",
        ("_bridge.evaluate_input(", "_bridge.evaluate_pre_tool_call("),
    ),
    "SemanticKernelWrapper": (
        "semantic_kernel_adapter.py",
        ("_bridge.evaluate_input(", "_bridge.evaluate_pre_tool_call("),
    ),
    "SmolagentsKernel": (
        "smolagents_adapter.py",
        (
            "_bridge.evaluate_input(",
            "_bridge.evaluate_pre_tool_call(",
            "_bridge.evaluate_output(",
        ),
    ),
}

LEGACY_HOOK_CONTRACTS: dict[str, tuple[str, tuple[str, ...]]] = {
    "LangGraphKernel": (
        "langgraph_adapter.py",
        ("before_node_execution(", "before_tool_call(", "_wrap_nodes("),
    ),
    "OpenAIAgentsKernel": (
        "openai_agents_sdk.py",
        (
            "on_agent_start",
            "pre_execute(",
            "on_agent_end",
            "post_execute(",
            "on_tool_start",
        ),
    ),
}

NON_KERNEL_EXPORTS = {"GovernedSemanticKernel", "LlamaFirewallAdapter"}
DIRECT_SUPPORTED_ADAPTERS = {"AgentShieldKernel", "MAFKernel", "OpenAIAgentsKernel"}


def _source(filename: str) -> str:
    return (INTEGRATIONS_DIR / filename).read_text(encoding="utf-8")


def _public_adapter_names() -> set[str]:
    exported = {
        name
        for name in integrations._LAZY_ADAPTER_MAP  # noqa: SLF001 - public contract inventory
        if name.endswith(("Adapter", "Kernel", "Wrapper"))
    }
    return exported | DIRECT_SUPPORTED_ADAPTERS


def _assert_ordered(source: str, *markers: str) -> None:
    cursor = -1
    for marker in markers:
        index = source.find(marker, cursor + 1)
        assert index != -1, f"missing marker {marker!r}"
        assert index > cursor, f"marker {marker!r} is out of order"
        cursor = index


def test_public_adapter_mediation_contract_is_explicit() -> None:
    expected = (
        set(V5_BRIDGE_CONTRACTS)
        | set(LEGACY_HOOK_CONTRACTS)
        | NON_KERNEL_EXPORTS
    )

    assert _public_adapter_names() - expected == set()


@pytest.mark.parametrize("adapter_name", sorted(V5_BRIDGE_CONTRACTS))
def test_v5_bridge_adapters_route_declared_intervention_points(adapter_name: str) -> None:
    filename, required_calls = V5_BRIDGE_CONTRACTS[adapter_name]
    source = _source(filename)

    assert "get_runtime_bridge(" in source
    for call in required_calls:
        assert call in source, f"{adapter_name} must route through {call}"


@pytest.mark.parametrize("adapter_name", sorted(LEGACY_HOOK_CONTRACTS))
def test_legacy_hook_adapters_keep_pre_side_effect_gates(adapter_name: str) -> None:
    filename, required_markers = LEGACY_HOOK_CONTRACTS[adapter_name]
    source = _source(filename)

    for marker in required_markers:
        assert marker in source, f"{adapter_name} must keep mediation marker {marker}"


def test_langchain_stream_buffers_before_yielding() -> None:
    source = _source("langchain_adapter.py")

    _assert_ordered(
        source,
        "chunks = list(self._original.stream",
        "bridge_result = self._kernel.evaluate_output",
        "yield from chunks",
    )
    _assert_ordered(
        source,
        "async def astream",
        "chunks = [chunk async for chunk in stream]",
        "for chunk in chunks:",
    )
    assert "async def astream_log" in source
    assert "async def astream_events" in source


def test_openai_stream_buffers_before_yielding() -> None:
    source = _source("openai_adapter.py")

    _assert_ordered(
        source,
        "events = []",
        "bridge_result = self._kernel.evaluate_output",
        "yield from events",
    )


def test_llamaindex_stream_chat_post_checks_before_replay() -> None:
    source = _source("llamaindex_adapter.py")

    _assert_ordered(
        source,
        "response = self._original.stream_chat",
        "return self._post_stream_response(response)",
    )
    _assert_ordered(
        source,
        "async def astream_chat",
        "self._enforce_budget()",
        "response = await self._post_async_stream_response(response)",
        "self._ctx.call_count += 1",
        "return response",
    )
    _assert_ordered(
        source,
        "def stream_chat",
        "self._enforce_budget()",
        "response = self._post_stream_response(response)",
        "self._ctx.call_count += 1",
        "return response",
    )
    _assert_ordered(
        source,
        "aggregated =",
        "checked = self._post(aggregated)",
        "return iter(chunks)",
    )


def test_bedrock_action_events_are_checked_before_yield() -> None:
    source = _source("bedrock_adapter.py")

    _assert_ordered(
        source,
        "bridge_result = self._kernel.evaluate_pre_tool_call",
        "raise PolicyViolationError.from_check_result",
        "yield event",
    )
