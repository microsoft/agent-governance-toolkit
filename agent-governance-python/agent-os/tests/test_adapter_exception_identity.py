# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Parity harness for adapter ``PolicyViolationError`` identity."""

from __future__ import annotations

import importlib

import pytest

from agent_os.exceptions import PolicyViolationError as canonical_PolicyViolationError


_PENDING_CONVERSION = pytest.mark.xfail(
    reason="Pending PR (d/eᵢ) conversion",
    strict=True,
)


@pytest.mark.parametrize(
    "module_path",
    [
        pytest.param(
            "agent_os.integrations.langchain_adapter",
            marks=_PENDING_CONVERSION,
            id="langchain_adapter",
        ),
        pytest.param(
            "agent_os.integrations.anthropic_adapter",
            marks=_PENDING_CONVERSION,
            id="anthropic_adapter",
        ),
        pytest.param(
            "agent_os.integrations.gemini_adapter",
            marks=_PENDING_CONVERSION,
            id="gemini_adapter",
        ),
        pytest.param(
            "agent_os.integrations.google_adk_adapter",
            marks=_PENDING_CONVERSION,
            id="google_adk_adapter",
        ),
        pytest.param(
            "agent_os.integrations.mistral_adapter",
            marks=_PENDING_CONVERSION,
            id="mistral_adapter",
        ),
        pytest.param(
            "agent_os.integrations.openai_adapter",
            marks=_PENDING_CONVERSION,
            id="openai_adapter",
        ),
        pytest.param(
            "agent_os.integrations.openai_agents_sdk",
            marks=_PENDING_CONVERSION,
            id="openai_agents_sdk",
        ),
        pytest.param(
            "agent_os.integrations.semantic_kernel_adapter",
            marks=_PENDING_CONVERSION,
            id="semantic_kernel_adapter",
        ),
        pytest.param(
            "agent_os.integrations.smolagents_adapter",
            marks=_PENDING_CONVERSION,
            id="smolagents_adapter",
        ),
    ],
)
def test_policy_violation_error_is_canonical(module_path: str) -> None:
    """Adapter must re-export the canonical PolicyViolationError."""
    mod = importlib.import_module(module_path)

    assert mod.PolicyViolationError is canonical_PolicyViolationError
