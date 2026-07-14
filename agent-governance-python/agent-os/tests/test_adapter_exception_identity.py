# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Parity harness for adapter ``PolicyViolationError`` identity."""

from __future__ import annotations

import importlib

import pytest

from agent_os.exceptions import PolicyViolationError as canonical_PolicyViolationError


@pytest.mark.parametrize(
    "module_path",
    [
        "agent_os.integrations.anthropic_adapter",
        "agent_os.integrations.gemini_adapter",
        "agent_os.integrations.google_adk_adapter",
        "agent_os.integrations.guardrails_adapter",
        "agent_os.integrations.langchain_adapter",
        "agent_os.integrations.llamaindex_adapter",
        "agent_os.integrations.maf_adapter",
        "agent_os.integrations.mistral_adapter",
        "agent_os.integrations.openai_adapter",
        "agent_os.integrations.openai_agents_sdk",
        "agent_os.integrations.semantic_kernel_adapter",
        "agent_os.integrations.smolagents_adapter",
    ],
)
def test_policy_violation_error_is_canonical(module_path: str) -> None:
    """Adapter must re-export the canonical PolicyViolationError."""
    mod = importlib.import_module(module_path)

    assert mod.PolicyViolationError is canonical_PolicyViolationError
