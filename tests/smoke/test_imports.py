# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Lightweight import smoke tests for the Python packages."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest


pytestmark = pytest.mark.skipif(
    sys.version_info < (3, 11),
    reason="agent-mesh declares Python >=3.11",
)


ROOT = Path(__file__).resolve().parents[2]
PYTHON_PACKAGE_SRCS = [
    ROOT / "agent-governance-python" / "agent-os" / "src",
    ROOT / "agent-governance-python" / "agent-sre" / "src",
    ROOT / "agent-governance-python" / "agent-mesh" / "src",
]


def _add_package_srcs_to_path() -> None:
    for path in reversed(PYTHON_PACKAGE_SRCS):
        sys.path.insert(0, str(path))


def test_python_packages_import_and_create_basic_objects() -> None:
    _add_package_srcs_to_path()

    agent_os = importlib.import_module("agent_os")
    agent_sre = importlib.import_module("agent_sre")
    agentmesh = importlib.import_module("agentmesh")

    agent_config = agent_os.AgentConfig(
        agent_id="smoke-agent",
        policies=["read_only"],
    )
    assert agent_config.agent_id == "smoke-agent"

    task_success_rate = importlib.import_module(
        "agent_sre.slo.indicators",
    ).TaskSuccessRate(target=0.95)
    slo = agent_sre.SLO(
        "smoke-slo",
        indicators=[task_success_rate],
        error_budget=agent_sre.ErrorBudget(total=0.05),
    )
    assert slo.name == "smoke-slo"

    client = agentmesh.AgentMeshClient(
        "smoke-agent",
        capabilities=["data.read"],
    )
    result = client.execute_with_governance("data.read")

    assert client.agent_did.startswith("did:agentmesh:")
    assert result.allowed is True
