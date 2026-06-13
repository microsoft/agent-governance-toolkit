# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the MCP tool server example."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


EXAMPLE_PATH = (
    Path(__file__).resolve().parents[1]
    / "examples"
    / "01-mcp-tool-server"
    / "main.py"
)


def _load_example_module():
    spec = importlib.util.spec_from_file_location("mcp_tool_server_example", EXAMPLE_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.asyncio
async def test_blocked_tool_call_is_audited_and_scores_trust_down():
    module = _load_example_module()
    server = module.GovernedMCPServer()
    initial_score = server.trust_score

    result = await server.mcp_server.handle_request(
        "filesystem_read",
        {"path": "/etc/passwd"},
    )

    assert "error" in result
    assert "Policy violation" in result["error"]
    assert server.trust_score == initial_score - 10

    entries = server.audit_log.get_entries_for_agent(str(server.identity.did))
    assert len(entries) == 1
    assert entries[0].outcome == "denied"
    assert entries[0].action == "filesystem_read"
    assert entries[0].data["reason"] == "Access to /etc/passwd is blocked by policy"

    reward_state = server.reward_engine._agents[str(server.identity.did)]
    assert reward_state.recent_signals[-1].value == 0.0
