# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tools that decide or change state must write the audit log.

``GetAuditLogTool.log_entry`` used to have no caller in the server, so
``get_audit_log`` and ``audit://`` always returned nothing even after a
policy block. Each test below names the call that must leave a trace.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from mcp_kernel_server.server import KernelMCPServer, ServerConfig
from mcp_kernel_server.tools import GetAuditLogTool


@pytest.fixture
def server():
    GetAuditLogTool._audit_log.clear()
    yield KernelMCPServer(ServerConfig())
    GetAuditLogTool._audit_log.clear()


async def _audit(server, **filters):
    args = {"limit": 100}
    if filters:
        args["filter"] = filters
    result = await server.handle_call_tool("get_audit_log", args)
    return json.loads(result["content"][0]["text"])


@pytest.mark.asyncio
async def test_kernel_execute_block_is_audited(server):
    await server.handle_call_tool(
        "kernel_execute",
        {"action": "file_write", "agent_id": "a1", "policies": ["read_only"]},
    )
    data = await _audit(server, type="blocked")
    assert data["returned"] == 1
    assert data["logs"][0]["agent_id"] == "a1"
    assert "read_only" in data["logs"][0]["reason"]


@pytest.mark.asyncio
async def test_kernel_execute_allow_is_audited(server):
    await server.handle_call_tool(
        "kernel_execute",
        {"action": "file_read", "params": {"path": "x"}, "agent_id": "a1"},
    )
    data = await _audit(server, type="allowed")
    assert data["returned"] == 1
    assert data["logs"][0]["action"] == "file_read"


@pytest.mark.asyncio
async def test_unsafe_code_verdict_is_audited_without_the_code(server):
    code = "import os; os.system('rm -rf /')"
    await server.handle_call_tool(
        "verify_code_safety",
        {"code": code, "language": "python", "context": {"agent_id": "a2"}},
    )
    data = await _audit(server, agent_id="a2")
    assert data["returned"] == 1
    entry = data["logs"][0]
    assert entry["type"] == "blocked"
    assert entry["violations"]
    assert code not in json.dumps(entry)


@pytest.mark.asyncio
async def test_failed_trust_verification_is_audited(server):
    await server.handle_call_tool(
        "iatp_verify",
        {"remote_agent_id": "r1", "required_trust_level": "verified_partner"},
    )
    data = await _audit(server, agent_id="r1")
    assert data["returned"] == 1
    assert data["logs"][0]["type"] == "blocked"
    assert data["logs"][0]["reason"]


@pytest.mark.asyncio
async def test_reputation_slash_is_audited_but_query_is_not(server):
    await server.handle_call_tool(
        "iatp_reputation", {"action": "query", "agent_id": "a3"}
    )
    assert (await _audit(server))["total"] == 0
    await server.handle_call_tool(
        "iatp_reputation",
        {"action": "slash", "agent_id": "a3", "slash_reason": "drift",
         "slash_severity": "high"},
    )
    data = await _audit(server, type="reputation_slash")
    assert data["returned"] == 1
    assert data["logs"][0]["new_score"] < data["logs"][0]["previous_score"]


@pytest.mark.asyncio
async def test_reputation_slash_audit_records_reason_length_not_text(server):
    reason = "caller supplied free text " * 400
    await server.handle_call_tool(
        "iatp_reputation",
        {"action": "slash", "agent_id": "a4", "slash_reason": reason,
         "slash_severity": "low"},
    )
    data = await _audit(server, type="reputation_slash")
    assert data["returned"] == 1
    entry = data["logs"][0]
    assert "reason" not in entry
    assert entry["reason_length"] == len(reason)
    assert "caller supplied free text" not in json.dumps(entry)


@pytest.mark.asyncio
async def test_cmvk_calls_are_audited_without_claim_text(server):
    await server.handle_call_tool("cmvk_verify", {"claim": "secret claim text"})
    await server.handle_call_tool(
        "cmvk_review", {"code": "eval(input())", "language": "python"}
    )
    data = await _audit(server)
    assert {e["type"] for e in data["logs"]} == {"cmvk_verify", "cmvk_review"}
    assert "secret claim text" not in json.dumps(data)


@pytest.mark.asyncio
async def test_stats_count_only_allowed_and_blocked(server):
    await server.handle_call_tool("cmvk_verify", {"claim": "x"})
    await server.handle_call_tool(
        "kernel_execute",
        {"action": "file_write", "agent_id": "a1", "policies": ["read_only"]},
    )
    stats = (await _audit(server))["stats"]
    assert stats == {"blocked_total": 1, "allowed_total": 0}


@pytest.mark.asyncio
async def test_audit_resource_returns_entries_for_that_agent(server):
    await server.handle_call_tool(
        "kernel_execute",
        {"action": "file_write", "agent_id": "a1", "policies": ["read_only"]},
    )
    await server.handle_call_tool(
        "kernel_execute",
        {"action": "file_write", "agent_id": "a9", "policies": ["read_only"]},
    )
    result = await server.handle_read_resource("audit://a1/log")
    content = json.loads(result["contents"][0]["text"])
    assert [e["agent_id"] for e in content["entries"]] == ["a1"]
