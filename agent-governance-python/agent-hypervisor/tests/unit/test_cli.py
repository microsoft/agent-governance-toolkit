# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the session CLI commands."""

from __future__ import annotations

import json

import pytest

from hypervisor.cli.formatters import format_output
from hypervisor.cli.session_commands import (
    build_parser,
    cmd_inspect,
    cmd_kill,
    cmd_list,
    dispatch,
)
from hypervisor.core import Hypervisor
from hypervisor.models import SessionConfig
from hypervisor.security.kill_switch import KillSwitch

# ── Fixtures ────────────────────────────────────────────────────────────


@pytest.fixture
def hv() -> Hypervisor:
    return Hypervisor()


@pytest.fixture
async def session_hv(hv: Hypervisor):
    """Hypervisor with one active session containing two agents."""
    session = await hv.create_session(
        config=SessionConfig(max_participants=5),
        creator_did="did:mesh:admin",
    )
    await hv.join_session(session.sso.session_id, "did:mesh:agent-1", sigma_raw=0.75)
    await hv.join_session(session.sso.session_id, "did:mesh:agent-2", sigma_raw=0.80)
    await hv.activate_session(session.sso.session_id)
    return hv, session.sso.session_id


# ── cmd_list ────────────────────────────────────────────────────────────


class TestCmdList:
    def test_list_empty(self, hv: Hypervisor):
        out = cmd_list(hv, "table")
        assert "No active sessions" in out

    @pytest.mark.asyncio
    async def test_list_table(self, session_hv):
        hv, sid = session_hv
        out = cmd_list(hv, "table")
        assert sid in out
        assert "active" in out

    @pytest.mark.asyncio
    async def test_list_json(self, session_hv):
        hv, sid = session_hv
        out = cmd_list(hv, "json")
        data = json.loads(out)
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["session_id"] == sid

    @pytest.mark.asyncio
    async def test_list_yaml(self, session_hv):
        hv, sid = session_hv
        out = cmd_list(hv, "yaml")
        assert "session_id:" in out
        assert sid in out


# ── cmd_inspect ─────────────────────────────────────────────────────────


class TestCmdInspect:
    def test_inspect_not_found(self, hv: Hypervisor):
        out = cmd_inspect(hv, "nonexistent", "table")
        assert "not found" in out

    @pytest.mark.asyncio
    async def test_inspect_table(self, session_hv):
        hv, sid = session_hv
        out = cmd_inspect(hv, sid, "table")
        assert "did:mesh:agent-1" in out
        assert "did:mesh:agent-2" in out
        assert "resource_usage" in out

    @pytest.mark.asyncio
    async def test_inspect_json(self, session_hv):
        hv, sid = session_hv
        out = cmd_inspect(hv, sid, "json")
        data = json.loads(out)
        assert data["session_id"] == sid
        assert data["state"] == "active"
        assert len(data["participants"]) == 2
        assert "resource_usage" in data
        assert "audit_log" in data

    @pytest.mark.asyncio
    async def test_inspect_json_fields(self, session_hv):
        """Verify participant fields in inspect output."""
        hv, sid = session_hv
        out = cmd_inspect(hv, sid, "json")
        data = json.loads(out)
        p = data["participants"][0]
        assert "agent_did" in p
        assert "ring" in p
        assert "eff_score" in p
        assert "is_active" in p

    @pytest.mark.asyncio
    async def test_inspect_yaml(self, session_hv):
        hv, sid = session_hv
        out = cmd_inspect(hv, sid, "yaml")
        assert "participants:" in out
        assert "resource_usage:" in out


# ── cmd_kill ────────────────────────────────────────────────────────────


class TestCmdKill:
    def test_kill_not_found(self, hv: Hypervisor):
        out = cmd_kill(hv, "nonexistent", "table")
        assert "not found" in out

    @pytest.mark.asyncio
    async def test_kill_session(self, session_hv):
        hv, sid = session_hv
        ks = KillSwitch()
        out = cmd_kill(hv, sid, "json", kill_switch=ks)
        data = json.loads(out)
        assert len(data) == 2
        agents = {r["agent_did"] for r in data}
        assert "did:mesh:agent-1" in agents
        assert "did:mesh:agent-2" in agents
        assert all(r["reason"] == "manual" for r in data)

    @pytest.mark.asyncio
    async def test_kill_deactivates_participants(self, session_hv):
        hv, sid = session_hv
        cmd_kill(hv, sid, "table")
        managed = hv.get_session(sid)
        assert managed is not None
        assert managed.sso.participant_count == 0  # All left


# ── Parser / dispatch ──────────────────────────────────────────────────


class TestParser:
    def test_build_parser_standalone(self):
        parser = build_parser()
        args = parser.parse_args(["--format", "json", "list"])
        assert args.output_format == "json"
        assert args.session_command == "list"

    def test_parse_inspect(self):
        parser = build_parser()
        args = parser.parse_args(["inspect", "session:abc123"])
        assert args.session_command == "inspect"
        assert args.session_id == "session:abc123"

    def test_parse_kill(self):
        parser = build_parser()
        args = parser.parse_args(["kill", "session:abc123"])
        assert args.session_command == "kill"

    def test_dispatch_list(self, hv: Hypervisor):
        parser = build_parser()
        args = parser.parse_args(["list"])
        out = dispatch(args, hv)
        assert "No active sessions" in out

    def test_dispatch_no_command(self, hv: Hypervisor):
        parser = build_parser()
        args = parser.parse_args([])
        out = dispatch(args, hv)
        assert "Error" in out


# ── Formatters ──────────────────────────────────────────────────────────


class TestFormatters:
    def test_json_output(self):
        data = [{"a": 1, "b": "hello"}]
        out = format_output(data, "json")
        parsed = json.loads(out)
        assert parsed == data

    def test_table_output(self):
        data = [{"name": "alice", "score": 100}, {"name": "bob", "score": 200}]
        out = format_output(data, "table")
        assert "NAME" in out
        assert "alice" in out
        assert "bob" in out

    def test_table_empty(self):
        out = format_output([], "table")
        assert "No results" in out

    def test_yaml_output(self):
        data = {"key": "value", "nested": {"a": 1}}
        out = format_output(data, "yaml")
        assert "key: value" in out
        assert "nested:" in out
        assert "  a: 1" in out

    def test_yaml_list(self):
        data = [{"x": 1}, {"x": 2}]
        out = format_output(data, "yaml")
        assert "- x: 1" in out
        assert "- x: 2" in out

    def test_yaml_none_and_bool(self):
        data = {"flag": True, "empty": None}
        out = format_output(data, "yaml")
        assert "flag: true" in out
        assert "empty: null" in out

    def test_dict_with_list_value(self):
        data = {"items": [{"a": 1}, {"a": 2}]}
        out = format_output(data, "table")
        assert "(2 items)" in out
