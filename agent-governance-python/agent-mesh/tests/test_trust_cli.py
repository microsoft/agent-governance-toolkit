# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the AgentMesh Trust Network CLI."""

import json

import pytest
from click.testing import CliRunner

from agentmesh.cli.main import app
from agentmesh.cli.trust_cli import (
    trust,
    _trust_level_label,
    _trust_level_style,
    _format_datetime,
    _get_demo_peers,
    _get_demo_history,
)


@pytest.fixture
def runner():
    """Create a Click CLI test runner."""
    return CliRunner()


# ---------------------------------------------------------------------------
# Helper function tests
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_trust_level_verified_partner(self):
        assert _trust_level_label(950) == "verified_partner"
        assert _trust_level_label(900) == "verified_partner"

    def test_trust_level_trusted(self):
        assert _trust_level_label(700) == "trusted"
        assert _trust_level_label(850) == "trusted"

    def test_trust_level_standard(self):
        assert _trust_level_label(500) == "standard"
        assert _trust_level_label(600) == "standard"

    def test_trust_level_probationary(self):
        assert _trust_level_label(300) == "probationary"
        assert _trust_level_label(400) == "probationary"

    def test_trust_level_untrusted(self):
        assert _trust_level_label(0) == "untrusted"
        assert _trust_level_label(299) == "untrusted"

    def test_trust_level_style_returns_string(self):
        for level in ("verified_partner", "trusted", "standard", "probationary", "untrusted"):
            style = _trust_level_style(level)
            assert isinstance(style, str)
            assert len(style) > 0

    def test_format_datetime_none(self):
        assert _format_datetime(None) == "N/A"

    def test_format_datetime_valid(self):
        from datetime import datetime
        dt = datetime(2026, 1, 15, 10, 30, 0)
        assert _format_datetime(dt) == "2026-01-15 10:30:00"

    def test_demo_peers_returns_dict(self):
        peers = _get_demo_peers()
        assert isinstance(peers, dict)
        assert len(peers) >= 3

    def test_demo_history_returns_list(self):
        history = _get_demo_history("did:mesh:agent-alpha-001")
        assert isinstance(history, list)
        assert len(history) > 0
        assert "score" in history[0]
        assert "timestamp" in history[0]


# ---------------------------------------------------------------------------
# trust list
# ---------------------------------------------------------------------------

class TestTrustList:
    def test_list_table(self, runner):
        result = runner.invoke(app, ["trust", "list"])
        assert result.exit_code == 0
        assert "alpha" in result.output or "Agent" in result.output

    def test_list_json(self, runner):
        result = runner.invoke(app, ["trust", "list", "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) >= 3
        assert "agent_id" in data[0]
        assert "trust_score" in data[0]

    def test_list_json_flag(self, runner):
        result = runner.invoke(app, ["trust", "list", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)

    def test_list_yaml(self, runner):
        result = runner.invoke(app, ["trust", "list", "--format", "yaml"])
        assert result.exit_code == 0
        assert "agent_id" in result.output

    def test_list_min_score(self, runner):
        result = runner.invoke(app, ["trust", "list", "--format", "json", "--min-score", "700"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        for entry in data:
            assert entry["trust_score"] >= 700

    def test_list_verified_only(self, runner):
        result = runner.invoke(app, ["trust", "list", "--format", "json", "--verified-only"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        for entry in data:
            assert entry["verified"] is True


# ---------------------------------------------------------------------------
# trust inspect
# ---------------------------------------------------------------------------

class TestTrustInspect:
    def test_inspect_table(self, runner):
        result = runner.invoke(app, ["trust", "inspect", "did:mesh:agent-alpha-001"])
        assert result.exit_code == 0
        assert "alpha" in result.output

    def test_inspect_json(self, runner):
        result = runner.invoke(app, ["trust", "inspect", "did:mesh:agent-alpha-001", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["agent_id"] == "did:mesh:agent-alpha-001"
        assert data["trust_score"] == 920

    def test_inspect_yaml(self, runner):
        result = runner.invoke(
            app, ["trust", "inspect", "did:mesh:agent-beta-002", "--format", "yaml"]
        )
        assert result.exit_code == 0
        assert "beta" in result.output

    def test_inspect_not_found(self, runner):
        result = runner.invoke(app, ["trust", "inspect", "did:mesh:nonexistent"])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# trust history
# ---------------------------------------------------------------------------

class TestTrustHistory:
    def test_history_table(self, runner):
        result = runner.invoke(app, ["trust", "history", "did:mesh:agent-alpha-001"])
        assert result.exit_code == 0
        assert "Score" in result.output or "score" in result.output.lower()

    def test_history_json(self, runner):
        result = runner.invoke(
            app, ["trust", "history", "did:mesh:agent-alpha-001", "--json"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["agent_id"] == "did:mesh:agent-alpha-001"
        assert isinstance(data["history"], list)

    def test_history_limit(self, runner):
        result = runner.invoke(
            app, ["trust", "history", "did:mesh:agent-alpha-001", "--json", "--limit", "3"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["history"]) == 3

    def test_history_unknown_agent(self, runner):
        """History for unknown agent still returns default data."""
        result = runner.invoke(
            app, ["trust", "history", "did:mesh:unknown", "--json"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data["history"]) > 0


# ---------------------------------------------------------------------------
# trust graph
# ---------------------------------------------------------------------------

class TestTrustGraph:
    def test_graph_ascii(self, runner):
        result = runner.invoke(app, ["trust", "graph"])
        assert result.exit_code == 0
        assert "Trust Network Graph" in result.output
        assert "Connections" in result.output

    def test_graph_mermaid(self, runner):
        result = runner.invoke(app, ["trust", "graph", "--format", "mermaid"])
        assert result.exit_code == 0
        assert "graph LR" in result.output

    def test_graph_json(self, runner):
        result = runner.invoke(app, ["trust", "graph", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "nodes" in data
        assert "edges" in data
        assert len(data["nodes"]) >= 3


# ---------------------------------------------------------------------------
# trust revoke
# ---------------------------------------------------------------------------

class TestTrustRevoke:
    def test_revoke_with_force(self, runner):
        result = runner.invoke(
            app,
            ["trust", "revoke", "did:mesh:agent-alpha-001", "--force"],
        )
        assert result.exit_code == 0
        assert "Revoked" in result.output or "revoked" in result.output.lower()

    def test_revoke_json(self, runner):
        result = runner.invoke(
            app,
            ["trust", "revoke", "did:mesh:agent-alpha-001", "--force", "--json"],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["action"] == "revoked"
        assert data["new_score"] == 0

    def test_revoke_custom_reason(self, runner):
        result = runner.invoke(
            app,
            [
                "trust", "revoke", "did:mesh:agent-beta-002",
                "--force", "--reason", "Compromised",
                "--json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["reason"] == "Compromised"

    def test_revoke_not_found(self, runner):
        result = runner.invoke(
            app, ["trust", "revoke", "did:mesh:nonexistent", "--force"]
        )
        assert result.exit_code != 0

    def test_revoke_cancelled(self, runner):
        """Without --force, answering 'n' cancels revocation."""
        result = runner.invoke(
            app,
            ["trust", "revoke", "did:mesh:agent-alpha-001"],
            input="n\n",
        )
        assert result.exit_code == 0
        assert "cancelled" in result.output.lower()


# ---------------------------------------------------------------------------
# trust attest
# ---------------------------------------------------------------------------

class TestTrustAttest:
    def test_attest_table(self, runner):
        result = runner.invoke(
            app, ["trust", "attest", "did:mesh:agent-beta-002"]
        )
        assert result.exit_code == 0
        assert "Attested" in result.output or "attested" in result.output.lower()

    def test_attest_json(self, runner):
        result = runner.invoke(
            app, ["trust", "attest", "did:mesh:agent-beta-002", "--json"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["action"] == "attested"
        assert data["new_score"] > data["previous_score"]

    def test_attest_custom_boost(self, runner):
        result = runner.invoke(
            app,
            [
                "trust", "attest", "did:mesh:agent-gamma-003",
                "--score-boost", "100", "--json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["score_boost"] == 100
        assert data["new_score"] == data["previous_score"] + 100

    def test_attest_score_capped_at_1000(self, runner):
        result = runner.invoke(
            app,
            [
                "trust", "attest", "did:mesh:agent-alpha-001",
                "--score-boost", "500", "--json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["new_score"] <= 1000

    def test_attest_not_found(self, runner):
        result = runner.invoke(
            app, ["trust", "attest", "did:mesh:nonexistent"]
        )
        assert result.exit_code != 0

    def test_attest_custom_note(self, runner):
        result = runner.invoke(
            app,
            [
                "trust", "attest", "did:mesh:agent-beta-002",
                "--note", "Passed security audit", "--json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["note"] == "Passed security audit"


# ---------------------------------------------------------------------------
# trust help
# ---------------------------------------------------------------------------

class TestTrustHelp:
    def test_trust_help(self, runner):
        result = runner.invoke(app, ["trust", "--help"])
        assert result.exit_code == 0
        assert "trust" in result.output.lower()

    def test_subcommand_help(self, runner):
        for cmd in ("list", "inspect", "history", "graph", "revoke", "attest", "report"):
            result = runner.invoke(app, ["trust", cmd, "--help"])
            assert result.exit_code == 0, f"Help for 'trust {cmd}' failed"


# ---------------------------------------------------------------------------
# trust report
# ---------------------------------------------------------------------------

class TestTrustReport:
    def test_report_table(self, runner):
        result = runner.invoke(app, ["trust", "report"])
        assert result.exit_code == 0
        assert "Trust Network" in result.output or "Agent" in result.output
        assert "Total agents" in result.output

    def test_report_json(self, runner):
        result = runner.invoke(app, ["trust", "report", "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) >= 3
        for agent in data:
            assert "agent_id" in agent
            assert "trust_score" in agent
            assert "trust_level" in agent
            assert "successful_tasks" in agent
            assert "failed_tasks" in agent
            assert "last_activity" in agent
            assert isinstance(agent["successful_tasks"], int)
            assert isinstance(agent["failed_tasks"], int)

    def test_report_json_flag(self, runner):
        result = runner.invoke(app, ["trust", "report", "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)

    def test_report_scores_in_range(self, runner):
        result = runner.invoke(app, ["trust", "report", "--json"])
        data = json.loads(result.output)
        for agent in data:
            assert 0 <= agent["trust_score"] <= 1000

    def test_report_levels_valid(self, runner):
        result = runner.invoke(app, ["trust", "report", "--json"])
        data = json.loads(result.output)
        valid_levels = {"Verified Partner", "Trusted", "Standard", "Probationary", "Untrusted",
                        "verified_partner", "trusted", "standard", "probationary", "untrusted"}
        for agent in data:
            assert agent["trust_level"] in valid_levels
