# Copyright (c) Microsoft Corporation. Licensed under the MIT License.
"""Tests for the CLI."""

from click.testing import CliRunner

from agent_discovery.cli.main import main
from agent_discovery.inventory import AgentInventory


class TestCLI:
    def setup_method(self):
        self.runner = CliRunner()

    def test_help(self):
        result = self.runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "Agent Discovery" in result.output

    def test_version(self):
        result = self.runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_scan_help(self):
        result = self.runner.invoke(main, ["scan", "--help"])
        assert result.exit_code == 0
        assert "scanner" in result.output.lower()

    def test_inventory_help(self):
        result = self.runner.invoke(main, ["inventory", "--help"])
        assert result.exit_code == 0

    def test_reconcile_help(self):
        result = self.runner.invoke(main, ["reconcile", "--help"])
        assert result.exit_code == 0

    def test_scan_config_only(self, tmp_path):
        """Run a config scan on an empty directory."""
        result = self.runner.invoke(
            main,
            ["scan", "-s", "config", "-p", str(tmp_path), "--storage", str(tmp_path / "inv.json")],
        )
        assert result.exit_code == 0
        assert "Agent Discovery Scan" in result.output

    def test_inventory_empty(self, tmp_path):
        """View empty inventory."""
        result = self.runner.invoke(
            main,
            ["inventory", "--storage", str(tmp_path / "nonexistent.json")],
        )
        assert result.exit_code == 0
        assert "No agents" in result.output

    def test_reconcile_empty(self, tmp_path):
        """Reconcile with empty inventory."""
        result = self.runner.invoke(
            main,
            ["reconcile", "--storage", str(tmp_path / "nonexistent.json")],
        )
        assert result.exit_code == 0
        assert "No agents" in result.output

    def test_scan_saves_risk_tags(self, tmp_path):
        (tmp_path / "crewai.yaml").write_text("agents: []\n", encoding="utf-8")
        storage = tmp_path / "inv.json"
        result = self.runner.invoke(
            main, ["scan", "-s", "config", "-p", str(tmp_path), "--storage", str(storage)]
        )
        assert result.exit_code == 0

        agents = AgentInventory(storage_path=storage).agents
        assert len(agents) == 1
        assert agents[0].tags["risk_level"]
        assert agents[0].tags["risk_score"]

    def test_reconcile_saves_statuses(self, tmp_path):
        (tmp_path / "crewai.yaml").write_text("agents: []\n", encoding="utf-8")
        storage = tmp_path / "inv.json"
        self.runner.invoke(
            main, ["scan", "-s", "config", "-p", str(tmp_path), "--storage", str(storage)]
        )
        result = self.runner.invoke(main, ["reconcile", "--storage", str(storage)])
        assert result.exit_code == 0

        result = self.runner.invoke(main, ["inventory", "--storage", str(storage), "-o", "summary"])
        assert '"shadow": 1' in result.output
