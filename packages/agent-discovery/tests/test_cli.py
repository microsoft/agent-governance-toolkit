"""Tests for the CLI."""

from click.testing import CliRunner

from agent_discovery.cli.main import main


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
