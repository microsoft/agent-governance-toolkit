# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for CLI."""

from agent_sre.cli.main import cli


class TestCLI:
    def test_version(self, capsys):
        assert cli(["version"]) == 0
        assert "0.1.0" in capsys.readouterr().out

    def test_info(self, capsys):
        assert cli(["info"]) == 0
        output = capsys.readouterr().out
        assert "agent-sre" in output
        assert "slo" in output

    def test_slo_status(self, capsys):
        assert cli(["slo", "status"]) == 0

    def test_slo_list(self, capsys):
        assert cli(["slo", "list"]) == 0

    def test_cost_summary(self, capsys):
        assert cli(["cost", "summary"]) == 0

    def test_no_args(self):
        assert cli([]) == 1

    def test_slo_no_subcommand(self):
        assert cli(["slo"]) == 1

    def test_cost_no_subcommand(self):
        assert cli(["cost"]) == 1
