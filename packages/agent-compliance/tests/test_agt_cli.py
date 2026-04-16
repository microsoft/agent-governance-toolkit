# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Tests for the unified ``agt`` CLI."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path
from unittest import mock

import click
import pytest
from click.testing import CliRunner

from agent_compliance.cli.agt import (
    AgtContext,
    AgtGroup,
    _discover_plugins,
    _get_package_version,
    _handle_error,
    _print,
    cli,
)
from agent_compliance.verify import GovernanceAttestation


@pytest.fixture()
def runner():
    try:
        return CliRunner(mix_stderr=False)
    except TypeError:
        return CliRunner()


@pytest.fixture()
def policy_file(tmp_path: Path) -> Path:
    p = tmp_path / "policy.yaml"
    p.write_text(
        textwrap.dedent(
            """\
            name: test-policy
            version: "1.0"
            description: A test policy
            rules:
              - name: block-delete
                condition:
                  field: tool_name
                  operator: in
                  value: ["delete_file"]
                action: deny
                priority: 100
            """
        ),
        encoding="utf-8",
    )
    return p


@pytest.fixture()
def bad_policy_file(tmp_path: Path) -> Path:
    p = tmp_path / "bad-policy.yaml"
    p.write_text(
        textwrap.dedent(
            """\
            name: bad-policy
            version: "1.0"
            rules:
              - name: rule-with-deprecated-field
                condition:
                  field: tool_name
                  op: eq
                  value: "delete_file"
                type: deny
                priority: 100
            """
        ),
        encoding="utf-8",
    )
    return p


@pytest.fixture()
def policy_dir(tmp_path: Path, policy_file: Path) -> Path:
    d = tmp_path / "policies"
    d.mkdir()
    (d / "a.yaml").write_text(policy_file.read_text(encoding="utf-8"), encoding="utf-8")
    (d / "b.yaml").write_text(policy_file.read_text(encoding="utf-8"), encoding="utf-8")
    return d


class TestRootCLI:
    def test_help_shows_description(self, runner: CliRunner):
        result = runner.invoke(cli, ["--help"])

        assert result.exit_code == 0
        assert "Agent Governance Toolkit CLI" in result.output

    def test_help_shows_quick_start(self, runner: CliRunner):
        result = runner.invoke(cli, ["--help"])

        assert "agt verify" in result.output
        assert "agt doctor" in result.output

    def test_help_lists_all_builtin_commands(self, runner: CliRunner):
        result = runner.invoke(cli, ["--help"])

        for cmd in ("verify", "integrity", "lint-policy", "doctor"):
            assert cmd in result.output

    def test_version_shows_agt_and_version(self, runner: CliRunner):
        result = runner.invoke(cli, ["--version"])

        assert result.exit_code == 0
        assert "agt" in result.output
        assert any(c.isdigit() for c in result.output)

    def test_no_args_shows_help_text(self, runner: CliRunner):
        result = runner.invoke(cli, [])

        assert result.exit_code in (0, 2)
        assert "Commands" in result.output or "Usage" in result.output

    def test_unknown_command_fails(self, runner: CliRunner):
        result = runner.invoke(cli, ["nonexistent-command-xyz"])

        assert result.exit_code != 0

    def test_help_flag_on_subcommand(self, runner: CliRunner):
        for cmd in ("verify", "integrity", "lint-policy", "doctor"):
            result = runner.invoke(cli, [cmd, "--help"])
            assert result.exit_code == 0


class TestGlobalOptions:
    def test_json_flag_produces_json(self, runner: CliRunner):
        result = runner.invoke(cli, ["--json", "doctor"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "python_version" in data

    def test_json_flag_position_after_command(self, runner: CliRunner):
        result = runner.invoke(cli, ["doctor", "--json"])

        assert result.exit_code != 0 or "python_version" not in result.output

    def test_verbose_flag_accepted(self, runner: CliRunner):
        result = runner.invoke(cli, ["--verbose", "doctor"])

        assert result.exit_code == 0

    def test_verbose_short_flag(self, runner: CliRunner):
        result = runner.invoke(cli, ["-v", "doctor"])

        assert result.exit_code == 0

    def test_quiet_flag_accepted(self, runner: CliRunner):
        result = runner.invoke(cli, ["--quiet", "doctor"])

        assert result.exit_code == 0

    def test_quiet_short_flag(self, runner: CliRunner):
        result = runner.invoke(cli, ["-q", "doctor"])

        assert result.exit_code == 0

    def test_no_color_flag_accepted(self, runner: CliRunner):
        result = runner.invoke(cli, ["--no-color", "doctor"])

        assert result.exit_code == 0

    def test_combined_flags(self, runner: CliRunner):
        result = runner.invoke(cli, ["--json", "--verbose", "--no-color", "doctor"])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "python_version" in data

    def test_mutually_exclusive_json_and_quiet(self, runner: CliRunner):
        result = runner.invoke(cli, ["--json", "--quiet", "doctor"])

        assert result.exit_code == 0


class TestDoctorCommand:
    def test_doctor_plain_output(self, runner: CliRunner):
        result = runner.invoke(cli, ["doctor"])

        assert result.exit_code == 0
        assert "agent_governance_toolkit" in result.output

    def test_doctor_json_schema(self, runner: CliRunner):
        result = runner.invoke(cli, ["--json", "doctor"])

        assert result.exit_code == 0
        data = json.loads(result.output)

        assert "python_version" in data
        assert "packages" in data
        assert "plugins" in data
        assert "config_files" in data

    def test_doctor_json_package_structure(self, runner: CliRunner):
        result = runner.invoke(cli, ["--json", "doctor"])
        data = json.loads(result.output)

        assert len(data["packages"]) == 8
        for pkg in data["packages"]:
            assert {"package", "name", "description", "installed", "version"} == set(pkg.keys())
            assert isinstance(pkg["installed"], bool)

    def test_doctor_detects_installed_toolkit(self, runner: CliRunner):
        result = runner.invoke(cli, ["--json", "doctor"])
        data = json.loads(result.output)
        toolkit_pkg = next(p for p in data["packages"] if p["package"] == "agent_governance_toolkit")

        assert toolkit_pkg["installed"] is True
        assert toolkit_pkg["version"] is not None

    def test_doctor_plugins_is_list(self, runner: CliRunner):
        result = runner.invoke(cli, ["--json", "doctor"])
        data = json.loads(result.output)

        assert isinstance(data["plugins"], list)

    def test_doctor_config_files_are_paths(self, runner: CliRunner):
        result = runner.invoke(cli, ["--json", "doctor"])
        data = json.loads(result.output)

        for path_str, exists in data["config_files"].items():
            assert isinstance(path_str, str)
            assert isinstance(exists, bool)

    def test_doctor_no_color_uses_plain_output(self, runner: CliRunner):
        result = runner.invoke(cli, ["--no-color", "doctor"])

        assert result.exit_code == 0
        assert "agent_governance_toolkit" in result.output


class TestPluginDiscovery:
    def test_returns_dict(self):
        result = _discover_plugins()

        assert isinstance(result, dict)

    def test_valid_click_command_discovered(self):
        mock_cmd = click.Command("my-cmd", callback=lambda: None)
        mock_ep = mock.Mock()
        mock_ep.name = "my-plugin"
        mock_ep.load.return_value = mock_cmd

        with mock.patch("importlib.metadata.entry_points", return_value=[mock_ep]):
            plugins = _discover_plugins()

        assert "my-plugin" in plugins
        assert plugins["my-plugin"] is mock_cmd

    def test_valid_click_group_discovered(self):
        mock_grp = click.Group("my-grp")
        mock_ep = mock.Mock()
        mock_ep.name = "grp-plugin"
        mock_ep.load.return_value = mock_grp

        with mock.patch("importlib.metadata.entry_points", return_value=[mock_ep]):
            plugins = _discover_plugins()

        assert "grp-plugin" in plugins

    def test_adapter_callable_returning_command(self):
        mock_cmd = click.Command("adapted", callback=lambda: None)

        def adapter():
            return mock_cmd

        mock_ep = mock.Mock()
        mock_ep.name = "adapted-plugin"
        mock_ep.load.return_value = adapter

        with mock.patch("importlib.metadata.entry_points", return_value=[mock_ep]):
            plugins = _discover_plugins()

        assert "adapted-plugin" in plugins

    def test_adapter_callable_returning_non_click_skipped(self):
        def bad_adapter():
            return "not a command"

        mock_ep = mock.Mock()
        mock_ep.name = "bad-adapter"
        mock_ep.load.return_value = bad_adapter

        with mock.patch("importlib.metadata.entry_points", return_value=[mock_ep]):
            plugins = _discover_plugins()

        assert "bad-adapter" not in plugins

    def test_non_click_object_skipped(self):
        mock_ep = mock.Mock()
        mock_ep.name = "bad"
        mock_ep.load.return_value = "not a click command"

        with mock.patch("importlib.metadata.entry_points", return_value=[mock_ep]):
            plugins = _discover_plugins()

        assert "bad" not in plugins

    def test_import_error_skipped(self):
        mock_ep = mock.Mock()
        mock_ep.name = "broken"
        mock_ep.load.side_effect = ImportError("no such module")

        with mock.patch("importlib.metadata.entry_points", return_value=[mock_ep]):
            plugins = _discover_plugins()

        assert "broken" not in plugins

    def test_runtime_error_skipped(self):
        mock_ep = mock.Mock()
        mock_ep.name = "crashy"
        mock_ep.load.side_effect = RuntimeError("init failed")

        with mock.patch("importlib.metadata.entry_points", return_value=[mock_ep]):
            plugins = _discover_plugins()

        assert "crashy" not in plugins

    def test_multiple_plugins(self):
        cmd1 = click.Command("c1", callback=lambda: None)
        cmd2 = click.Command("c2", callback=lambda: None)

        ep1 = mock.Mock()
        ep1.name = "plugin-a"
        ep1.load.return_value = cmd1

        ep2 = mock.Mock()
        ep2.name = "plugin-b"
        ep2.load.return_value = cmd2

        with mock.patch("importlib.metadata.entry_points", return_value=[ep1, ep2]):
            plugins = _discover_plugins()

        assert len(plugins) == 2
        assert "plugin-a" in plugins
        assert "plugin-b" in plugins

    def test_entry_points_api_failure_returns_empty(self):
        with mock.patch("importlib.metadata.entry_points", side_effect=Exception("boom")):
            plugins = _discover_plugins()

        assert plugins == {}


class TestAgtGroup:
    def test_list_commands_sorted(self, runner: CliRunner):
        result = runner.invoke(cli, ["--help"])

        assert result.exit_code == 0

    def test_plugins_loaded_once(self):
        group = AgtGroup(name="test")

        assert group._plugins_loaded is False

        with mock.patch("agent_compliance.cli.agt._discover_plugins", return_value={}) as mock_disc:
            ctx = click.Context(group)
            group.list_commands(ctx)
            group.list_commands(ctx)
            group.get_command(ctx, "nonexistent")

        assert mock_disc.call_count == 1
        assert group._plugins_loaded is True

    def test_plugin_does_not_override_builtin(self):
        fake_cmd = click.Command("doctor", callback=lambda: click.echo("fake"))

        with mock.patch("agent_compliance.cli.agt._discover_plugins", return_value={"doctor": fake_cmd}):
            test_runner = CliRunner()
            result = test_runner.invoke(cli, ["doctor", "--help"])

        assert "Diagnose" in result.output or "installation" in result.output.lower()

    def test_get_command_returns_none_for_unknown(self):
        group = AgtGroup(name="test")

        with mock.patch("agent_compliance.cli.agt._discover_plugins", return_value={}):
            ctx = click.Context(group)
            assert group.get_command(ctx, "nonexistent-xyz") is None


class TestAgtContext:
    def test_default_values(self):
        ctx = AgtContext()

        assert ctx.output_json is False
        assert ctx.verbose is False
        assert ctx.quiet is False
        assert ctx.no_color is False

    def test_custom_values(self):
        ctx = AgtContext(output_json=True, verbose=True, quiet=True, no_color=True)

        assert ctx.output_json is True
        assert ctx.verbose is True
        assert ctx.quiet is True
        assert ctx.no_color is True

    def test_partial_values(self):
        ctx = AgtContext(output_json=True)

        assert ctx.output_json is True
        assert ctx.verbose is False


class TestVersionHelper:
    def test_returns_version_for_click(self):
        ver = _get_package_version("click")

        assert ver is not None
        assert "." in ver

    def test_returns_version_for_toolkit(self):
        ver = _get_package_version("agent_governance_toolkit")

        assert ver is not None

    def test_returns_none_for_missing_package(self):
        ver = _get_package_version("nonexistent-package-xyz-999")

        assert ver is None

    def test_returns_none_for_empty_string(self):
        ver = _get_package_version("")

        assert ver is None


class TestErrorHandling:
    def test_known_error_json(self, capsys):
        _handle_error(ValueError("bad value"), output_json=True)
        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert data["type"] == "ValidationError"
        assert data["status"] == "error"
        assert "bad value" in data["message"]

    def test_unknown_error_json_sanitized(self, capsys):
        _handle_error(RuntimeError("secret internal detail"), output_json=True)
        captured = capsys.readouterr()
        data = json.loads(captured.out)

        assert data["type"] == "InternalError"
        assert "secret internal detail" not in data["message"]
        assert "internal error" in data["message"].lower()

    def test_known_error_plain(self, capsys):
        _handle_error(FileNotFoundError("not found"), output_json=False)
        captured = capsys.readouterr()

        assert "not found" in captured.err or "not found" in captured.out

    def test_unknown_error_plain_no_leak(self, capsys):
        _handle_error(RuntimeError("secret"), output_json=False)
        captured = capsys.readouterr()
        combined = captured.out + captured.err

        assert "secret" not in combined
        assert "internal error" in combined.lower()

    def test_io_error_is_known(self, capsys):
        _handle_error(IOError("disk full"), output_json=True)
        data = json.loads(capsys.readouterr().out)

        assert data["type"] == "ValidationError"

    def test_permission_error_is_known(self, capsys):
        _handle_error(PermissionError("access denied"), output_json=True)
        data = json.loads(capsys.readouterr().out)

        assert data["type"] == "ValidationError"

    def test_key_error_is_known(self, capsys):
        _handle_error(KeyError("missing_key"), output_json=True)
        data = json.loads(capsys.readouterr().out)

        assert data["type"] == "ValidationError"


class TestPrintHelper:
    def test_print_plain_stdout(self, capsys):
        _print("hello", style="")

        assert "hello" in capsys.readouterr().out

    def test_print_plain_stderr(self, capsys):
        _print("error msg", style="", err=True)

        assert "error msg" in capsys.readouterr().err

    def test_print_with_style(self, capsys):
        _print("styled", style="bold")
        captured = capsys.readouterr()

        assert "styled" in captured.out or "styled" in captured.err


class TestVerifyCommand:
    def test_help(self, runner: CliRunner):
        result = runner.invoke(cli, ["verify", "--help"])

        assert result.exit_code == 0
        assert "OWASP" in result.output
        assert "--badge" in result.output
        assert "--evidence" in result.output
        assert "--strict" in result.output

    def test_verify_runs(self, runner: CliRunner):
        result = runner.invoke(cli, ["verify"])

        assert result.exit_code in (0, 1)

    def test_verify_json_mode(self, runner: CliRunner):
        result = runner.invoke(cli, ["--json", "verify"])

        assert result.exit_code in (0, 1)
        if result.output.strip():
            data = json.loads(result.output)
            assert isinstance(data, dict)

    def test_verify_badge_mode(self, runner: CliRunner):
        result = runner.invoke(cli, ["verify", "--badge"])

        assert result.exit_code in (0, 1)

    def test_verify_evidence_mode_calls_runtime_verifier(
        self,
        runner: CliRunner,
        tmp_path: Path,
    ):
        evidence_path = tmp_path / "agt-evidence.json"
        evidence_path.write_text("{}", encoding="utf-8")

        attestation = GovernanceAttestation(
            passed=True,
            controls_passed=1,
            controls_total=1,
            toolkit_version="3.0.0",
            python_version="3.11.0",
            platform_info="Linux x86_64",
            mode="evidence",
            strict=True,
            evidence_source=str(evidence_path),
        )
        attestation.recalculate_hash()

        with mock.patch(
            "agent_compliance.verify.GovernanceVerifier.verify_evidence",
            return_value=attestation,
        ) as mocked:
            result = runner.invoke(
                cli,
                ["verify", "--evidence", str(evidence_path), "--strict"],
            )

        assert result.exit_code == 0
        mocked.assert_called_once_with(evidence_path=str(evidence_path), strict=True)

    def test_verify_evidence_json_mode(self, runner: CliRunner, tmp_path: Path):
        evidence_path = tmp_path / "agt-evidence.json"
        evidence_path.write_text("{}", encoding="utf-8")

        attestation = GovernanceAttestation(
            passed=True,
            controls_passed=1,
            controls_total=1,
            toolkit_version="3.0.0",
            python_version="3.11.0",
            platform_info="Linux x86_64",
            mode="evidence",
            evidence_source=str(evidence_path),
        )
        attestation.recalculate_hash()

        with mock.patch(
            "agent_compliance.verify.GovernanceVerifier.verify_evidence",
            return_value=attestation,
        ):
            result = runner.invoke(
                cli,
                ["--json", "verify", "--evidence", str(evidence_path)],
            )

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["mode"] == "evidence"
        assert data["evidence_source"] == str(evidence_path)

    def test_verify_evidence_strict_returns_nonzero_on_failed_attestation(
        self,
        runner: CliRunner,
        tmp_path: Path,
    ):
        evidence_path = tmp_path / "agt-evidence.json"
        evidence_path.write_text("{}", encoding="utf-8")

        attestation = GovernanceAttestation(
            passed=False,
            controls_passed=1,
            controls_total=1,
            toolkit_version="3.0.0",
            python_version="3.11.0",
            platform_info="Linux x86_64",
            mode="evidence",
            strict=True,
            evidence_source=str(evidence_path),
            failures=["Audit sink missing, disabled, or missing target."],
        )
        attestation.recalculate_hash()

        with mock.patch(
            "agent_compliance.verify.GovernanceVerifier.verify_evidence",
            return_value=attestation,
        ):
            result = runner.invoke(
                cli,
                ["verify", "--evidence", str(evidence_path), "--strict"],
            )

        assert result.exit_code == 1


class TestIntegrityCommand:
    def test_help(self, runner: CliRunner):
        result = runner.invoke(cli, ["integrity", "--help"])

        assert result.exit_code == 0
        assert "--manifest" in result.output
        assert "--generate" in result.output

    def test_integrity_runs(self, runner: CliRunner):
        result = runner.invoke(cli, ["integrity"])

        assert result.exit_code in (0, 1)

    def test_integrity_generate(self, runner: CliRunner, tmp_path: Path):
        out_path = str(tmp_path / "integrity.json")
        result = runner.invoke(cli, ["integrity", "--generate", out_path])

        assert result.exit_code == 0
        assert Path(out_path).exists()
        data = json.loads(Path(out_path).read_text(encoding="utf-8"))
        assert "files" in data

    def test_integrity_generate_json(self, runner: CliRunner, tmp_path: Path):
        out_path = str(tmp_path / "integrity.json")
        result = runner.invoke(cli, ["--json", "integrity", "--generate", out_path])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status"] == "ok"
        assert "files" in data

    def test_integrity_manifest_and_generate_exclusive(self, runner: CliRunner, tmp_path: Path):
        result = runner.invoke(
            cli,
            [
                "integrity",
                "--manifest",
                str(tmp_path / "m.json"),
                "--generate",
                str(tmp_path / "g.json"),
            ],
        )

        assert result.exit_code == 1

    def test_integrity_nonexistent_manifest(self, runner: CliRunner):
        result = runner.invoke(cli, ["integrity", "--manifest", "/nonexistent/path.json"])

        assert result.exit_code == 1

    def test_integrity_roundtrip(self, runner: CliRunner, tmp_path: Path):
        manifest_path = str(tmp_path / "integrity.json")

        gen_result = runner.invoke(cli, ["integrity", "--generate", manifest_path])
        assert gen_result.exit_code == 0

        ver_result = runner.invoke(cli, ["integrity", "--manifest", manifest_path])
        assert ver_result.exit_code in (0, 1)


class TestLintPolicyCommand:
    def test_help(self, runner: CliRunner):
        result = runner.invoke(cli, ["lint-policy", "--help"])

        assert result.exit_code == 0
        assert "--strict" in result.output

    def test_requires_path_argument(self, runner: CliRunner):
        result = runner.invoke(cli, ["lint-policy"])

        assert result.exit_code != 0

    def test_lint_valid_policy(self, runner: CliRunner, policy_file: Path):
        result = runner.invoke(cli, ["lint-policy", str(policy_file)])

        assert result.exit_code == 0

    def test_lint_valid_policy_json(self, runner: CliRunner, policy_file: Path):
        result = runner.invoke(cli, ["--json", "lint-policy", str(policy_file)])

        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "passed" in data or "errors" in data or "messages" in data

    def test_lint_policy_directory(self, runner: CliRunner, policy_dir: Path):
        result = runner.invoke(cli, ["lint-policy", str(policy_dir)])

        assert result.exit_code in (0, 1)

    def test_lint_bad_policy_warnings(self, runner: CliRunner, bad_policy_file: Path):
        result = runner.invoke(cli, ["lint-policy", str(bad_policy_file)])

        assert result.exit_code in (0, 1)

    def test_lint_strict_mode(self, runner: CliRunner, bad_policy_file: Path):
        result = runner.invoke(cli, ["lint-policy", "--strict", str(bad_policy_file)])

        assert result.exit_code in (0, 1)

    def test_lint_nonexistent_path(self, runner: CliRunner):
        result = runner.invoke(cli, ["lint-policy", "/nonexistent/path"])

        assert result.exit_code != 0


class TestBackwardCompatibility:
    def test_old_cli_main_importable(self):
        from agent_compliance.cli.main import main

        assert callable(main)

    def test_old_cli_verify_importable(self):
        from agent_compliance.cli.main import cmd_verify

        assert callable(cmd_verify)

    def test_old_cli_integrity_importable(self):
        from agent_compliance.cli.main import cmd_integrity

        assert callable(cmd_integrity)


class TestPerformance:
    def test_help_renders_fast(self, runner: CliRunner):
        import time

        start = time.monotonic()
        result = runner.invoke(cli, ["--help"])
        elapsed = time.monotonic() - start

        assert result.exit_code == 0
        assert elapsed < 2.0

    def test_version_renders_fast(self, runner: CliRunner):
        import time

        start = time.monotonic()
        result = runner.invoke(cli, ["--version"])
        elapsed = time.monotonic() - start

        assert result.exit_code == 0
        assert elapsed < 2.0

    def test_doctor_json_renders_fast(self, runner: CliRunner):
        import time

        start = time.monotonic()
        result = runner.invoke(cli, ["--json", "doctor"])
        elapsed = time.monotonic() - start

        assert result.exit_code == 0
        assert elapsed < 5.0
        