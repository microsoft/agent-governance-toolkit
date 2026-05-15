# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for CLI exit codes.

Each CLI command must exit non-zero when its core operation fails.
Previously, ``install``, ``uninstall``, ``verify``, and ``publish``
caught ``MarketplaceError``, printed a red error message, and
returned with exit code 0. CI gates and pre-commit hooks that piped
the CLI's exit status treated installation or signature failures as
successes — a silent supply-chain risk.
"""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from agent_marketplace.cli_commands import plugin


def test_install_nonexistent_plugin_exits_nonzero() -> None:
    runner = CliRunner()
    result = runner.invoke(plugin, ["install", "this-plugin-does-not-exist"])
    assert result.exit_code != 0, (
        f"install of missing plugin must exit non-zero, "
        f"got exit_code={result.exit_code}; output={result.output!r}"
    )


def test_uninstall_nonexistent_plugin_exits_nonzero() -> None:
    runner = CliRunner()
    result = runner.invoke(plugin, ["uninstall", "this-plugin-does-not-exist"])
    assert result.exit_code != 0


def test_verify_missing_manifest_exits_nonzero(tmp_path: Path) -> None:
    """A directory with no manifest should fail verify with non-zero exit."""
    runner = CliRunner()
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    result = runner.invoke(plugin, ["verify", str(empty_dir)])
    assert result.exit_code != 0


def test_publish_invalid_manifest_exits_nonzero(tmp_path: Path) -> None:
    """An invalid manifest (missing required fields) should fail publish."""
    bad = tmp_path / "agent-plugin.yaml"
    bad.write_text("name: missing-required-fields\n", encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(plugin, ["publish", str(bad)])
    assert result.exit_code != 0
