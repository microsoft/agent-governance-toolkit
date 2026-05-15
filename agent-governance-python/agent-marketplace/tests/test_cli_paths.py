# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for AgentMesh state-directory resolution in the CLI.

Previously ``DEFAULT_PLUGINS_DIR`` / ``DEFAULT_REGISTRY_FILE`` were relative
to whatever ``cwd`` happened to be at first use, so a long-running process
that called ``_get_registry()`` and then ``os.chdir`` would see two
different registries. The resolver now snapshots an absolute path on first
call and honours ``$AGENTMESH_HOME``.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _reset_home_cache(monkeypatch):
    """Clear the cached home and any env override between tests."""
    monkeypatch.delenv("AGENTMESH_HOME", raising=False)
    from agent_marketplace import cli_commands
    monkeypatch.setattr(cli_commands, "_agentmesh_home_cache", None)
    yield
    monkeypatch.setattr(cli_commands, "_agentmesh_home_cache", None)


class TestAgentmeshHome:
    def test_env_var_honoured(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AGENTMESH_HOME", str(tmp_path / "custom-home"))
        from agent_marketplace.cli_commands import _agentmesh_home

        assert _agentmesh_home() == (tmp_path / "custom-home").resolve()

    def test_default_uses_cwd_at_first_call(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        from agent_marketplace.cli_commands import _agentmesh_home

        assert _agentmesh_home() == (tmp_path / ".agentmesh").resolve()

    def test_default_is_absolute(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        from agent_marketplace.cli_commands import _agentmesh_home

        result = _agentmesh_home()
        assert result.is_absolute()

    def test_cached_across_calls_even_when_cwd_changes(self, tmp_path, monkeypatch):
        """Regression: cwd changes after first call must not switch registries."""
        first_cwd = tmp_path / "first"
        second_cwd = tmp_path / "second"
        first_cwd.mkdir()
        second_cwd.mkdir()

        monkeypatch.chdir(first_cwd)
        from agent_marketplace.cli_commands import _agentmesh_home

        initial = _agentmesh_home()

        monkeypatch.chdir(second_cwd)
        subsequent = _agentmesh_home()

        assert initial == subsequent
        assert initial == (first_cwd / ".agentmesh").resolve()

    def test_plugins_dir_and_registry_under_home(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AGENTMESH_HOME", str(tmp_path / "h"))
        from agent_marketplace.cli_commands import _plugins_dir, _registry_file

        home = (tmp_path / "h").resolve()
        assert _plugins_dir() == home / "plugins"
        assert _registry_file() == home / "registry.json"


class TestRegistryAndInstallerHelpers:
    def test_get_registry_targets_resolved_path(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AGENTMESH_HOME", str(tmp_path))
        from agent_marketplace.cli_commands import _get_registry

        registry = _get_registry()
        # The internal path is private but the contract is "this storage_path".
        assert registry._storage_path == (tmp_path / "registry.json").resolve()

    def test_get_installer_targets_resolved_paths(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AGENTMESH_HOME", str(tmp_path))
        from agent_marketplace.cli_commands import _get_installer

        installer = _get_installer()
        assert installer._plugins_dir == (tmp_path / "plugins").resolve()
