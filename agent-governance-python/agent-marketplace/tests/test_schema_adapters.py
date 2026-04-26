# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for Copilot / Claude plugin manifest schema adapters."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_marketplace.exceptions import MarketplaceError
from agent_marketplace.manifest import PluginManifest, PluginType
from agent_marketplace.schema_adapters import (
    AgentDef,
    ClaudePluginManifest,
    CopilotPluginManifest,
    MCPServerDef,
    SkillDef,
    adapt_to_canonical,
    detect_manifest_format,
    extract_capabilities,
    extract_mcp_servers,
)


# ── fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture()
def copilot_data() -> dict:
    """Minimal valid Copilot plugin manifest dict."""
    return {
        "name": "my-copilot-plugin",
        "description": "A Copilot plugin",
        "version": "1.0.0",
        "author": "alice@example.com",
        "skills": [{"name": "code-review", "description": "Review code"}],
        "agents": [{"name": "reviewer", "model": "gpt-4", "instructions": "Be helpful"}],
        "mcps": [
            {
                "name": "repo-server",
                "url": "https://mcp.example.com",
                "tools": ["read_file", "search"],
            }
        ],
    }


@pytest.fixture()
def claude_data() -> dict:
    """Minimal valid Claude plugin manifest dict."""
    return {
        "name": "my-claude-plugin",
        "description": "A Claude plugin",
        "version": "2.0.0",
        "author": "bob@example.com",
        "permissions": ["file_read", "network"],
        "allowed_tools": ["bash", "editor"],
        "skills": [{"name": "summarise", "description": "Summarise text"}],
        "agents": [],
        "mcps": [
            {
                "name": "local-mcp",
                "command": "npx mcp-server",
                "tools": ["run_test"],
            }
        ],
    }


@pytest.fixture()
def generic_data() -> dict:
    """A plain canonical plugin manifest dict."""
    return {
        "name": "plain-plugin",
        "version": "0.1.0",
        "description": "Nothing special",
        "author": "eve@example.com",
        "plugin_type": "integration",
    }


# ── detect_manifest_format ──────────────────────────────────────────────────


class TestDetectManifestFormat:
    def test_copilot_detected_by_skills(self, copilot_data: dict):
        assert detect_manifest_format(copilot_data) == "copilot"

    def test_copilot_detected_by_mcps_only(self):
        data = {"name": "x", "mcps": []}
        assert detect_manifest_format(data) == "copilot"

    def test_claude_detected_by_permissions(self, claude_data: dict):
        assert detect_manifest_format(claude_data) == "claude"

    def test_claude_wins_with_allowed_tools(self):
        data = {"name": "x", "allowed_tools": ["bash"]}
        assert detect_manifest_format(data) == "claude"

    def test_generic_fallback(self, generic_data: dict):
        assert detect_manifest_format(generic_data) == "generic"

    def test_claude_takes_precedence_over_copilot(self):
        """When both Claude and Copilot signals exist, Claude wins."""
        data = {"name": "x", "skills": [], "permissions": ["net"]}
        assert detect_manifest_format(data) == "claude"


# ── Pydantic models ─────────────────────────────────────────────────────────


class TestCopilotPluginManifest:
    def test_valid_manifest(self, copilot_data: dict):
        m = CopilotPluginManifest(**copilot_data)
        assert m.name == "my-copilot-plugin"
        assert len(m.skills) == 1
        assert len(m.agents) == 1
        assert len(m.mcps) == 1

    def test_missing_name_raises(self):
        with pytest.raises(Exception):
            CopilotPluginManifest(description="no name")

    def test_defaults(self):
        m = CopilotPluginManifest(name="minimal")
        assert m.version == "1.0.0"
        assert m.skills == []
        assert m.agents == []
        assert m.mcps == []


class TestClaudePluginManifest:
    def test_valid_manifest(self, claude_data: dict):
        m = ClaudePluginManifest(**claude_data)
        assert m.name == "my-claude-plugin"
        assert m.permissions == ["file_read", "network"]
        assert m.allowed_tools == ["bash", "editor"]

    def test_defaults(self):
        m = ClaudePluginManifest(name="minimal")
        assert m.permissions == []
        assert m.allowed_tools == []


class TestMCPServerDef:
    def test_url_server(self):
        s = MCPServerDef(name="s1", url="https://example.com")
        assert s.url == "https://example.com"

    def test_command_server(self):
        s = MCPServerDef(name="s1", command="npx serve")
        assert s.command == "npx serve"

    def test_neither_url_nor_command_raises(self):
        with pytest.raises(MarketplaceError, match="must declare either"):
            MCPServerDef(name="bad")


# ── adapt_to_canonical ──────────────────────────────────────────────────────


class TestAdaptToCanonical:
    def test_copilot_to_canonical(self, copilot_data: dict):
        manifest = adapt_to_canonical(copilot_data, "copilot")
        assert isinstance(manifest, PluginManifest)
        assert manifest.name == "my-copilot-plugin"
        assert manifest.plugin_type == PluginType.AGENT
        assert manifest.author == "alice@example.com"
        assert "code-review" in manifest.capabilities

    def test_claude_to_canonical(self, claude_data: dict):
        manifest = adapt_to_canonical(claude_data, "claude")
        assert isinstance(manifest, PluginManifest)
        assert manifest.name == "my-claude-plugin"
        assert "bash" in manifest.capabilities
        assert "editor" in manifest.capabilities

    def test_generic_passthrough(self, generic_data: dict):
        manifest = adapt_to_canonical(generic_data, "generic")
        assert manifest.name == "plain-plugin"
        assert manifest.plugin_type == PluginType.INTEGRATION

    def test_unknown_format_raises(self, copilot_data: dict):
        with pytest.raises(MarketplaceError, match="Unknown manifest format"):
            adapt_to_canonical(copilot_data, "unknown-fmt")

    def test_invalid_copilot_raises(self):
        with pytest.raises(MarketplaceError, match="Invalid copilot manifest"):
            adapt_to_canonical({}, "copilot")

    def test_author_defaults_to_unknown(self):
        data = {"name": "no-author", "skills": []}
        manifest = adapt_to_canonical(data, "copilot")
        assert manifest.author == "unknown"


# ── extract_capabilities ────────────────────────────────────────────────────


class TestExtractCapabilities:
    def test_copilot_skills_and_mcp_tools(self, copilot_data: dict):
        caps = extract_capabilities(copilot_data, "copilot")
        assert "code-review" in caps
        assert "read_file" in caps
        assert "search" in caps

    def test_claude_includes_allowed_tools(self, claude_data: dict):
        caps = extract_capabilities(claude_data, "claude")
        assert "bash" in caps
        assert "editor" in caps
        assert "summarise" in caps

    def test_generic_returns_capabilities_field(self, generic_data: dict):
        generic_data["capabilities"] = ["cap-a", "cap-b"]
        caps = extract_capabilities(generic_data, "generic")
        assert caps == ["cap-a", "cap-b"]

    def test_deduplication(self):
        data = {
            "skills": [{"name": "dup"}, {"name": "dup"}],
            "mcps": [{"name": "s", "url": "http://x", "tools": ["dup"]}],
        }
        caps = extract_capabilities(data, "copilot")
        assert caps.count("dup") == 1

    def test_sorted_output(self):
        data = {"skills": [{"name": "z"}, {"name": "a"}], "mcps": []}
        caps = extract_capabilities(data, "copilot")
        assert caps == sorted(caps)


# ── extract_mcp_servers ─────────────────────────────────────────────────────


class TestExtractMCPServers:
    def test_extracts_server_names(self, copilot_data: dict):
        assert extract_mcp_servers(copilot_data) == ["repo-server"]

    def test_empty_when_no_mcps(self, generic_data: dict):
        assert extract_mcp_servers(generic_data) == []

    def test_multiple_servers(self):
        data = {
            "mcps": [
                {"name": "s1", "url": "http://a"},
                {"name": "s2", "command": "run"},
            ]
        }
        assert extract_mcp_servers(data) == ["s1", "s2"]


# ── Top-level import smoke test ─────────────────────────────────────────────


def test_schema_adapter_imports():
    """New public symbols are importable from the top-level package."""
    from agent_marketplace import (
        ClaudePluginManifest,
        CopilotPluginManifest,
        adapt_to_canonical,
        detect_manifest_format,
        extract_capabilities,
        extract_mcp_servers,
    )

    assert callable(detect_manifest_format)
    assert callable(adapt_to_canonical)
    assert callable(extract_capabilities)
    assert callable(extract_mcp_servers)
    assert CopilotPluginManifest is not None
    assert ClaudePluginManifest is not None


# ── CLI verify integration (file-based) ─────────────────────────────────────


class TestVerifyCLIIntegration:
    """Verify the CLI can handle Copilot/Claude plugin.json files."""

    def test_verify_copilot_plugin_json(self, tmp_path: Path, copilot_data: dict):
        manifest_file = tmp_path / "plugin.json"
        manifest_file.write_text(json.dumps(copilot_data))

        from click.testing import CliRunner

        from agent_marketplace.cli_commands import plugin

        runner = CliRunner()
        result = runner.invoke(plugin, ["verify", str(manifest_file)])
        assert result.exit_code == 0
        assert "copilot" in result.output
        assert "my-copilot-plugin" in result.output

    def test_verify_claude_plugin_json(self, tmp_path: Path, claude_data: dict):
        manifest_file = tmp_path / "plugin.json"
        manifest_file.write_text(json.dumps(claude_data))

        from click.testing import CliRunner

        from agent_marketplace.cli_commands import plugin

        runner = CliRunner()
        result = runner.invoke(plugin, ["verify", str(manifest_file)])
        assert result.exit_code == 0
        assert "claude" in result.output
        assert "my-claude-plugin" in result.output

    def test_verify_with_explicit_format(self, tmp_path: Path, copilot_data: dict):
        manifest_file = tmp_path / "plugin.json"
        manifest_file.write_text(json.dumps(copilot_data))

        from click.testing import CliRunner

        from agent_marketplace.cli_commands import plugin

        runner = CliRunner()
        result = runner.invoke(
            plugin, ["verify", "--format", "copilot-plugin", str(manifest_file)]
        )
        assert result.exit_code == 0
        assert "my-copilot-plugin" in result.output

    def test_verify_dir_with_plugin_json(self, tmp_path: Path, copilot_data: dict):
        manifest_file = tmp_path / "plugin.json"
        manifest_file.write_text(json.dumps(copilot_data))

        from click.testing import CliRunner

        from agent_marketplace.cli_commands import plugin

        runner = CliRunner()
        result = runner.invoke(plugin, ["verify", str(tmp_path)])
        assert result.exit_code == 0
        assert "my-copilot-plugin" in result.output
