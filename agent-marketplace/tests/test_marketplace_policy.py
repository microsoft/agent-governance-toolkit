# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for marketplace policy enforcement."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from agent_marketplace.exceptions import MarketplaceError
from agent_marketplace.manifest import PluginManifest, PluginType
from agent_marketplace.marketplace_policy import (
    ComplianceResult,
    MCPServerPolicy,
    MarketplacePolicy,
    evaluate_plugin_compliance,
    load_marketplace_policy,
)
from agent_marketplace.registry import PluginRegistry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_manifest(**overrides) -> PluginManifest:
    """Create a PluginManifest with sensible defaults."""
    defaults = {
        "name": "test-plugin",
        "version": "1.0.0",
        "description": "A test plugin",
        "author": "test@example.com",
        "plugin_type": PluginType.INTEGRATION,
    }
    defaults.update(overrides)
    return PluginManifest(**defaults)


def _write_policy_file(directory: Path, policy_data: dict) -> Path:
    """Write a marketplace policy YAML and return the path."""
    path = directory / "marketplace-policy.yaml"
    path.write_text(yaml.dump(policy_data), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# MCPServerPolicy model tests
# ---------------------------------------------------------------------------


class TestMCPServerPolicy:
    def test_defaults(self) -> None:
        policy = MCPServerPolicy()
        assert policy.mode == "allowlist"
        assert policy.allowed == []
        assert policy.blocked == []
        assert policy.require_declaration is False

    def test_allowlist_mode(self) -> None:
        policy = MCPServerPolicy(mode="allowlist", allowed=["server-a", "server-b"])
        assert policy.mode == "allowlist"
        assert policy.allowed == ["server-a", "server-b"]

    def test_blocklist_mode(self) -> None:
        policy = MCPServerPolicy(mode="blocklist", blocked=["bad-server"])
        assert policy.mode == "blocklist"
        assert policy.blocked == ["bad-server"]

    def test_invalid_mode_raises(self) -> None:
        with pytest.raises(MarketplaceError, match="Invalid MCP server policy mode"):
            MCPServerPolicy(mode="unknown")


# ---------------------------------------------------------------------------
# MarketplacePolicy model tests
# ---------------------------------------------------------------------------


class TestMarketplacePolicy:
    def test_defaults(self) -> None:
        policy = MarketplacePolicy()
        assert policy.mcp_servers.mode == "allowlist"
        assert policy.allowed_plugin_types is None
        assert policy.require_signature is False

    def test_full_policy(self) -> None:
        policy = MarketplacePolicy(
            mcp_servers=MCPServerPolicy(
                mode="allowlist",
                allowed=["approved-server"],
                require_declaration=True,
            ),
            allowed_plugin_types=["integration", "agent"],
            require_signature=True,
        )
        assert policy.mcp_servers.allowed == ["approved-server"]
        assert policy.allowed_plugin_types == ["integration", "agent"]
        assert policy.require_signature is True


# ---------------------------------------------------------------------------
# ComplianceResult model tests
# ---------------------------------------------------------------------------


class TestComplianceResult:
    def test_compliant(self) -> None:
        result = ComplianceResult(compliant=True, violations=[])
        assert result.compliant is True
        assert result.violations == []

    def test_non_compliant(self) -> None:
        result = ComplianceResult(compliant=False, violations=["some error"])
        assert result.compliant is False
        assert len(result.violations) == 1


# ---------------------------------------------------------------------------
# load_marketplace_policy tests
# ---------------------------------------------------------------------------


class TestLoadMarketplacePolicy:
    def test_load_valid_policy(self, tmp_path: Path) -> None:
        data = {
            "mcp_servers": {
                "mode": "allowlist",
                "allowed": ["server-a"],
                "require_declaration": True,
            },
            "require_signature": True,
        }
        path = _write_policy_file(tmp_path, data)
        policy = load_marketplace_policy(path)

        assert policy.mcp_servers.mode == "allowlist"
        assert policy.mcp_servers.allowed == ["server-a"]
        assert policy.require_signature is True

    def test_missing_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(MarketplaceError, match="not found"):
            load_marketplace_policy(tmp_path / "nonexistent.yaml")

    def test_invalid_yaml_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.yaml"
        path.write_text(": : :", encoding="utf-8")
        with pytest.raises(MarketplaceError, match="Failed to load"):
            load_marketplace_policy(path)

    def test_non_mapping_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "list.yaml"
        path.write_text("- a\n- b\n", encoding="utf-8")
        with pytest.raises(MarketplaceError, match="must be a YAML mapping"):
            load_marketplace_policy(path)

    def test_empty_policy_uses_defaults(self, tmp_path: Path) -> None:
        path = _write_policy_file(tmp_path, {})
        policy = load_marketplace_policy(path)

        assert policy.mcp_servers.mode == "allowlist"
        assert policy.require_signature is False


# ---------------------------------------------------------------------------
# evaluate_plugin_compliance tests
# ---------------------------------------------------------------------------


class TestEvaluatePluginCompliance:
    def test_compliant_plugin(self) -> None:
        manifest = _make_manifest(signature="sig123")
        policy = MarketplacePolicy(require_signature=True)

        result = evaluate_plugin_compliance(manifest, policy)

        assert result.compliant is True
        assert result.violations == []

    def test_missing_signature_violation(self) -> None:
        manifest = _make_manifest()
        policy = MarketplacePolicy(require_signature=True)

        result = evaluate_plugin_compliance(manifest, policy)

        assert result.compliant is False
        assert any("signed" in v for v in result.violations)

    def test_disallowed_plugin_type(self) -> None:
        manifest = _make_manifest(plugin_type=PluginType.VALIDATOR)
        policy = MarketplacePolicy(allowed_plugin_types=["integration", "agent"])

        result = evaluate_plugin_compliance(manifest, policy)

        assert result.compliant is False
        assert any("not allowed" in v for v in result.violations)

    def test_allowed_plugin_type(self) -> None:
        manifest = _make_manifest(plugin_type=PluginType.INTEGRATION)
        policy = MarketplacePolicy(allowed_plugin_types=["integration"])

        result = evaluate_plugin_compliance(manifest, policy)

        assert result.compliant is True

    def test_allowlist_blocks_unlisted_server(self) -> None:
        manifest = _make_manifest()
        policy = MarketplacePolicy(
            mcp_servers=MCPServerPolicy(
                mode="allowlist", allowed=["approved-server"]
            )
        )

        result = evaluate_plugin_compliance(
            manifest, policy, mcp_servers=["rogue-server"]
        )

        assert result.compliant is False
        assert any("not in allowlist" in v for v in result.violations)
        assert any("rogue-server" in v for v in result.violations)

    def test_allowlist_permits_listed_server(self) -> None:
        manifest = _make_manifest()
        policy = MarketplacePolicy(
            mcp_servers=MCPServerPolicy(
                mode="allowlist", allowed=["approved-server"]
            )
        )

        result = evaluate_plugin_compliance(
            manifest, policy, mcp_servers=["approved-server"]
        )

        assert result.compliant is True

    def test_blocklist_blocks_listed_server(self) -> None:
        manifest = _make_manifest()
        policy = MarketplacePolicy(
            mcp_servers=MCPServerPolicy(
                mode="blocklist", blocked=["evil-server"]
            )
        )

        result = evaluate_plugin_compliance(
            manifest, policy, mcp_servers=["evil-server"]
        )

        assert result.compliant is False
        assert any("blocked" in v for v in result.violations)

    def test_blocklist_permits_unlisted_server(self) -> None:
        manifest = _make_manifest()
        policy = MarketplacePolicy(
            mcp_servers=MCPServerPolicy(
                mode="blocklist", blocked=["evil-server"]
            )
        )

        result = evaluate_plugin_compliance(
            manifest, policy, mcp_servers=["good-server"]
        )

        assert result.compliant is True

    def test_require_declaration_no_servers(self) -> None:
        manifest = _make_manifest()
        policy = MarketplacePolicy(
            mcp_servers=MCPServerPolicy(require_declaration=True)
        )

        result = evaluate_plugin_compliance(manifest, policy, mcp_servers=None)

        assert result.compliant is False
        assert any("declare" in v for v in result.violations)

    def test_require_declaration_with_servers(self) -> None:
        manifest = _make_manifest()
        policy = MarketplacePolicy(
            mcp_servers=MCPServerPolicy(require_declaration=True)
        )

        result = evaluate_plugin_compliance(
            manifest, policy, mcp_servers=["server-a"]
        )

        assert result.compliant is True

    def test_multiple_violations(self) -> None:
        manifest = _make_manifest(plugin_type=PluginType.VALIDATOR)
        policy = MarketplacePolicy(
            require_signature=True,
            allowed_plugin_types=["integration"],
            mcp_servers=MCPServerPolicy(
                mode="allowlist", allowed=["good-server"]
            ),
        )

        result = evaluate_plugin_compliance(
            manifest, policy, mcp_servers=["bad-server"]
        )

        assert result.compliant is False
        assert len(result.violations) == 3

    def test_no_policy_restrictions(self) -> None:
        manifest = _make_manifest()
        policy = MarketplacePolicy()

        result = evaluate_plugin_compliance(
            manifest, policy, mcp_servers=["any-server"]
        )

        assert result.compliant is True

    def test_empty_allowlist_permits_all(self) -> None:
        """An empty allowlist (no entries) should not block any servers."""
        manifest = _make_manifest()
        policy = MarketplacePolicy(
            mcp_servers=MCPServerPolicy(mode="allowlist", allowed=[])
        )

        result = evaluate_plugin_compliance(
            manifest, policy, mcp_servers=["any-server"]
        )

        assert result.compliant is True

    def test_empty_blocklist_permits_all(self) -> None:
        """An empty blocklist should not block any servers."""
        manifest = _make_manifest()
        policy = MarketplacePolicy(
            mcp_servers=MCPServerPolicy(mode="blocklist", blocked=[])
        )

        result = evaluate_plugin_compliance(
            manifest, policy, mcp_servers=["any-server"]
        )

        assert result.compliant is True


# ---------------------------------------------------------------------------
# PluginRegistry integration tests
# ---------------------------------------------------------------------------


class TestRegistryPolicyEnforcement:
    def test_register_compliant_plugin(self) -> None:
        policy = MarketplacePolicy(require_signature=False)
        registry = PluginRegistry(marketplace_policy=policy)
        manifest = _make_manifest()

        registry.register(manifest)

        assert registry.get_plugin("test-plugin") == manifest

    def test_register_rejects_non_compliant_plugin(self) -> None:
        policy = MarketplacePolicy(require_signature=True)
        registry = PluginRegistry(marketplace_policy=policy)
        manifest = _make_manifest()  # no signature

        with pytest.raises(MarketplaceError, match="violates marketplace policy"):
            registry.register(manifest)

    def test_register_with_mcp_servers(self) -> None:
        policy = MarketplacePolicy(
            mcp_servers=MCPServerPolicy(
                mode="allowlist", allowed=["approved-server"]
            )
        )
        registry = PluginRegistry(marketplace_policy=policy)
        manifest = _make_manifest()

        # Passing allowed servers succeeds
        registry.register(manifest, mcp_servers=["approved-server"])
        assert registry.get_plugin("test-plugin") == manifest

    def test_register_rejects_blocked_mcp_server(self) -> None:
        policy = MarketplacePolicy(
            mcp_servers=MCPServerPolicy(
                mode="allowlist", allowed=["approved-server"]
            )
        )
        registry = PluginRegistry(marketplace_policy=policy)
        manifest = _make_manifest()

        with pytest.raises(MarketplaceError, match="violates marketplace policy"):
            registry.register(manifest, mcp_servers=["rogue-server"])

    def test_register_without_policy(self) -> None:
        """Registry without a policy accepts any plugin."""
        registry = PluginRegistry()
        manifest = _make_manifest()
        registry.register(manifest)
        assert registry.get_plugin("test-plugin") == manifest


# ---------------------------------------------------------------------------
# CLI evaluate command tests
# ---------------------------------------------------------------------------


class TestEvaluateCLICommand:
    def test_compliant_plugin(self, tmp_path: Path) -> None:
        """Exit code 0 for a compliant plugin."""
        # Write manifest
        manifest_data = {
            "name": "good-plugin",
            "version": "1.0.0",
            "description": "A compliant plugin",
            "author": "test@example.com",
            "plugin_type": "integration",
        }
        manifest_file = tmp_path / "agent-plugin.yaml"
        manifest_file.write_text(yaml.dump(manifest_data), encoding="utf-8")

        # Write policy
        policy_data = {"require_signature": False}
        policy_file = _write_policy_file(tmp_path, policy_data)

        from agent_marketplace.cli_commands import plugin

        runner = CliRunner()
        result = runner.invoke(
            plugin,
            [
                "evaluate",
                str(manifest_file),
                "--marketplace-policy",
                str(policy_file),
            ],
        )

        assert result.exit_code == 0
        assert "compliant" in result.output

    def test_non_compliant_plugin(self, tmp_path: Path) -> None:
        """Exit code 1 for a non-compliant plugin."""
        manifest_data = {
            "name": "unsigned-plugin",
            "version": "1.0.0",
            "description": "No signature",
            "author": "test@example.com",
            "plugin_type": "integration",
        }
        manifest_file = tmp_path / "agent-plugin.yaml"
        manifest_file.write_text(yaml.dump(manifest_data), encoding="utf-8")

        policy_data = {"require_signature": True}
        policy_file = _write_policy_file(tmp_path, policy_data)

        from agent_marketplace.cli_commands import plugin

        runner = CliRunner()
        result = runner.invoke(
            plugin,
            [
                "evaluate",
                str(manifest_file),
                "--marketplace-policy",
                str(policy_file),
            ],
        )

        assert result.exit_code == 1
        assert "violations" in result.output

    def test_evaluate_with_mcp_servers(self, tmp_path: Path) -> None:
        """MCP servers are extracted and checked against the policy."""
        manifest_data = {
            "name": "mcp-plugin",
            "description": "Plugin with MCP servers",
            "version": "1.0.0",
            "author": "test@example.com",
            "skills": [],
            "mcps": [
                {"name": "rogue-server", "url": "https://evil.example.com", "tools": []}
            ],
        }
        manifest_file = tmp_path / "plugin.json"
        manifest_file.write_text(json.dumps(manifest_data), encoding="utf-8")

        policy_data = {
            "mcp_servers": {
                "mode": "allowlist",
                "allowed": ["safe-server"],
            }
        }
        policy_file = _write_policy_file(tmp_path, policy_data)

        from agent_marketplace.cli_commands import plugin

        runner = CliRunner()
        result = runner.invoke(
            plugin,
            [
                "evaluate",
                str(manifest_file),
                "--marketplace-policy",
                str(policy_file),
            ],
        )

        assert result.exit_code == 1
        assert "rogue-server" in result.output

    def test_evaluate_missing_policy(self, tmp_path: Path) -> None:
        """CLI handles missing policy file gracefully."""
        manifest_data = {
            "name": "test-plugin",
            "version": "1.0.0",
            "description": "A plugin",
            "author": "test@example.com",
            "plugin_type": "integration",
        }
        manifest_file = tmp_path / "agent-plugin.yaml"
        manifest_file.write_text(yaml.dump(manifest_data), encoding="utf-8")

        from agent_marketplace.cli_commands import plugin

        runner = CliRunner()
        result = runner.invoke(
            plugin,
            [
                "evaluate",
                str(manifest_file),
                "--marketplace-policy",
                str(tmp_path / "nonexistent.yaml"),
            ],
        )

        # Click validates path existence; should fail
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# Top-level import smoke test
# ---------------------------------------------------------------------------


def test_marketplace_policy_imports():
    """New public symbols are importable from the top-level package."""
    from agent_marketplace import (
        ComplianceResult,
        MCPServerPolicy,
        MarketplacePolicy,
        evaluate_plugin_compliance,
        load_marketplace_policy,
    )

    assert ComplianceResult is not None
    assert MCPServerPolicy is not None
    assert MarketplacePolicy is not None
    assert callable(evaluate_plugin_compliance)
    assert callable(load_marketplace_policy)
