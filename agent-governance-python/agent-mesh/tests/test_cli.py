# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for AgentMesh CLI."""

import pytest
from click.testing import CliRunner
from pathlib import Path
import tempfile
import yaml
import json

from agentmesh.cli.main import app, main


class TestCLI:
    """Tests for CLI commands."""
    
    @pytest.fixture
    def runner(self):
        """Create CLI test runner."""
        return CliRunner()
    
    def test_cli_help(self, runner):
        """Test CLI shows help."""
        result = runner.invoke(app, ["--help"])
        
        assert result.exit_code == 0
        assert "AgentMesh" in result.output
        assert "Identity" in result.output or "Trust" in result.output
    
    def test_cli_version(self, runner):
        """Test CLI shows version."""
        result = runner.invoke(app, ["--version"])
        
        assert result.exit_code == 0
        assert "3.1.0" in result.output
    
    def test_init_command(self, runner):
        """Test init command creates agent scaffold."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = runner.invoke(app, [
                "init",
                "--name", "test-agent",
                "--sponsor", "test@example.com",
                "--output", tmpdir,
            ])
            
            assert result.exit_code == 0
            
            # Check files created
            agent_dir = Path(tmpdir) / "test-agent"
            assert agent_dir.exists()
            assert (agent_dir / "agentmesh.yaml").exists()
            assert (agent_dir / "policies").exists()
            assert (agent_dir / "src" / "main.py").exists()
    
    def test_init_creates_manifest(self, runner):
        """Test init creates valid manifest."""
        with tempfile.TemporaryDirectory() as tmpdir:
            runner.invoke(app, [
                "init",
                "--name", "my-agent",
                "--sponsor", "sponsor@example.com",
                "--output", tmpdir,
            ])
            
            manifest_path = Path(tmpdir) / "my-agent" / "agentmesh.yaml"
            
            with open(manifest_path) as f:
                manifest = yaml.safe_load(f)
            
            assert manifest["agent"]["name"] == "my-agent"
            assert manifest["sponsor"]["email"] == "sponsor@example.com"
            assert manifest["identity"]["ttl_minutes"] == 15
    
    def test_init_creates_default_policy(self, runner):
        """Test init creates default security policy."""
        with tempfile.TemporaryDirectory() as tmpdir:
            runner.invoke(app, [
                "init",
                "--name", "secure-agent",
                "--sponsor", "s@e.com",
                "--output", tmpdir,
            ])
            
            policy_path = Path(tmpdir) / "secure-agent" / "policies" / "default.yaml"
            
            with open(policy_path) as f:
                policy = yaml.safe_load(f)
            
            assert "policies" in policy
            assert len(policy["policies"]) > 0
    
    def test_status_command(self, runner):
        """Test status command output."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # First init an agent
            runner.invoke(app, [
                "init",
                "--name", "status-test",
                "--sponsor", "s@e.com",
                "--output", tmpdir,
            ])
            
            agent_dir = Path(tmpdir) / "status-test"
            
            # Then check status
            result = runner.invoke(app, ["status", str(agent_dir)])
            
            assert result.exit_code == 0
            assert "status-test" in result.output or "Agent" in result.output
    
    def test_policy_command_valid(self, runner):
        """Test policy command with valid policy."""
        with tempfile.TemporaryDirectory() as tmpdir:
            policy_file = Path(tmpdir) / "test-policy.yaml"
            
            policy_data = {
                "policies": [{
                    "name": "Test Policy",
                    "rules": [{
                        "name": "rule-1",
                        "condition": "action.type == 'read'",
                        "action": "allow",
                    }],
                }],
            }
            
            with open(policy_file, "w") as f:
                yaml.dump(policy_data, f)
            
            result = runner.invoke(app, ["policy", str(policy_file)])
            
            assert result.exit_code == 0
            assert "Test Policy" in result.output or "Loaded" in result.output
    
    def test_audit_command(self, runner):
        """Test audit command output."""
        result = runner.invoke(app, ["audit", "--limit", "5"])
        
        assert result.exit_code == 0
        # Should show audit entries (even if simulated)
    
    def test_audit_json_format(self, runner):
        """Test audit command with JSON output."""
        result = runner.invoke(app, ["audit", "--format", "json"])
        
        assert result.exit_code == 0
        # Output should be valid JSON
        try:
            data = json.loads(result.output)
            assert isinstance(data, list)
        except json.JSONDecodeError:
            pytest.fail("Audit JSON output is not valid JSON")
    
    def test_proxy_command_help(self, runner):
        """Test proxy command shows help."""
        result = runner.invoke(app, ["proxy", "--help"])
        
        assert result.exit_code == 0
        assert "proxy" in result.output.lower()
        assert "target" in result.output.lower()
    
    def test_init_integration_claude(self, runner):
        """Test init-integration command for Claude."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "claude_config.json"
            
            result = runner.invoke(app, [
                "init-integration",
                "--claude",
                "--config-path", str(config_path),
                "--no-backup",
            ])
            
            assert result.exit_code == 0
            assert config_path.exists()
            
            # Verify config contents
            with open(config_path) as f:
                config = json.load(f)
            
            assert "mcpServers" in config
            assert "agentmesh" in str(config).lower()
    
    def test_init_integration_updates_existing_config(self, runner):
        """Test init-integration preserves existing config."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "existing_config.json"
            
            # Create existing config
            existing_config = {
                "mcpServers": {
                    "existing-server": {
                        "command": "python",
                        "args": ["server.py"]
                    }
                }
            }
            with open(config_path, "w") as f:
                json.dump(existing_config, f)
            
            # Run init-integration
            result = runner.invoke(app, [
                "init-integration",
                "--claude",
                "--config-path", str(config_path),
                "--no-backup",
            ])
            
            assert result.exit_code == 0
            
            # Verify existing server is preserved
            with open(config_path) as f:
                config = json.load(f)
            
            assert "existing-server" in config["mcpServers"]
            assert len(config["mcpServers"]) > 1


class TestCLIEdgeCases:
    """Edge case tests for CLI."""
    
    @pytest.fixture
    def runner(self):
        return CliRunner()
    
    def test_init_special_characters_in_name(self, runner):
        """Test init with special characters in agent name."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = runner.invoke(app, [
                "init",
                "--name", "test-agent-v2.0",
                "--sponsor", "s@e.com",
                "--output", tmpdir,
            ])
            
            # Should handle special characters
            assert result.exit_code == 0
    
    def test_status_nonexistent_directory(self, runner):
        """Test status with non-existent directory."""
        result = runner.invoke(app, ["status", "/nonexistent/path"])
        
        # Should handle gracefully
        assert "not found" in result.output.lower() or result.exit_code != 0
    
    def test_policy_invalid_file(self, runner):
        """Test policy with invalid file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            invalid_file = Path(tmpdir) / "invalid.yaml"
            invalid_file.write_text("not: valid: yaml: [[")
            
            result = runner.invoke(app, ["policy", str(invalid_file)])
            
            # Should report error
            assert result.exit_code != 0 or "error" in result.output.lower()
