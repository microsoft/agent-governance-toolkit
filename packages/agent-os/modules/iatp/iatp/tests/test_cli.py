# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for IATP CLI commands
"""
import json

import pytest
from click.testing import CliRunner

from iatp.cli import cli


@pytest.fixture
def runner():
    """Create a CLI test runner."""
    return CliRunner()


@pytest.fixture
def valid_manifest(tmp_path):
    """Create a valid manifest file for testing."""
    manifest = {
        "agent_id": "test-agent",
        "trust_level": "verified_partner",
        "capabilities": {
            "reversibility": "full",
            "idempotency": True,
            "rate_limit": 100,
            "sla_latency": "2000ms"
        },
        "privacy_contract": {
            "retention": "ephemeral",
            "human_review": False
        }
    }
    manifest_file = tmp_path / "manifest.json"
    manifest_file.write_text(json.dumps(manifest))
    return manifest_file


@pytest.fixture
def invalid_manifest(tmp_path):
    """Create an invalid manifest file for testing."""
    manifest = {
        "agent_id": "untrusted-test",
        "trust_level": "untrusted",
        "capabilities": {
            "reversibility": "none",
            "idempotency": False,
            "rate_limit": 10,
            "sla_latency": "5000ms"
        },
        "privacy_contract": {
            "retention": "permanent",
            "human_review": True
        }
    }
    manifest_file = tmp_path / "manifest.json"
    manifest_file.write_text(json.dumps(manifest))
    return manifest_file


def test_cli_version(runner):
    """Test the version command."""
    result = runner.invoke(cli, ['version'])
    assert result.exit_code == 0
    assert 'IATP CLI' in result.output


def test_cli_help(runner):
    """Test the help command."""
    result = runner.invoke(cli, ['--help'])
    assert result.exit_code == 0
    assert 'verify' in result.output
    assert 'scan' in result.output


def test_verify_valid_manifest(runner, valid_manifest):
    """Test verifying a valid manifest."""
    result = runner.invoke(cli, ['verify', str(valid_manifest)])
    assert result.exit_code == 0
    assert '✅ Schema validation passed' in result.output
    assert 'Trust Score: 10/10' in result.output


def test_verify_invalid_manifest(runner, invalid_manifest):
    """Test verifying an invalid manifest (should fail)."""
    result = runner.invoke(cli, ['verify', str(invalid_manifest)])
    assert result.exit_code == 1
    assert '❌ Validation failed' in result.output


def test_verify_verbose(runner, valid_manifest):
    """Test verify with verbose flag."""
    result = runner.invoke(cli, ['verify', str(valid_manifest), '--verbose'])
    # Exit code 0 for valid manifest
    if result.exit_code != 0:
        print(result.output)
    assert result.exit_code == 0
    assert 'Schema validation passed' in result.output


def test_verify_nonexistent_file(runner):
    """Test verifying a file that doesn't exist."""
    result = runner.invoke(cli, ['verify', '/nonexistent/manifest.json'])
    # Click returns exit code 2 for usage errors
    assert result.exit_code in [1, 2]


def test_verify_invalid_json(runner, tmp_path):
    """Test verifying a file with invalid JSON."""
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("{ this is not valid json }")
    result = runner.invoke(cli, ['verify', str(bad_file)])
    assert result.exit_code == 1


def test_scan_help(runner):
    """Test scan command help."""
    result = runner.invoke(cli, ['scan', '--help'])
    assert result.exit_code == 0
    # Check for argument name (lowercase due to click formatting)
    assert 'agent_url' in result.output.lower() or 'agent-url' in result.output.lower()


def test_scan_unreachable_agent(runner):
    """Test scanning an unreachable agent."""
    result = runner.invoke(cli, ['scan', 'http://localhost:99999'])
    assert result.exit_code == 1
    assert 'error' in result.output.lower()
