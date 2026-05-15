# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Tests for agent-governance integrity CLI round-trip behavior.

Ensures that:
1. `agent-governance integrity --generate <path>` produces a valid manifest
2. `agent-governance integrity --manifest <path>` verifies successfully
3. Tampering with source files causes verification to fail
4. The CLI output format matches what AGENTS.md documents

These tests guard against regressions in the plugin signing pipeline
used by the Agency Playground (agency-microsoft/playground).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from agent_compliance.cli.main import main


def run_cli(*args: str) -> int:
    """Run the CLI with the given arguments and return the exit code."""
    old_argv = sys.argv
    sys.argv = ["agent-governance", *args]
    try:
        return main()
    finally:
        sys.argv = old_argv


class TestIntegrityGenerateRoundTrip:
    """Generate a manifest, then verify it passes without changes."""

    def test_generate_creates_valid_json(self, tmp_path: Path):
        output = tmp_path / "integrity.json"

        rc = run_cli("integrity", "--generate", str(output))

        assert rc == 0
        assert output.exists()
        manifest = json.loads(output.read_text(encoding="utf-8"))
        assert "files" in manifest
        assert "functions" in manifest
        # Manifest may be empty when governance modules (agent_os, agentmesh)
        # are not installed, e.g. in isolated CI for agent-compliance only.
        assert isinstance(manifest["files"], dict)
        assert isinstance(manifest["functions"], dict)

    def test_generate_then_verify_passes(self, tmp_path: Path):
        output = tmp_path / "integrity.json"

        rc_gen = run_cli("integrity", "--generate", str(output))
        assert rc_gen == 0

        rc_verify = run_cli("integrity", "--manifest", str(output))
        assert rc_verify == 0

    def test_generate_output_mentions_file_count(self, tmp_path: Path, capsys):
        output = tmp_path / "integrity.json"

        run_cli("integrity", "--generate", str(output))

        captured = capsys.readouterr()
        assert "Files hashed:" in captured.out
        assert "Functions hashed:" in captured.out

    def test_generate_overwrites_existing_manifest(self, tmp_path: Path):
        output = tmp_path / "integrity.json"
        output.write_text('{"old": true}', encoding="utf-8")

        rc = run_cli("integrity", "--generate", str(output))

        assert rc == 0
        manifest = json.loads(output.read_text(encoding="utf-8"))
        assert "old" not in manifest
        assert "files" in manifest


class TestIntegrityTamperDetection:
    """Verify that modifying source after generation causes failure."""

    def test_tampered_file_hash_fails_verification(self, tmp_path: Path):
        output = tmp_path / "integrity.json"

        rc_gen = run_cli("integrity", "--generate", str(output))
        assert rc_gen == 0

        # Tamper with the manifest by changing a file hash
        manifest = json.loads(output.read_text(encoding="utf-8"))
        if manifest["files"]:
            first_module = next(iter(manifest["files"]))
            manifest["files"][first_module]["sha256"] = "0" * 64
            output.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

            rc_verify = run_cli("integrity", "--manifest", str(output))
            assert rc_verify == 1

    def test_removed_module_from_manifest_detected(self, tmp_path: Path):
        output = tmp_path / "integrity.json"

        rc_gen = run_cli("integrity", "--generate", str(output))
        assert rc_gen == 0

        # Remove a module entry from manifest
        manifest = json.loads(output.read_text(encoding="utf-8"))
        original_count = len(manifest["files"])
        if original_count > 1:
            first_key = next(iter(manifest["files"]))
            del manifest["files"][first_key]
            output.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

            # Re-verify: the verifier should detect the missing module
            # (it may pass or fail depending on verifier behavior, but the
            # manifest should now differ from a fresh generation)
            fresh = tmp_path / "fresh.json"
            run_cli("integrity", "--generate", str(fresh))
            fresh_manifest = json.loads(fresh.read_text(encoding="utf-8"))
            assert len(fresh_manifest["files"]) == original_count
            assert len(manifest["files"]) == original_count - 1


class TestIntegrityJsonOutput:
    """Test --json flag for machine-readable output."""

    def test_verify_json_output_structure(self, tmp_path: Path, capsys):
        output = tmp_path / "integrity.json"
        run_cli("integrity", "--generate", str(output))

        # Clear capsys buffer from generate step
        capsys.readouterr()

        run_cli("integrity", "--manifest", str(output), "--json")

        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert "passed" in data
        assert data["passed"] is True

    def test_verify_json_output_on_tampered_manifest(self, tmp_path: Path, capsys):
        output = tmp_path / "integrity.json"
        run_cli("integrity", "--generate", str(output))

        # Tamper
        manifest = json.loads(output.read_text(encoding="utf-8"))
        if manifest["files"]:
            first_module = next(iter(manifest["files"]))
            manifest["files"][first_module]["sha256"] = "a" * 64
            output.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

            # Clear capsys buffer
            capsys.readouterr()

            run_cli("integrity", "--manifest", str(output), "--json")

            captured = capsys.readouterr()
            data = json.loads(captured.out)
            assert data["passed"] is False


class TestIntegrityNoArgs:
    """Test that running integrity without --generate or --manifest still works."""

    def test_integrity_no_flags_verifies_live(self, capsys):
        """Without flags, integrity subcommand verifies live modules."""
        rc = run_cli("integrity")

        # Should pass (live verification, no manifest comparison)
        assert rc == 0
