# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for CLI edge cases (GitHub issue #159).

Covers:
- Providing both --manifest and --generate simultaneously
- Non-existent manifest file path
- Read-only output directory
"""

from __future__ import annotations

import os
import stat
import sys

import pytest

from agent_compliance.cli.main import main


def run_cli(*args: str) -> int:
    """Run the CLI with the given arguments and return the exit code."""
    old_argv = sys.argv
    sys.argv = ["agent-compliance", *args]
    try:
        return main()
    finally:
        sys.argv = old_argv


class TestIntegrityBothFlags:
    """--manifest and --generate are mutually exclusive."""

    def test_both_manifest_and_generate_errors(self, tmp_path, capsys):
        manifest_file = str(tmp_path / "existing.json")
        output_file = str(tmp_path / "generated.json")

        with open(manifest_file, "w") as f:
            f.write("{}")

        rc = run_cli(
            "integrity",
            "--manifest", manifest_file,
            "--generate", output_file,
        )

        assert rc == 1
        captured = capsys.readouterr()
        assert "mutually exclusive" in captured.err


class TestNonExistentManifest:
    """Passing a manifest path that does not exist should fail gracefully."""

    def test_nonexistent_manifest_returns_error(self, capsys):
        rc = run_cli(
            "integrity",
            "--manifest", "/absolutely/does/not/exist/integrity.json",
        )

        assert rc == 1
        captured = capsys.readouterr()
        assert "not found" in captured.err

    def test_nonexistent_manifest_no_traceback(self, capsys):
        """The error should be user-friendly, not a raw traceback."""
        run_cli(
            "integrity",
            "--manifest", "/absolutely/does/not/exist/integrity.json",
        )

        captured = capsys.readouterr()
        assert "Traceback" not in captured.err
        assert "Traceback" not in captured.out


class TestReadOnlyOutputDirectory:
    """Generating a manifest into a read-only directory should fail
    gracefully with a non-zero exit code."""

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="chmod-based read-only directories are not enforced on Windows",
    )
    def test_readonly_output_dir(self, tmp_path):
        readonly_dir = tmp_path / "locked"
        readonly_dir.mkdir()

        output_file = str(readonly_dir / "integrity.json")

        # Make the directory read-only
        readonly_dir.chmod(stat.S_IRUSR | stat.S_IXUSR)

        try:
            rc = run_cli("integrity", "--generate", output_file)

            assert rc == 1
            assert not os.path.exists(output_file)
        finally:
            # Restore permissions for cleanup
            readonly_dir.chmod(stat.S_IRWXU)

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason="chmod-based read-only directories are not enforced on Windows",
    )
    def test_readonly_output_dir_error_message(self, tmp_path, capsys):
        readonly_dir = tmp_path / "locked"
        readonly_dir.mkdir()

        output_file = str(readonly_dir / "integrity.json")

        readonly_dir.chmod(stat.S_IRUSR | stat.S_IXUSR)

        try:
            run_cli("integrity", "--generate", output_file)

            captured = capsys.readouterr()
            assert "Error" in captured.err or "error" in captured.err.lower()
            assert "Traceback" not in captured.err
            assert "Traceback" not in captured.out
        finally:
            readonly_dir.chmod(stat.S_IRWXU)
