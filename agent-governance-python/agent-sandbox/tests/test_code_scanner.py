# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for host-side sandbox code scanning."""

from __future__ import annotations

import pytest

from agent_sandbox.code_scanner import (
    SandboxCodeViolation,
    enforce_no_subprocess_execution,
    scan_code_for_subprocesses,
)


def _patterns(code: str) -> list[str]:
    return [violation.pattern for violation in scan_code_for_subprocesses(code)]


class TestCodeScanner:
    @pytest.mark.parametrize(
        ("code", "pattern"),
        [
            ("import subprocess\nsubprocess.run(['ls'])", "subprocess.run"),
            ("import subprocess as sp\nsp.Popen(['az'])", "subprocess.Popen"),
            ("from subprocess import check_output\ncheck_output(['id'])", "subprocess.check_output"),
            ("import os\nos.system('id')", "os.system"),
            ("from os import popen as pipe\npipe('whoami')", "os.popen"),
            ("import shutil\nshutil.which('kubectl')", "shutil.which"),
            ("import pty\npty.spawn('/bin/sh')", "pty.spawn"),
            ("__import__('subprocess').run(['ls'])", "subprocess.run"),
        ],
    )
    def test_detects_obvious_process_patterns(self, code, pattern):
        assert pattern in _patterns(code)

    def test_does_not_flag_strings_or_comments(self):
        code = """
# subprocess.run(['ls'])
print("os.system('id')")
"""
        assert scan_code_for_subprocesses(code) == []

    def test_syntax_errors_are_left_to_python_runtime(self):
        assert scan_code_for_subprocesses("def broken(") == []

    def test_wildcard_import_from_dangerous_module_blocks(self):
        violations = scan_code_for_subprocesses("from subprocess import *")
        assert violations[0].pattern == "subprocess.*"

    def test_enforce_raises_with_violation_details(self):
        with pytest.raises(SandboxCodeViolation, match="subprocess.run") as exc:
            enforce_no_subprocess_execution("import subprocess\nsubprocess.run(['ls'])")

        assert exc.value.violations[0].line == 2
