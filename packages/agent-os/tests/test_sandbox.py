# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the execution sandbox (security enforcement)."""

import sys

import pytest

from agent_os.exceptions import SecurityError
from agent_os.sandbox import (
    ExecutionSandbox,
    SandboxConfig,
    SandboxImportHook,
    SecurityViolation,
)


# ---------------------------------------------------------------------------
# SandboxConfig
# ---------------------------------------------------------------------------


class TestSandboxConfig:
    def test_defaults(self):
        cfg = SandboxConfig()
        assert "subprocess" in cfg.blocked_modules
        assert "os" in cfg.blocked_modules
        assert "importlib" in cfg.blocked_modules
        assert "eval" in cfg.blocked_builtins
        assert cfg.allowed_paths == []
        assert cfg.max_memory_mb is None

    def test_custom_overrides(self):
        cfg = SandboxConfig(
            blocked_modules=["requests"],
            blocked_builtins=["exec"],
            allowed_paths=["/tmp"],
            max_memory_mb=256,
            max_cpu_seconds=10,
        )
        assert cfg.blocked_modules == ["requests"]
        assert cfg.blocked_builtins == ["exec"]
        assert cfg.allowed_paths == ["/tmp"]
        assert cfg.max_memory_mb == 256
        assert cfg.max_cpu_seconds == 10


# ---------------------------------------------------------------------------
# Import checks
# ---------------------------------------------------------------------------


class TestCheckImport:
    def test_blocked_module(self):
        sandbox = ExecutionSandbox()
        assert sandbox.check_import("subprocess") is False

    def test_blocked_submodule(self):
        sandbox = ExecutionSandbox()
        assert sandbox.check_import("os.path") is False

    def test_allowed_module(self):
        sandbox = ExecutionSandbox()
        assert sandbox.check_import("json") is True
        assert sandbox.check_import("math") is True


# ---------------------------------------------------------------------------
# Builtin checks
# ---------------------------------------------------------------------------


class TestCheckBuiltin:
    def test_blocked_builtin(self):
        sandbox = ExecutionSandbox()
        assert sandbox.check_builtin("eval") is False
        assert sandbox.check_builtin("exec") is False

    def test_allowed_builtin(self):
        sandbox = ExecutionSandbox()
        assert sandbox.check_builtin("print") is True
        assert sandbox.check_builtin("len") is True


# ---------------------------------------------------------------------------
# File-access checks
# ---------------------------------------------------------------------------


class TestCheckFileAccess:
    def test_no_allowed_paths_blocks_all(self):
        sandbox = ExecutionSandbox()
        assert sandbox.check_file_access("/etc/passwd", "r") is False

    def test_allowed_path_grants_access(self):
        sandbox = ExecutionSandbox(
            config=SandboxConfig(allowed_paths=["/tmp/sandbox"])
        )
        assert sandbox.check_file_access("/tmp/sandbox/data.txt", "r") is True

    def test_outside_allowed_path_blocked(self):
        sandbox = ExecutionSandbox(
            config=SandboxConfig(allowed_paths=["/tmp/sandbox"])
        )
        assert sandbox.check_file_access("/etc/passwd", "r") is False

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific path handling")
    def test_windows_paths(self):
        sandbox = ExecutionSandbox(
            config=SandboxConfig(allowed_paths=["C:/Users/agent/workspace"])
        )
        assert sandbox.check_file_access("C:\\Users\\agent\\workspace\\f.txt", "r") is True


# ---------------------------------------------------------------------------
# AST validation
# ---------------------------------------------------------------------------


class TestValidateCode:
    def test_detects_import_subprocess(self):
        sandbox = ExecutionSandbox()
        violations = sandbox.validate_code("import subprocess")
        assert len(violations) == 1
        assert violations[0].violation_type == "blocked_import"

    def test_detects_from_os_import(self):
        sandbox = ExecutionSandbox()
        violations = sandbox.validate_code("from os import system")
        assert len(violations) == 1
        assert violations[0].violation_type == "blocked_import"

    def test_detects_os_system_call(self):
        sandbox = ExecutionSandbox()
        code = "os.system('rm -rf /')"
        violations = sandbox.validate_code(code)
        assert any(v.violation_type == "blocked_module_call" for v in violations)

    def test_detects_eval_call(self):
        sandbox = ExecutionSandbox()
        violations = sandbox.validate_code("eval('1+1')")
        assert any(v.violation_type == "blocked_builtin" for v in violations)

    def test_clean_code_no_violations(self):
        sandbox = ExecutionSandbox()
        violations = sandbox.validate_code("x = 1 + 2\nprint(x)")
        assert violations == []

    def test_syntax_error_returns_violation(self):
        sandbox = ExecutionSandbox()
        violations = sandbox.validate_code("def (broken")
        assert len(violations) == 1
        assert violations[0].violation_type == "syntax_error"

    def test_detects_importlib_import_module_bypass(self):
        """Regression test for #179: importlib.import_module() must be flagged."""
        sandbox = ExecutionSandbox()
        code = "importlib.import_module('subprocess')"
        violations = sandbox.validate_code(code)
        assert any(
            v.violation_type == "blocked_import" and "importlib" in v.description
            for v in violations
        )

    def test_importlib_import_module_safe_module_ok(self):
        sandbox = ExecutionSandbox()
        code = "importlib.import_module('json')"
        violations = sandbox.validate_code(code)
        assert not any(
            v.violation_type == "blocked_import" and "importlib" in v.description
            for v in violations
        )

    def test_import_importlib_blocked(self):
        """Regression test for #179: 'import importlib' itself must be blocked."""
        sandbox = ExecutionSandbox()
        assert sandbox.check_import("importlib") is False
        violations = sandbox.validate_code("import importlib")
        assert any(v.violation_type == "blocked_import" for v in violations)


# ---------------------------------------------------------------------------
# Restricted globals
# ---------------------------------------------------------------------------


class TestRestrictedGlobals:
    def test_blocked_builtins_raise(self):
        sandbox = ExecutionSandbox()
        restricted = sandbox.create_restricted_globals()
        with pytest.raises(SecurityError):
            restricted["__builtins__"]["eval"]("1+1")

    def test_blocked_exec_raises(self):
        sandbox = ExecutionSandbox()
        restricted = sandbox.create_restricted_globals()
        with pytest.raises(SecurityError):
            restricted["__builtins__"]["exec"]("x = 1")

    def test_safe_builtins_still_work(self):
        sandbox = ExecutionSandbox()
        restricted = sandbox.create_restricted_globals()
        assert restricted["__builtins__"]["len"]([1, 2, 3]) == 3

    def test_user_globals_merged(self):
        sandbox = ExecutionSandbox()
        restricted = sandbox.create_restricted_globals({"my_var": 42})
        assert restricted["my_var"] == 42


# ---------------------------------------------------------------------------
# Import hook install / uninstall
# ---------------------------------------------------------------------------


class TestSandboxImportHook:
    def test_hook_install_and_uninstall(self):
        hook = SandboxImportHook(["fake_blocked_module_xyz"])
        assert hook not in sys.meta_path

        hook.install()
        assert hook in sys.meta_path

        hook.uninstall()
        assert hook not in sys.meta_path

    def test_hook_blocks_import(self):
        hook = SandboxImportHook(["fake_blocked_module_xyz"])
        hook.install()
        try:
            with pytest.raises(SecurityError, match="blocked by sandbox"):
                __import__("fake_blocked_module_xyz")
        finally:
            hook.uninstall()

    def test_hook_allows_safe_module(self):
        hook = SandboxImportHook(["fake_blocked_module_xyz"])
        hook.install()
        try:
            import json  # should not raise

            assert json is not None
        finally:
            hook.uninstall()


# ---------------------------------------------------------------------------
# execute_sandboxed
# ---------------------------------------------------------------------------


class TestExecuteSandboxed:
    def test_sandboxed_blocks_import(self):
        sandbox = ExecutionSandbox(
            config=SandboxConfig(blocked_modules=["fake_sandbox_test_mod"])
        )

        def bad_func():
            __import__("fake_sandbox_test_mod")

        with pytest.raises(SecurityError):
            sandbox.execute_sandboxed(bad_func)

        # Hook should be cleaned up
        assert sandbox._hook not in sys.meta_path

    def test_sandboxed_allows_normal_code(self):
        sandbox = ExecutionSandbox()
        result = sandbox.execute_sandboxed(lambda: 1 + 1)
        assert result == 2

    def test_sandboxed_cleans_up_on_error(self):
        sandbox = ExecutionSandbox()

        def raise_func():
            raise ValueError("boom")

        with pytest.raises(ValueError):
            sandbox.execute_sandboxed(raise_func)

        assert sandbox._hook not in sys.meta_path


# ---------------------------------------------------------------------------
# SecurityViolation dataclass
# ---------------------------------------------------------------------------


class TestSecurityViolation:
    def test_fields(self):
        v = SecurityViolation(
            line=10, column=4, violation_type="blocked_import",
            description="bad import", severity="critical",
        )
        assert v.line == 10
        assert v.column == 4
        assert v.severity == "critical"

    def test_default_severity(self):
        v = SecurityViolation(
            line=1, column=0, violation_type="test", description="test",
        )
        assert v.severity == "high"
