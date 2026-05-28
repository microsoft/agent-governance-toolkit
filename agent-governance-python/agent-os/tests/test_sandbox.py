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

    def test_whitelist_drops_open(self):
        """Hardening: ``open`` is not in the safe whitelist by default."""
        sandbox = ExecutionSandbox()
        restricted = sandbox.create_restricted_globals()
        # 'open' is now in blocked_builtins, so it's a raising stub (not missing)
        # but the key property is it cannot be called successfully.
        assert "open" in restricted["__builtins__"]
        with pytest.raises(SecurityError):
            restricted["__builtins__"]["open"]("/etc/passwd")

    def test_whitelist_drops_dangerous_unlisted_builtins(self):
        """Hardening: builtins neither whitelisted nor blocked are omitted."""
        sandbox = ExecutionSandbox()
        restricted = sandbox.create_restricted_globals()
        # __loader__, __spec__, __build_class__ flavour — must not leak
        # arbitrary unfiltered builtins. We pick a few that are real but
        # neither on the safe whitelist nor in the explicit blocked list.
        for name in ("copyright", "credits", "license", "exit", "quit"):
            assert name not in restricted["__builtins__"], (
                f"{name} should not leak into restricted globals"
            )

    def test_user_globals_cannot_inject_builtins(self):
        sandbox = ExecutionSandbox()
        evil_builtins = {"eval": lambda s: "pwned"}
        restricted = sandbox.create_restricted_globals(
            {"__builtins__": evil_builtins}
        )
        # The injected __builtins__ must be ignored
        assert restricted["__builtins__"] is not evil_builtins
        with pytest.raises(SecurityError):
            restricted["__builtins__"]["eval"]("1")


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


# ---------------------------------------------------------------------------
# Hardening: dunder traversal, sys.modules bypass, AST enforcement
# ---------------------------------------------------------------------------


class TestDunderEscapeDetection:
    """Regression coverage for ``().__class__.__bases__[0].__subclasses__()``."""

    def test_detects_class_traversal(self):
        sandbox = ExecutionSandbox()
        violations = sandbox.validate_code(
            "x = ().__class__.__bases__[0].__subclasses__()"
        )
        kinds = {v.violation_type for v in violations}
        assert "dunder_escape" in kinds

    def test_detects_globals_access(self):
        sandbox = ExecutionSandbox()
        violations = sandbox.validate_code("f.__globals__['os']")
        assert any(v.violation_type == "dunder_escape" for v in violations)

    def test_detects_getattr_dunder_bypass(self):
        sandbox = ExecutionSandbox()
        violations = sandbox.validate_code(
            "cls = getattr((), '__class__')"
        )
        assert any(v.violation_type == "dunder_escape" for v in violations)

    def test_clean_attribute_access_ok(self):
        sandbox = ExecutionSandbox()
        violations = sandbox.validate_code("y = obj.normal_attr")
        assert violations == []


class TestSysModulesBypass:
    """The original escape path: import hook blocks NEW imports, but
    ``sys.modules['os']`` already has a cached reference."""

    def test_ast_detects_sys_modules_lookup(self):
        sandbox = ExecutionSandbox()
        violations = sandbox.validate_code("sys.modules['os'].system('id')")
        kinds = {v.violation_type for v in violations}
        # sys is a blocked module call AND sys.modules subscript is flagged
        assert "sys_modules_access" in kinds

    def test_sys_module_is_blocked_by_default(self):
        sandbox = ExecutionSandbox()
        assert sandbox.check_import("sys") is False
        assert sandbox.check_import("builtins") is False
        assert sandbox.check_import("gc") is False
        assert sandbox.check_import("inspect") is False

    def test_shadow_sys_modules_blocks_runtime_access(self):
        """The key hardening: even with cached sys.modules entries,
        runtime attribute access on shadowed modules raises SecurityError."""
        sandbox = ExecutionSandbox()
        captured: dict = {}

        def attempt_escape():
            # 'sys' is in blocked_modules and already cached in sys.modules.
            # After shadowing, sys.modules['sys'] is a proxy.
            captured["proxy"] = sys.modules["sys"]
            # Any attribute access raises SecurityError
            return captured["proxy"].modules

        with pytest.raises(SecurityError):
            sandbox.execute_sandboxed(attempt_escape)

        # sys.modules must be restored after execution
        assert sys.modules["sys"] is sys
        assert sys.modules["os"] is __import__("os")

    def test_shadow_sys_modules_blocks_os_access(self):
        sandbox = ExecutionSandbox()

        def attempt_escape():
            return sys.modules["os"].getcwd()

        with pytest.raises(SecurityError):
            sandbox.execute_sandboxed(attempt_escape)

        # Restored
        import os as _os
        assert sys.modules["os"] is _os

    def test_shadow_sys_modules_restored_on_exception(self):
        sandbox = ExecutionSandbox()
        original_os = sys.modules["os"]

        def boom():
            raise RuntimeError("user error")

        with pytest.raises(RuntimeError):
            sandbox.execute_sandboxed(boom)

        assert sys.modules["os"] is original_os

    def test_shadow_can_be_disabled(self):
        """Opt-out flag preserves prior behaviour for hosts that need it."""
        import os as _os
        sandbox = ExecutionSandbox(
            config=SandboxConfig(shadow_sys_modules=False)
        )

        def safe():
            return sys.modules["os"].path.sep  # Would raise if shadowed

        result = sandbox.execute_sandboxed(safe)
        assert result == _os.path.sep

    def test_shadow_proxy_denies_class_traversal(self):
        """Hardening: ``type(proxy).__mro__[1].__subclasses__()`` escape.

        Even when bytecode bypasses AST validation (e.g. a trusted host
        function calls into the sandbox), the proxy itself must refuse to
        leak its own ``__class__`` via Python-level attribute lookup.
        """
        sandbox = ExecutionSandbox()
        captured: dict = {}

        def grab_proxy():
            captured["proxy"] = sys.modules["os"]
            return captured["proxy"].__class__  # must raise

        with pytest.raises(SecurityError):
            sandbox.execute_sandboxed(grab_proxy)

    def test_nested_execute_sandboxed_keeps_outer_shadow(self):
        """Regression: inner call's restore must not unshadow the outer call.

        Previously the inner ``finally`` cleared the shared shadow dict,
        leaving the outer call running with real ``sys.modules['os']``.
        """
        sandbox = ExecutionSandbox()

        def inner():
            # Inner sandboxed call exits and runs its own restore.
            sandbox.execute_sandboxed(lambda: None)
            # Outer must still see the proxy.
            return type(sys.modules["os"]).__name__

        result_type = sandbox.execute_sandboxed(inner)
        assert result_type == "_BlockedModuleProxy"
        # And after both exits, sys.modules is fully restored.
        import os as _os
        assert sys.modules["os"] is _os

    def test_nested_execute_sandboxed_keeps_outer_hook(self):
        """Regression: inner call must not uninstall the import hook.

        Previously ``_install_hook_reentrant`` LIFO-popped without tracking
        whether the inner layer actually owned the install, so nested
        same-instance calls left the outer call without an import hook.
        """
        sandbox = ExecutionSandbox()

        def inner():
            sandbox.execute_sandboxed(lambda: None)
            # After the inner call returns, the import hook must still
            # be on sys.meta_path so the outer call can block imports.
            return sandbox._hook in sys.meta_path

        assert sandbox.execute_sandboxed(inner) is True
        # And after the outer call exits, the hook is cleaned up.
        assert sandbox._hook not in sys.meta_path

    def test_concurrent_execute_sandboxed_is_thread_safe(self):
        """Regression: two threads must not corrupt each other's shadow.

        Without the shared lock + depth counter, a fast thread's restore
        wiped a slow thread's still-active shadow, exposing real
        ``sys.modules['os']`` mid-execution.
        """
        import threading
        import time

        sandbox = ExecutionSandbox()
        observed: dict[str, str] = {}

        def worker(name: str, sleep_s: float):
            def body():
                time.sleep(sleep_s)
                observed[name] = type(sys.modules["os"]).__name__
            sandbox.execute_sandboxed(body)

        t_slow = threading.Thread(target=worker, args=("slow", 0.30))
        t_fast = threading.Thread(target=worker, args=("fast", 0.05))
        t_slow.start()
        # Give slow a head start so its shadow is up before fast enters.
        time.sleep(0.05)
        t_fast.start()
        t_slow.join()
        t_fast.join()

        assert observed["slow"] == "_BlockedModuleProxy"
        assert observed["fast"] == "_BlockedModuleProxy"
        # Process-wide restore: nothing left over.
        import os as _os
        assert sys.modules["os"] is _os


class TestExecuteCodeSandboxed:
    """End-to-end fail-closed code execution path."""

    def test_validation_rejects_blocked_import_before_exec(self):
        sandbox = ExecutionSandbox()
        with pytest.raises(SecurityError) as exc_info:
            sandbox.execute_code_sandboxed("import subprocess")
        assert exc_info.value.error_code == "SANDBOX_VALIDATION_FAILED"
        assert "violations" in exc_info.value.details

    def test_validation_rejects_dunder_escape(self):
        sandbox = ExecutionSandbox()
        with pytest.raises(SecurityError):
            sandbox.execute_code_sandboxed(
                "x = ().__class__.__bases__[0].__subclasses__()"
            )

    def test_validation_rejects_sys_modules(self):
        sandbox = ExecutionSandbox()
        with pytest.raises(SecurityError):
            sandbox.execute_code_sandboxed(
                "result = sys.modules['os'].system('whoami')"
            )

    def test_clean_code_executes(self):
        sandbox = ExecutionSandbox()
        result = sandbox.execute_code_sandboxed("x = 1 + 2\ny = x * 10")
        assert result["x"] == 3
        assert result["y"] == 30
        assert "__builtins__" not in result

    def test_user_globals_available(self):
        sandbox = ExecutionSandbox()
        result = sandbox.execute_code_sandboxed(
            "out = base + 5", user_globals={"base": 100}
        )
        assert result["out"] == 105

    def test_validation_can_be_disabled(self):
        """If a host opts out of AST validation, runtime guards still fire."""
        sandbox = ExecutionSandbox(
            config=SandboxConfig(enforce_ast_validation=False)
        )
        # eval is still replaced in restricted builtins -> raises at runtime,
        # which execute_code_sandboxed rewraps as SecurityError.
        with pytest.raises(SecurityError):
            sandbox.execute_code_sandboxed("eval('1+1')")

    def test_fail_closed_on_runtime_error(self):
        """Unexpected exceptions during sandboxed exec become SecurityError."""
        sandbox = ExecutionSandbox(
            config=SandboxConfig(enforce_ast_validation=False)
        )
        with pytest.raises(SecurityError) as exc_info:
            sandbox.execute_code_sandboxed("raise RuntimeError('inner')")
        assert exc_info.value.error_code == "SANDBOX_EXECUTION_ERROR"


class TestDefaultBlockedModulesExpanded:
    """Hardening: confirm escape-vector modules are blocked by default."""

    @pytest.mark.parametrize(
        "name",
        [
            "sys", "builtins", "gc", "inspect", "pickle", "marshal",
            "code", "codeop", "_posixsubprocess", "multiprocessing",
            "threading", "_thread",
        ],
    )
    def test_escape_vector_module_blocked(self, name):
        cfg = SandboxConfig()
        assert name in cfg.blocked_modules

    @pytest.mark.parametrize(
        "name", ["open", "breakpoint", "globals", "locals", "getattr"],
    )
    def test_escape_vector_builtin_blocked(self, name):
        cfg = SandboxConfig()
        assert name in cfg.blocked_builtins


class TestWarningCategory:
    """SandboxSecurityWarning lets callers filter sandbox warnings precisely."""

    def test_default_init_emits_sandbox_warning(self):
        from agent_os.sandbox import SandboxSecurityWarning

        with pytest.warns(SandboxSecurityWarning):
            ExecutionSandbox()
