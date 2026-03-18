# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the plugin subprocess sandbox (V28)."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentmesh.marketplace.sandbox import (
    PluginSandbox,
    PluginSandboxError,
)


@pytest.fixture
def plugins_dir(tmp_path: Path) -> Path:
    d = tmp_path / "plugins"
    d.mkdir()
    return d


def _create_plugin(plugins_dir: Path, name: str, code: str) -> Path:
    """Helper to create a plugin with the given code."""
    plugin_dir = plugins_dir / name
    plugin_dir.mkdir(parents=True, exist_ok=True)
    mod_name = name.replace("-", "_")
    (plugin_dir / f"{mod_name}.py").write_text(code, encoding="utf-8")
    return plugin_dir


# ===========================================================================
# Happy path
# ===========================================================================


class TestSandboxHappyPath:
    """Basic sandbox execution works correctly."""

    def test_simple_echo(self, plugins_dir: Path):
        _create_plugin(plugins_dir, "echo-plugin", """
def process(data):
    return {"echo": data}
""")
        sandbox = PluginSandbox(plugins_dir)
        result = sandbox.execute("echo-plugin", "process", {"msg": "hello"})
        assert result["result"]["echo"]["msg"] == "hello"

    def test_pure_computation(self, plugins_dir: Path):
        _create_plugin(plugins_dir, "math-plugin", """
def add(data):
    return {"sum": data["a"] + data["b"]}
""")
        sandbox = PluginSandbox(plugins_dir)
        result = sandbox.execute("math-plugin", "add", {"a": 3, "b": 7})
        assert result["result"]["sum"] == 10

    def test_custom_module_name(self, plugins_dir: Path):
        plugin_dir = plugins_dir / "my-plugin"
        plugin_dir.mkdir()
        (plugin_dir / "custom_mod.py").write_text("""
def greet(data):
    return {"greeting": f"Hello, {data['name']}!"}
""", encoding="utf-8")
        sandbox = PluginSandbox(plugins_dir)
        result = sandbox.execute(
            "my-plugin", "greet", {"name": "World"},
            module_name="custom_mod",
        )
        assert result["result"]["greeting"] == "Hello, World!"

    def test_returns_list(self, plugins_dir: Path):
        _create_plugin(plugins_dir, "list-plugin", """
def items(data):
    return [1, 2, 3]
""")
        sandbox = PluginSandbox(plugins_dir)
        result = sandbox.execute("list-plugin", "items", {})
        assert result["result"] == [1, 2, 3]

    def test_returns_string(self, plugins_dir: Path):
        _create_plugin(plugins_dir, "str-plugin", """
def say(data):
    return "ok"
""")
        sandbox = PluginSandbox(plugins_dir)
        result = sandbox.execute("str-plugin", "say", {})
        assert result["result"] == "ok"


# ===========================================================================
# Blocked imports (core security tests)
# ===========================================================================


class TestSandboxBlockedImports:
    """Dangerous module imports are blocked at runtime."""

    @pytest.mark.parametrize("module", [
        "subprocess", "os", "shutil", "ctypes", "importlib",
        "socket", "pickle", "marshal", "multiprocessing",
    ])
    def test_blocked_module_import(self, plugins_dir: Path, module: str):
        _create_plugin(plugins_dir, "evil-plugin", f"""
import {module}
def run(data):
    return "should not reach here"
""")
        sandbox = PluginSandbox(plugins_dir)
        result = sandbox.execute("evil-plugin", "run", {})
        assert "error" in result
        assert "blocked" in result["error"].lower() or "import" in result["error"].lower()

    def test_blocked_os_path(self, plugins_dir: Path):
        _create_plugin(plugins_dir, "os-path-plugin", """
import os.path
def run(data):
    return os.path.exists("/etc/passwd")
""")
        sandbox = PluginSandbox(plugins_dir)
        result = sandbox.execute("os-path-plugin", "run", {})
        assert "error" in result

    def test_blocked_from_import(self, plugins_dir: Path):
        _create_plugin(plugins_dir, "from-import-plugin", """
from subprocess import Popen
def run(data):
    return "nope"
""")
        sandbox = PluginSandbox(plugins_dir)
        result = sandbox.execute("from-import-plugin", "run", {})
        assert "error" in result

    def test_blocked_dynamic_import(self, plugins_dir: Path):
        _create_plugin(plugins_dir, "dynamic-plugin", """
def run(data):
    mod = __import__("subprocess")
    return mod.check_output(["whoami"]).decode()
""")
        sandbox = PluginSandbox(plugins_dir)
        result = sandbox.execute("dynamic-plugin", "run", {})
        assert "error" in result

    def test_allowed_safe_modules(self, plugins_dir: Path):
        _create_plugin(plugins_dir, "safe-plugin", """
import json
import math
import hashlib
import re
def run(data):
    return {"pi": math.pi, "hash": hashlib.sha256(b"test").hexdigest()}
""")
        sandbox = PluginSandbox(plugins_dir)
        result = sandbox.execute("safe-plugin", "run", {})
        assert "result" in result
        assert result["result"]["pi"] == 3.141592653589793


# ===========================================================================
# Restricted builtins
# ===========================================================================


class TestSandboxRestrictedBuiltins:
    """Dangerous builtins are removed."""

    def test_no_eval(self, plugins_dir: Path):
        _create_plugin(plugins_dir, "eval-plugin", """
def run(data):
    return eval("1+1")
""")
        sandbox = PluginSandbox(plugins_dir)
        result = sandbox.execute("eval-plugin", "run", {})
        assert "error" in result

    def test_no_exec(self, plugins_dir: Path):
        _create_plugin(plugins_dir, "exec-plugin", """
def run(data):
    exec("x = 1")
    return x
""")
        sandbox = PluginSandbox(plugins_dir)
        result = sandbox.execute("exec-plugin", "run", {})
        assert "error" in result

    def test_no_compile_code_execution(self, plugins_dir: Path):
        """compile() is available (needed by importlib) but exec/eval are blocked,
        so compile+exec attack vector doesn't work.
        """
        _create_plugin(plugins_dir, "compile-exec-plugin", """
def run(data):
    code = compile("__import__('subprocess')", "<string>", "eval")
    return eval(code)
""")
        sandbox = PluginSandbox(plugins_dir)
        result = sandbox.execute("compile-exec-plugin", "run", {})
        assert "error" in result


# ===========================================================================
# Timeout
# ===========================================================================


class TestSandboxTimeout:
    """Plugins that hang are killed."""

    def test_infinite_loop_killed(self, plugins_dir: Path):
        _create_plugin(plugins_dir, "hang-plugin", """
import time
def run(data):
    time.sleep(999)
    return "never"
""")
        sandbox = PluginSandbox(plugins_dir, timeout_seconds=2)
        with pytest.raises(PluginSandboxError, match="timeout"):
            sandbox.execute("hang-plugin", "run", {})

    def test_custom_timeout_override(self, plugins_dir: Path):
        _create_plugin(plugins_dir, "slow-plugin", """
import time
def run(data):
    time.sleep(10)
    return "done"
""")
        sandbox = PluginSandbox(plugins_dir, timeout_seconds=60)
        with pytest.raises(PluginSandboxError, match="timeout"):
            sandbox.execute("slow-plugin", "run", {}, timeout=2)


# ===========================================================================
# Error handling
# ===========================================================================


class TestSandboxErrorHandling:
    """Errors in plugins are captured cleanly."""

    def test_plugin_not_installed(self, plugins_dir: Path):
        sandbox = PluginSandbox(plugins_dir)
        with pytest.raises(PluginSandboxError, match="not installed"):
            sandbox.execute("ghost-plugin", "run", {})

    def test_missing_entry_function(self, plugins_dir: Path):
        _create_plugin(plugins_dir, "no-func-plugin", """
def other():
    pass
""")
        sandbox = PluginSandbox(plugins_dir)
        result = sandbox.execute("no-func-plugin", "run", {})
        assert "error" in result
        assert "not found" in result["error"]

    def test_plugin_raises_exception(self, plugins_dir: Path):
        _create_plugin(plugins_dir, "error-plugin", """
def run(data):
    raise ValueError("something went wrong")
""")
        sandbox = PluginSandbox(plugins_dir)
        result = sandbox.execute("error-plugin", "run", {})
        assert "error" in result
        assert "something went wrong" in result["error"]

    def test_non_serializable_result(self, plugins_dir: Path):
        _create_plugin(plugins_dir, "bad-result-plugin", """
def run(data):
    return object()
""")
        sandbox = PluginSandbox(plugins_dir)
        # object() can't be serialized — either JSON error or sandbox error
        try:
            result = sandbox.execute("bad-result-plugin", "run", {})
            assert "error" in result
        except PluginSandboxError:
            pass  # also acceptable — invalid JSON output from subprocess

    def test_syntax_error_in_plugin(self, plugins_dir: Path):
        _create_plugin(plugins_dir, "syntax-plugin", """
def run(data)
    return "missing colon"
""")
        sandbox = PluginSandbox(plugins_dir)
        # Syntax errors prevent module loading — subprocess crashes
        with pytest.raises(PluginSandboxError):
            sandbox.execute("syntax-plugin", "run", {})


# ===========================================================================
# Environment isolation
# ===========================================================================


class TestSandboxIsolation:
    """Subprocess has minimal environment."""

    def test_no_env_vars_leaked(self, plugins_dir: Path):
        """os module is blocked, so plugins can't read env vars."""
        _create_plugin(plugins_dir, "env-plugin", """
def run(data):
    import os
    return {"home": os.environ.get("HOME", "")}
""")
        sandbox = PluginSandbox(plugins_dir)
        result = sandbox.execute("env-plugin", "run", {})
        assert "error" in result  # os is blocked

    def test_cannot_access_filesystem_via_os(self, plugins_dir: Path):
        _create_plugin(plugins_dir, "fs-plugin", """
def run(data):
    import os
    return {"files": os.listdir("/")}
""")
        sandbox = PluginSandbox(plugins_dir)
        result = sandbox.execute("fs-plugin", "run", {})
        assert "error" in result  # os is blocked
