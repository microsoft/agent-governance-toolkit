# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Plugin Sandbox — Subprocess Isolation
======================================

Executes plugin code in an isolated subprocess with:
- Blocked dangerous module imports (subprocess, os, ctypes, etc.)
- Restricted built-in functions at runtime (no exec/eval/breakpoint)
- JSON-only I/O (stdin → stdout)
- Configurable timeout (default 30s)
- No access to AgentMesh internals

Security layers (defense-in-depth):
1. Subprocess isolation — separate process, no shared memory
2. Import guard — blocks dangerous modules before AND during execution
3. Builtin restriction — exec/eval/breakpoint removed AFTER module loading
   (kept during import because importlib.exec_module needs them)
4. Minimal environment — no secrets leaked via env vars
5. Timeout — kills runaway processes

Usage:
    sandbox = PluginSandbox(plugins_dir=Path("./plugins"))
    result = sandbox.execute(
        plugin_name="my-plugin",
        entry_function="process",
        input_data={"query": "hello"},
    )
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any, Optional

from agentmesh.marketplace.installer import RESTRICTED_MODULES, MarketplaceError

logger = logging.getLogger(__name__)

# Default execution timeout in seconds.
DEFAULT_TIMEOUT_SECONDS = 30

# Additional modules blocked beyond RESTRICTED_MODULES.
_EXTRA_BLOCKED = frozenset({
    "socket", "http", "urllib", "ftplib", "smtplib", "telnetlib",
    "pickle", "shelve", "marshal", "code", "codeop", "compileall",
    "multiprocessing", "signal", "resource", "pty", "termios",
    "fcntl", "mmap", "winreg", "_winapi",
})

ALL_BLOCKED_MODULES = RESTRICTED_MODULES | _EXTRA_BLOCKED

# The runner script is injected into the subprocess via -c.
# It installs an import guard, loads the plugin, calls the entry
# function with JSON from stdin, and writes JSON to stdout.
_RUNNER_TEMPLATE = textwrap.dedent("""\
    import importlib, json, sys

    # ── 1. Install import guard ──────────────────────────────────
    _BLOCKED = {blocked!r}
    _real_import = __builtins__.__import__ if hasattr(__builtins__, '__import__') else __import__

    def _guarded_import(name, *args, **kwargs):
        top = name.split(".")[0]
        if top in _BLOCKED:
            raise ImportError(
                f"Import of '{{name}}' is blocked by the AgentMesh plugin sandbox."
            )
        return _real_import(name, *args, **kwargs)

    if isinstance(__builtins__, dict):
        __builtins__["__import__"] = _guarded_import
    else:
        __builtins__.__import__ = _guarded_import

    # ── 2. Read input ────────────────────────────────────────────
    try:
        input_data = json.loads(sys.stdin.read())
    except Exception as exc:
        json.dump({{"error": f"Invalid JSON input: {{exc}}"}}, sys.stdout)
        sys.exit(1)

    # ── 3. Load plugin module (builtins intact for importlib) ────
    plugin_dir = input_data.get("_plugin_dir", "")
    module_name = input_data.get("_module_name", "")
    entry_func = input_data.get("_entry_function", "")
    payload = input_data.get("data", {{}})

    if plugin_dir:
        sys.path.insert(0, plugin_dir)

    try:
        mod = importlib.import_module(module_name)
    except ImportError as exc:
        json.dump({{"error": f"Cannot import plugin: {{exc}}"}}, sys.stdout)
        sys.exit(1)

    fn = getattr(mod, entry_func, None)
    if fn is None:
        json.dump({{"error": f"Entry function '{{entry_func}}' not found in {{module_name}}"}}, sys.stdout)
        sys.exit(1)

    # ── 4. Strip dangerous builtins AFTER import ─────────────────
    # exec/eval/compile are needed by importlib during module loading,
    # but must be blocked before running plugin entry code.
    _STRIP = ("exec", "eval", "breakpoint")
    if isinstance(__builtins__, dict):
        for _b in _STRIP:
            __builtins__.pop(_b, None)
    else:
        for _b in _STRIP:
            if hasattr(__builtins__, _b):
                delattr(__builtins__, _b)

    # ── 5. Call entry function ───────────────────────────────────
    try:
        result = fn(payload)
    except Exception as exc:
        json.dump({{"error": f"Plugin raised: {{type(exc).__name__}}: {{exc}}"}}, sys.stdout)
        sys.exit(1)

    # ── 6. Write output ──────────────────────────────────────────
    try:
        json.dump({{"result": result}}, sys.stdout)
    except (TypeError, ValueError) as exc:
        json.dump({{"error": f"Plugin returned non-serializable result: {{exc}}"}}, sys.stdout)
        sys.exit(1)
""")


class PluginSandboxError(MarketplaceError):
    """Raised when sandbox execution fails."""


class PluginSandbox:
    """Execute plugin code in an isolated subprocess.

    Plugins receive JSON input and must return JSON output.
    They cannot import dangerous modules, use exec/eval, or access
    the host process in any way.

    Args:
        plugins_dir: Directory where plugins are installed.
        timeout_seconds: Maximum execution time before the subprocess
            is killed. Defaults to 30.
        python_executable: Path to the Python interpreter. Defaults to
            the current interpreter (``sys.executable``).
    """

    def __init__(
        self,
        plugins_dir: Path,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        python_executable: Optional[str] = None,
    ) -> None:
        self._plugins_dir = plugins_dir
        self._timeout = timeout_seconds
        self._python = python_executable or sys.executable

    def execute(
        self,
        plugin_name: str,
        entry_function: str,
        input_data: dict[str, Any],
        *,
        module_name: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> dict[str, Any]:
        """Execute a plugin function in the sandbox.

        Args:
            plugin_name: Installed plugin name (directory under plugins_dir).
            entry_function: Name of the function to call in the plugin module.
            input_data: JSON-serializable dict passed to the function.
            module_name: Python module to import. Defaults to ``plugin_name``
                with hyphens replaced by underscores.
            timeout: Override the default timeout for this execution.

        Returns:
            Dict with either ``{"result": ...}`` on success or
            ``{"error": "..."}`` on failure.

        Raises:
            PluginSandboxError: On timeout, crash, or invalid output.
        """
        plugin_dir = self._plugins_dir / plugin_name
        if not plugin_dir.is_dir():
            raise PluginSandboxError(f"Plugin not installed: {plugin_name}")

        mod_name = module_name or plugin_name.replace("-", "_")
        effective_timeout = timeout or self._timeout

        # Build the payload sent via stdin
        envelope = {
            "_plugin_dir": str(plugin_dir),
            "_module_name": mod_name,
            "_entry_function": entry_function,
            "data": input_data,
        }

        runner_code = _RUNNER_TEMPLATE.format(blocked=set(ALL_BLOCKED_MODULES))

        # Minimal env — keep Python working but don't leak secrets.
        minimal_env = {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONIOENCODING": "utf-8",
        }
        # On Windows, Python needs SYSTEMROOT to load standard library.
        import os as _os
        for key in ("SYSTEMROOT", "SystemRoot", "COMSPEC", "TEMP", "TMP"):
            val = _os.environ.get(key)
            if val:
                minimal_env[key] = val

        try:
            proc = subprocess.run(  # noqa: S603 — trusted subprocess in sandbox execution
                [self._python, "-c", runner_code],
                input=json.dumps(envelope),
                capture_output=True,
                text=True,
                timeout=effective_timeout,
                env=minimal_env,
            )
        except subprocess.TimeoutExpired:
            raise PluginSandboxError(
                f"Plugin '{plugin_name}' exceeded {effective_timeout}s timeout"
            )

        if proc.returncode != 0 and not proc.stdout.strip():
            stderr_tail = (proc.stderr or "")[-500:]
            raise PluginSandboxError(
                f"Plugin '{plugin_name}' crashed (exit {proc.returncode}): {stderr_tail}"
            )

        try:
            output = json.loads(proc.stdout)
        except (json.JSONDecodeError, ValueError) as exc:
            raise PluginSandboxError(
                f"Plugin '{plugin_name}' returned invalid JSON: {exc}"
            )

        if "error" in output:
            logger.warning("Plugin %s error: %s", plugin_name, output["error"])

        return output
