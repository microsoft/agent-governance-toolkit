# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Execution Sandbox for Agent OS

Prevents agents from bypassing the kernel via direct stdlib calls
(subprocess, os, eval, etc.) using import hooks and AST-based static analysis.
"""

from __future__ import annotations

import ast
import importlib.abc
import importlib.machinery
import os
import pathlib
import sys
import warnings
from dataclasses import dataclass, field
from typing import Any, Callable

from pydantic import BaseModel, Field

from agent_os.exceptions import SecurityError

_SAMPLE_DISCLAIMER = (
    "\u26a0\ufe0f  These are SAMPLE sandbox rules provided as a starting point. "
    "You MUST review, customise, and extend them for your specific use case "
    "before deploying to production."
)

_DEFAULT_BLOCKED_MODULES: list[str] = [
    "subprocess",
    "os",
    "shutil",
    "socket",
    "ctypes",
    "importlib",
]

_DEFAULT_BLOCKED_BUILTINS: list[str] = [
    "exec",
    "eval",
    "compile",
    "__import__",
]


# ---------------------------------------------------------------------------
# Externalised configuration dataclass
# ---------------------------------------------------------------------------

@dataclass
class SandboxSecurityConfig:
    """Structured configuration for sandbox security rules, loadable from YAML.

    Attributes:
        blocked_modules: Python modules to deny inside the sandbox.
        blocked_builtins: Built-in functions to block.
        disclaimer: Disclaimer text shown in logs.
    """

    blocked_modules: list[str] = field(default_factory=lambda: list(_DEFAULT_BLOCKED_MODULES))
    blocked_builtins: list[str] = field(default_factory=lambda: list(_DEFAULT_BLOCKED_BUILTINS))
    disclaimer: str = ""


def load_sandbox_config(path: str) -> SandboxSecurityConfig:
    """Load sandbox security configuration from a YAML file.

    Args:
        path: Path to a YAML file with a ``sandbox`` section.

    Returns:
        SandboxSecurityConfig populated from the YAML data.

    Raises:
        FileNotFoundError: If the config file does not exist.
        ValueError: If the YAML is missing the ``sandbox`` section.
    """
    import yaml

    if not os.path.exists(path):
        raise FileNotFoundError(f"Sandbox config not found: {path}")

    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh.read())

    if not isinstance(data, dict) or "sandbox" not in data:
        raise ValueError(f"YAML file must contain a 'sandbox' section: {path}")

    sp = data["sandbox"]
    return SandboxSecurityConfig(
        blocked_modules=sp.get("blocked_modules", list(_DEFAULT_BLOCKED_MODULES)),
        blocked_builtins=sp.get("blocked_builtins", list(_DEFAULT_BLOCKED_BUILTINS)),
        disclaimer=data.get("disclaimer", ""),
    )


class SandboxConfig(BaseModel):
    """Configuration for the execution sandbox."""

    blocked_modules: list[str] = Field(default_factory=lambda: list(_DEFAULT_BLOCKED_MODULES))
    blocked_builtins: list[str] = Field(default_factory=lambda: list(_DEFAULT_BLOCKED_BUILTINS))
    allowed_paths: list[str] = Field(default_factory=list)
    max_memory_mb: int | None = None
    max_cpu_seconds: int | None = None


@dataclass
class SecurityViolation:
    """Represents a security violation found during static analysis."""

    line: int
    column: int
    violation_type: str
    description: str
    severity: str = "high"


class SandboxImportHook(importlib.abc.MetaPathFinder):
    """Import hook that blocks imports of dangerous modules.

    Intercepts import attempts for blocked modules and raises SecurityError.
    Can be installed/uninstalled dynamically via install()/uninstall().
    """

    def __init__(self, blocked_modules: list[str]) -> None:
        self._blocked_modules = set(blocked_modules)

    def find_module(
        self,
        fullname: str,
        path: Any = None,
    ) -> SandboxImportHook | None:
        """Check if this module should be blocked (legacy API)."""
        top_level = fullname.split(".")[0]
        if top_level in self._blocked_modules:
            return self
        return None

    def load_module(self, fullname: str) -> None:
        """Block the import by raising SecurityError (legacy API)."""
        raise SecurityError(
            f"Import of '{fullname}' is blocked by sandbox policy",
            error_code="BLOCKED_IMPORT",
            details={"module": fullname},
        )

    def find_spec(
        self,
        fullname: str,
        path: Any = None,
        target: Any = None,
    ) -> None:
        """Intercept import via the modern finder protocol."""
        top_level = fullname.split(".")[0]
        if top_level in self._blocked_modules:
            raise SecurityError(
                f"Import of '{fullname}' is blocked by sandbox policy",
                error_code="BLOCKED_IMPORT",
                details={"module": fullname},
            )
        return None

    def install(self) -> None:
        """Install this hook into sys.meta_path."""
        if self not in sys.meta_path:
            sys.meta_path.insert(0, self)

    def uninstall(self) -> None:
        """Remove this hook from sys.meta_path."""
        while self in sys.meta_path:
            sys.meta_path.remove(self)


class _ASTSecurityVisitor(ast.NodeVisitor):
    """AST visitor that detects security violations in code."""

    def __init__(self, blocked_modules: set, blocked_builtins: set) -> None:
        self._blocked_modules = blocked_modules
        self._blocked_builtins = blocked_builtins
        self.violations: list[SecurityViolation] = []

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for alias in node.names:
            top_level = alias.name.split(".")[0]
            if top_level in self._blocked_modules:
                self.violations.append(
                    SecurityViolation(
                        line=node.lineno,
                        column=node.col_offset,
                        violation_type="blocked_import",
                        description=f"Import of blocked module '{alias.name}'",
                    )
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        if node.module:
            top_level = node.module.split(".")[0]
            if top_level in self._blocked_modules:
                self.violations.append(
                    SecurityViolation(
                        line=node.lineno,
                        column=node.col_offset,
                        violation_type="blocked_import",
                        description=f"Import from blocked module '{node.module}'",
                    )
                )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        # Detect calls to blocked builtins: eval(...), exec(...)
        if isinstance(node.func, ast.Name) and node.func.id in self._blocked_builtins:
            self.violations.append(
                SecurityViolation(
                    line=node.lineno,
                    column=node.col_offset,
                    violation_type="blocked_builtin",
                    description=f"Call to blocked builtin '{node.func.id}'",
                )
            )

        # Detect os.system(...) style calls
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                if node.func.value.id in self._blocked_modules:
                    self.violations.append(
                        SecurityViolation(
                            line=node.lineno,
                            column=node.col_offset,
                            violation_type="blocked_module_call",
                            description=(
                                f"Call to blocked module "
                                f"'{node.func.value.id}.{node.func.attr}'"
                            ),
                        )
                    )

                # Detect importlib.import_module('blocked_mod') bypass
                if (
                    node.func.value.id == "importlib"
                    and node.func.attr == "import_module"
                    and node.args
                ):
                    arg = node.args[0]
                    if isinstance(arg, ast.Constant) and isinstance(
                        arg.value, str
                    ):
                        top_level = arg.value.split(".")[0]
                        if top_level in self._blocked_modules:
                            self.violations.append(
                                SecurityViolation(
                                    line=node.lineno,
                                    column=node.col_offset,
                                    violation_type="blocked_import",
                                    description=(
                                        f"Dynamic import of blocked module "
                                        f"'{arg.value}' via importlib"
                                    ),
                                )
                            )

        self.generic_visit(node)


class ExecutionSandbox:
    """Restricted execution environment that prevents stdlib bypass.

    Uses import hooks and AST-based static analysis to enforce security
    policies on agent code execution.
    """

    def __init__(
        self,
        config: SandboxConfig | None = None,
        policy: Any = None,
    ) -> None:
        if config is None:
            warnings.warn(
                "ExecutionSandbox() uses built-in sample rules that may not "
                "cover all sandbox evasion techniques. For production use, load an "
                "explicit config with load_sandbox_config(). "
                "See examples/policies/sandbox-safety.yaml for a sample configuration.",
                stacklevel=2,
            )
        self.config = config or SandboxConfig()
        self.policy = policy
        self._hook = SandboxImportHook(self.config.blocked_modules)

    def check_import(self, module_name: str) -> bool:
        """Check if a module import is allowed.

        Args:
            module_name: The module name to check.

        Returns:
            True if the import is allowed, False if blocked.
        """
        top_level = module_name.split(".")[0]
        return top_level not in self.config.blocked_modules

    def check_builtin(self, name: str) -> bool:
        """Check if a builtin call is allowed.

        Args:
            name: The builtin name to check.

        Returns:
            True if the builtin is allowed, False if blocked.
        """
        return name not in self.config.blocked_builtins

    def check_file_access(self, path: str, mode: str = "r") -> bool:
        """Check if file access is allowed based on allowed_paths.

        Args:
            path: The file path to check.
            mode: The access mode (e.g., 'r', 'w').

        Returns:
            True if the access is allowed, False if blocked.
        """
        if not self.config.allowed_paths:
            return False

        # Resolve symlinks and '..' to prevent path traversal attacks
        try:
            resolved = pathlib.Path(path).resolve()
        except (OSError, ValueError):
            return False

        for allowed in self.config.allowed_paths:
            try:
                allowed_resolved = pathlib.Path(allowed).resolve()
            except (OSError, ValueError):
                continue
            # Use is_relative_to for safe containment check
            if resolved == allowed_resolved or resolved.is_relative_to(
                allowed_resolved
            ):
                return True
        return False

    def create_restricted_globals(
        self,
        user_globals: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a restricted globals dict that blocks dangerous builtins.

        Args:
            user_globals: Optional dict of user-provided globals to merge in.

        Returns:
            A globals dict with blocked builtins replaced by raising functions.
        """
        import builtins as _builtins

        safe_builtins = dict(vars(_builtins).items())

        for name in self.config.blocked_builtins:
            safe_builtins[name] = _make_blocked_builtin(name)

        restricted: dict[str, Any] = {"__builtins__": safe_builtins}

        if user_globals:
            for k, v in user_globals.items():
                if k != "__builtins__":
                    restricted[k] = v

        return restricted

    def validate_code(self, code: str) -> list[SecurityViolation]:
        """Validate code via AST static analysis for blocked calls.

        Args:
            code: Python source code to analyze.

        Returns:
            A list of SecurityViolation instances found in the code.
        """
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return [
                SecurityViolation(
                    line=0,
                    column=0,
                    violation_type="syntax_error",
                    description="Code contains syntax errors and cannot be analyzed",
                    severity="medium",
                )
            ]

        visitor = _ASTSecurityVisitor(
            blocked_modules=set(self.config.blocked_modules),
            blocked_builtins=set(self.config.blocked_builtins),
        )
        visitor.visit(tree)
        return visitor.violations

    def execute_sandboxed(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        """Run a function with import hooks that enforce the sandbox.

        Args:
            func: The function to execute.
            *args: Positional arguments passed to the function.
            **kwargs: Keyword arguments passed to the function.

        Returns:
            The return value of the function.
        """
        self._hook.install()
        try:
            return func(*args, **kwargs)
        finally:
            self._hook.uninstall()


def _make_blocked_builtin(name: str) -> Callable[..., None]:
    """Create a function that raises SecurityError when called."""

    def _blocked(*args: Any, **kwargs: Any) -> None:
        raise SecurityError(
            f"Builtin '{name}' is blocked by sandbox policy",
            error_code="BLOCKED_BUILTIN",
            details={"builtin": name},
        )

    _blocked.__name__ = f"blocked_{name}"
    return _blocked
