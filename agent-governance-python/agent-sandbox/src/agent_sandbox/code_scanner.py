# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Static pre-execution scanner for sandboxed Python code.

This is an intentionally lightweight guardrail. It catches obvious
process-spawning APIs before code reaches a sandbox provider; it does not
replace runtime process monitoring, seccomp, or eBPF tracing.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

_DANGEROUS_CALLS: dict[str, set[str]] = {
    "subprocess": {
        "Popen",
        "call",
        "check_call",
        "check_output",
        "getoutput",
        "getstatusoutput",
        "run",
    },
    "os": {
        "execl",
        "execle",
        "execlp",
        "execlpe",
        "execv",
        "execve",
        "execvp",
        "execvpe",
        "popen",
        "spawnl",
        "spawnle",
        "spawnlp",
        "spawnlpe",
        "spawnv",
        "spawnve",
        "spawnvp",
        "spawnvpe",
        "system",
    },
    "pty": {"spawn"},
    "shutil": {"which"},
}


@dataclass(frozen=True)
class CodeScanViolation:
    """A static finding that should block sandbox execution."""

    line: int
    column: int
    pattern: str
    message: str


class SandboxCodeViolation(PermissionError):
    """Raised when static scanning finds a denied subprocess pattern."""

    def __init__(self, violations: list[CodeScanViolation]) -> None:
        self.violations = tuple(violations)
        detail = "; ".join(
            f"line {v.line}:{v.column + 1} {v.pattern}" for v in self.violations[:3]
        )
        suffix = "" if len(self.violations) <= 3 else f"; +{len(self.violations) - 3} more"
        super().__init__(f"Sandbox code denied: potential subprocess execution ({detail}{suffix})")


def scan_code_for_subprocesses(code: str) -> list[CodeScanViolation]:
    """Return obvious subprocess/process-spawning patterns in Python source."""

    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []

    visitor = _SubprocessScanVisitor()
    visitor.visit(tree)
    return visitor.violations


def enforce_no_subprocess_execution(code: str) -> None:
    """Raise when *code* contains denied subprocess execution patterns."""

    violations = scan_code_for_subprocesses(code)
    if violations:
        raise SandboxCodeViolation(violations)


class _SubprocessScanVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self._module_aliases: dict[str, str] = {}
        self._call_aliases: dict[str, tuple[str, str]] = {}
        self.violations: list[CodeScanViolation] = []

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for alias in node.names:
            root_module = alias.name.split(".", 1)[0]
            if root_module in _DANGEROUS_CALLS:
                local_name = alias.asname or root_module
                self._module_aliases[local_name] = root_module
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        if node.module is None:
            return
        root_module = node.module.split(".", 1)[0]
        dangerous = _DANGEROUS_CALLS.get(root_module)
        if not dangerous:
            return

        for alias in node.names:
            if alias.name == "*":
                self._add_violation(
                    node,
                    f"{root_module}.*",
                    f"Wildcard import from {root_module} can expose process-spawning APIs",
                )
                continue
            if alias.name in dangerous:
                local_name = alias.asname or alias.name
                self._call_aliases[local_name] = (root_module, alias.name)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        pattern = self._resolve_call_pattern(node.func)
        if pattern is not None:
            self._add_violation(
                node,
                pattern,
                f"{pattern} may spawn or discover subprocesses inside the sandbox",
            )
        self.generic_visit(node)

    def _resolve_call_pattern(self, func: ast.expr) -> str | None:
        if isinstance(func, ast.Name):
            resolved = self._call_aliases.get(func.id)
            if resolved is None:
                return None
            module, attr = resolved
            return f"{module}.{attr}"

        if not isinstance(func, ast.Attribute):
            return None

        module = self._resolve_module_name(func.value)
        if module is None:
            return None

        dangerous = _DANGEROUS_CALLS.get(module)
        if dangerous and func.attr in dangerous:
            return f"{module}.{func.attr}"
        return None

    def _resolve_module_name(self, node: ast.expr) -> str | None:
        if isinstance(node, ast.Name):
            return self._module_aliases.get(node.id, node.id)
        if isinstance(node, ast.Call):
            return self._resolve_dynamic_import(node)
        return None

    def _resolve_dynamic_import(self, node: ast.Call) -> str | None:
        if isinstance(node.func, ast.Name) and node.func.id == "__import__" and node.args:
            return self._constant_module_name(node.args[0])

        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "import_module"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "importlib"
            and node.args
        ):
            return self._constant_module_name(node.args[0])

        return None

    def _constant_module_name(self, node: ast.expr) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value.split(".", 1)[0]
        return None

    def _add_violation(self, node: ast.AST, pattern: str, message: str) -> None:
        self.violations.append(
            CodeScanViolation(
                line=getattr(node, "lineno", 1),
                column=getattr(node, "col_offset", 0),
                pattern=pattern,
                message=message,
            )
        )
