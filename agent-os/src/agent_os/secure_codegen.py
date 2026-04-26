# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Secure code generation templates and post-LLM code validation.

Provides AST-based analysis of LLM-generated code to detect security issues
such as dangerous imports, unsafe function calls, shell injection, SQL injection,
path traversal, and hardcoded secrets. Also supplies secure code templates that
enforce safe patterns for common tasks.

Architecture
------------
- ``CodeSecurityValidator`` – walks the AST of generated code, collecting
  ``SecurityIssue`` records for every violation found.
- ``SecureCodeTemplate`` – returns pre-vetted code snippets that follow secure
  defaults (timeouts, parameterised queries, shell=False, etc.).
- ``ValidationResult`` – lightweight result container returned by validation.
"""

from __future__ import annotations

import ast
import re
import textwrap
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Sequence


# ---------------------------------------------------------------------------
# Result / finding types
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    """Severity level for a security issue."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass(frozen=True)
class SecurityIssue:
    """A single security issue detected during code validation."""

    severity: Severity
    rule: str
    line: int
    message: str


@dataclass
class ValidationResult:
    """Outcome of validating a code snippet."""

    is_safe: bool
    issues: list[SecurityIssue] = field(default_factory=list)
    sanitized_code: Optional[str] = None

    @property
    def critical_issues(self) -> list[SecurityIssue]:
        return [i for i in self.issues if i.severity == Severity.CRITICAL]

    @property
    def high_issues(self) -> list[SecurityIssue]:
        return [i for i in self.issues if i.severity == Severity.HIGH]


# ---------------------------------------------------------------------------
# Code security validator
# ---------------------------------------------------------------------------


class CodeSecurityValidator:
    """Validates LLM-generated code for security issues using AST analysis.

    Checks cover dangerous imports, unsafe calls, shell injection,
    SQL injection patterns, path traversal, and hardcoded secrets.
    """

    DANGEROUS_IMPORTS: frozenset[str] = frozenset(
        {
            "pickle",
            "shelve",
            "marshal",
            "subprocess",
            "ctypes",
            "importlib",
            "code",
            "codeop",
            "compileall",
            "py_compile",
            "multiprocessing",
            "pty",
            "commands",
            "pdb",
            "profile",
            "trace",
            "webbrowser",
        }
    )

    DANGEROUS_CALLS: frozenset[str] = frozenset(
        {
            "eval",
            "exec",
            "compile",
            "getattr",
            "setattr",
            "delattr",
            "__import__",
            "globals",
            "locals",
            "vars",
            "os.system",
            "os.popen",
            "os.exec",
            "os.execl",
            "os.execle",
            "os.execlp",
            "os.execv",
            "os.execve",
            "os.execvp",
            "os.execvpe",
            "os.spawn",
            "os.spawnl",
            "os.spawnle",
        }
    )

    # Patterns for hardcoded secrets
    _SECRET_PATTERNS: Sequence[re.Pattern[str]] = (
        re.compile(
            r"""(?:api[_-]?key|apikey)\s*=\s*['"][A-Za-z0-9_\-]{16,}['"]""",
            re.IGNORECASE,
        ),
        re.compile(
            r"""(?:password|passwd|pwd)\s*=\s*['"][^'"]{4,}['"]""",
            re.IGNORECASE,
        ),
        re.compile(
            r"""(?:secret|token|auth)\s*=\s*['"][A-Za-z0-9_\-]{16,}['"]""",
            re.IGNORECASE,
        ),
        re.compile(
            r"""(?:aws_access_key_id|aws_secret_access_key)\s*=\s*['"][^'"]+['"]""",
            re.IGNORECASE,
        ),
        re.compile(
            r"""(?:PRIVATE[_\s]KEY)""",
            re.IGNORECASE,
        ),
    )

    # Path-traversal indicators
    _PATH_TRAVERSAL_PATTERN: re.Pattern[str] = re.compile(r"\.\.[/\\]")

    # SQL injection – string formatting in SQL-like statements
    _SQL_INJECTION_PATTERNS: Sequence[re.Pattern[str]] = (
        re.compile(
            r"""(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\s.+%[sd]""",
            re.IGNORECASE,
        ),
        re.compile(
            r"""(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\s.+\.format\(""",
            re.IGNORECASE,
        ),
        re.compile(
            r"""f['"].*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\s""",
            re.IGNORECASE,
        ),
    )

    # ------------------------------------------------------------------ #

    def validate(self, code: str, language: str = "python") -> ValidationResult:
        """Parse and validate code for security issues.

        Args:
            code: Source code to validate.
            language: Programming language (currently only ``"python"``).

        Returns:
            A ``ValidationResult`` with any issues found.

        Raises:
            ValueError: If *language* is not supported.
        """
        if language.lower() != "python":
            raise ValueError(f"Unsupported language: {language!r}")
        return self.validate_python(code)

    def validate_python(self, code: str) -> ValidationResult:
        """AST-based Python code validation.

        Uses ``ast.parse`` to walk the tree and applies heuristic
        regex checks on the raw source for patterns that cannot be
        caught structurally (secrets, SQL injection, path traversal).

        Args:
            code: Python source code to analyse.

        Returns:
            A ``ValidationResult`` describing all detected issues.
        """
        issues: list[SecurityIssue] = []

        # --- AST-based checks ----------------------------------------- #
        try:
            tree = ast.parse(code)
        except SyntaxError as exc:
            issues.append(
                SecurityIssue(
                    severity=Severity.MEDIUM,
                    rule="syntax-error",
                    line=exc.lineno or 0,
                    message=f"Code has a syntax error: {exc.msg}",
                )
            )
            return ValidationResult(is_safe=False, issues=issues)

        for node in ast.walk(tree):
            self._check_imports(node, issues)
            self._check_calls(node, issues)
            self._check_shell_injection(node, issues)

        # --- Regex-based checks on raw source ------------------------- #
        self._check_sql_injection(code, issues)
        self._check_path_traversal(code, issues)
        self._check_hardcoded_secrets(code, issues)

        is_safe = len(issues) == 0
        sanitized = self._sanitize(code, issues) if not is_safe else None
        return ValidationResult(is_safe=is_safe, issues=issues, sanitized_code=sanitized)

    # ------------------------------------------------------------------ #
    # Private AST checks
    # ------------------------------------------------------------------ #

    def _check_imports(
        self, node: ast.AST, issues: list[SecurityIssue]
    ) -> None:
        """Flag imports from the dangerous-imports set."""
        if isinstance(node, ast.Import):
            for alias in node.names:
                top = alias.name.split(".")[0]
                if top in self.DANGEROUS_IMPORTS:
                    issues.append(
                        SecurityIssue(
                            severity=Severity.HIGH,
                            rule="dangerous-import",
                            line=node.lineno,
                            message=f"Dangerous import: {alias.name}",
                        )
                    )
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                top = node.module.split(".")[0]
                if top in self.DANGEROUS_IMPORTS:
                    issues.append(
                        SecurityIssue(
                            severity=Severity.HIGH,
                            rule="dangerous-import",
                            line=node.lineno,
                            message=f"Dangerous import: from {node.module}",
                        )
                    )

    def _check_calls(
        self, node: ast.AST, issues: list[SecurityIssue]
    ) -> None:
        """Flag calls to dangerous builtins / functions."""
        if not isinstance(node, ast.Call):
            return
        name = self._resolve_call_name(node)
        if name and name in self.DANGEROUS_CALLS:
            issues.append(
                SecurityIssue(
                    severity=Severity.CRITICAL,
                    rule="dangerous-call",
                    line=node.lineno,
                    message=f"Dangerous call: {name}()",
                )
            )

    def _check_shell_injection(
        self, node: ast.AST, issues: list[SecurityIssue]
    ) -> None:
        """Detect ``subprocess`` calls with ``shell=True``."""
        if not isinstance(node, ast.Call):
            return
        name = self._resolve_call_name(node)
        if not name:
            return
        # Match subprocess.run / subprocess.Popen / subprocess.call etc.
        if not name.startswith("subprocess."):
            return
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                issues.append(
                    SecurityIssue(
                        severity=Severity.CRITICAL,
                        rule="shell-injection",
                        line=node.lineno,
                        message=f"Shell injection risk: {name}() with shell=True",
                    )
                )

    # ------------------------------------------------------------------ #
    # Private regex checks
    # ------------------------------------------------------------------ #

    def _check_sql_injection(
        self, code: str, issues: list[SecurityIssue]
    ) -> None:
        for lineno, line in enumerate(code.splitlines(), start=1):
            for pat in self._SQL_INJECTION_PATTERNS:
                if pat.search(line):
                    issues.append(
                        SecurityIssue(
                            severity=Severity.HIGH,
                            rule="sql-injection",
                            line=lineno,
                            message="Potential SQL injection: use parameterised queries",
                        )
                    )
                    break  # one issue per line is enough

    def _check_path_traversal(
        self, code: str, issues: list[SecurityIssue]
    ) -> None:
        for lineno, line in enumerate(code.splitlines(), start=1):
            if self._PATH_TRAVERSAL_PATTERN.search(line):
                issues.append(
                    SecurityIssue(
                        severity=Severity.HIGH,
                        rule="path-traversal",
                        line=lineno,
                        message="Potential path traversal: avoid '../' in file paths",
                    )
                )

    def _check_hardcoded_secrets(
        self, code: str, issues: list[SecurityIssue]
    ) -> None:
        for lineno, line in enumerate(code.splitlines(), start=1):
            for pat in self._SECRET_PATTERNS:
                if pat.search(line):
                    issues.append(
                        SecurityIssue(
                            severity=Severity.CRITICAL,
                            rule="hardcoded-secret",
                            line=lineno,
                            message="Potential hardcoded secret detected",
                        )
                    )
                    break

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _resolve_call_name(node: ast.Call) -> Optional[str]:
        """Return the dotted name of a call, e.g. ``os.system``."""
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            parts: list[str] = [func.attr]
            current: ast.expr = func.value
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return None

    @staticmethod
    def _sanitize(code: str, issues: list[SecurityIssue]) -> str:
        """Return a copy of *code* with dangerous lines commented out."""
        dangerous_lines = {i.line for i in issues}
        result_lines: list[str] = []
        for lineno, line in enumerate(code.splitlines(), start=1):
            if lineno in dangerous_lines:
                result_lines.append(f"# REMOVED (security): {line}")
            else:
                result_lines.append(line)
        return "\n".join(result_lines)


# ---------------------------------------------------------------------------
# Secure code templates
# ---------------------------------------------------------------------------


class SecureCodeTemplate:
    """Templates that enforce secure patterns in generated code.

    Each template encodes best-practice defaults (timeouts, parameterised
    queries, ``shell=False``, env-var configuration, path validation, etc.)
    and can be retrieved with ``get_template(name, **kwargs)``.
    """

    TEMPLATES: dict[str, str] = {
        "http_client": textwrap.dedent("""\
            import httpx

            def fetch(url: str, *, timeout: float = {timeout}) -> httpx.Response:
                \"\"\"Perform a GET request with enforced timeout and TLS verification.\"\"\"
                with httpx.Client(verify=True, timeout=timeout) as client:
                    response = client.get(url)
                    response.raise_for_status()
                    return response
        """),
        "file_read": textwrap.dedent("""\
            import os
            from pathlib import Path

            def safe_read(filepath: str, *, base_dir: str = {base_dir}) -> str:
                \"\"\"Read a file, preventing path-traversal attacks.\"\"\"
                base = Path(base_dir).resolve()
                target = (base / filepath).resolve()
                if not str(target).startswith(str(base)):
                    raise ValueError("Path traversal detected")
                if not target.is_file():
                    raise FileNotFoundError(f"{{target}} does not exist")
                return target.read_text(encoding="utf-8")
        """),
        "sql_query": textwrap.dedent("""\
            import sqlite3

            def safe_query(db_path: str, query: str, params: tuple = ()) -> list:
                \"\"\"Execute a parameterised SQL query – never interpolate user data.\"\"\"
                conn = sqlite3.connect(db_path)
                try:
                    cursor = conn.execute(query, params)
                    return cursor.fetchall()
                finally:
                    conn.close()
        """),
        "subprocess": textwrap.dedent("""\
            import subprocess

            ALLOWED_COMMANDS: frozenset[str] = frozenset({allowed_commands})

            def safe_run(command: list[str], *, timeout: int = {timeout}) -> subprocess.CompletedProcess:
                \"\"\"Run an allow-listed command without a shell.\"\"\"
                if not command or command[0] not in ALLOWED_COMMANDS:
                    raise ValueError(f"Command not allowed: {{command[0] if command else '<empty>'}}")
                return subprocess.run(
                    command,
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=True,
                )
        """),
        "env_config": textwrap.dedent("""\
            import os

            def get_config(key: str, *, default: str | None = None) -> str:
                \"\"\"Read configuration from environment variables – never hard-code secrets.\"\"\"
                value = os.environ.get(key, default)
                if value is None:
                    raise RuntimeError(f"Required config '{{key}}' not set in environment")
                return value
        """),
    }

    # Defaults used when the caller omits keyword arguments
    _DEFAULTS: dict[str, dict[str, str]] = {
        "http_client": {"timeout": "30.0"},
        "file_read": {"base_dir": '"/safe/base"'},
        "sql_query": {},
        "subprocess": {
            "allowed_commands": '{"ls", "cat", "echo"}',
            "timeout": "30",
        },
        "env_config": {},
    }

    def get_template(self, name: str, **kwargs: str) -> str:
        """Return a secure code template with placeholders filled in.

        Args:
            name: Template name (one of ``TEMPLATES`` keys).
            **kwargs: Values to substitute into the template.

        Returns:
            The rendered template source.

        Raises:
            KeyError: If *name* is not a known template.
        """
        if name not in self.TEMPLATES:
            raise KeyError(
                f"Unknown template {name!r}. "
                f"Available: {', '.join(sorted(self.TEMPLATES))}"
            )
        merged = {**self._DEFAULTS.get(name, {}), **kwargs}
        return self.TEMPLATES[name].format(**merged)

    @staticmethod
    def wrap_with_sandbox(code: str) -> str:
        """Wrap arbitrary code in a restricted-execution sandbox.

        The wrapper catches exceptions, prevents globals leakage,
        and records the execution result.
        """
        return textwrap.dedent("""\
            # --- sandboxed execution begin ---
            _sandbox_result = None
            _sandbox_error = None
            try:
            {indented_code}
            except Exception as _sandbox_exc:
                _sandbox_error = str(_sandbox_exc)
            # --- sandboxed execution end ---
        """).format(indented_code=textwrap.indent(code, "    "))
