# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Tests for secure_codegen – code security validation and templates."""

from __future__ import annotations

import textwrap

import pytest

from agent_os.secure_codegen import (
    CodeSecurityValidator,
    SecureCodeTemplate,
    SecurityIssue,
    Severity,
    ValidationResult,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _issues_with_rule(
    result: ValidationResult, rule: str
) -> list[SecurityIssue]:
    """Return issues matching a given rule id."""
    return [i for i in result.issues if i.rule == rule]


# ---------------------------------------------------------------------------
# ValidationResult
# ---------------------------------------------------------------------------


class TestValidationResult:
    def test_safe_result(self) -> None:
        r = ValidationResult(is_safe=True)
        assert r.is_safe is True
        assert r.issues == []
        assert r.sanitized_code is None

    def test_critical_and_high_properties(self) -> None:
        issues = [
            SecurityIssue(Severity.CRITICAL, "a", 1, "crit"),
            SecurityIssue(Severity.HIGH, "b", 2, "high"),
            SecurityIssue(Severity.LOW, "c", 3, "low"),
        ]
        r = ValidationResult(is_safe=False, issues=issues)
        assert len(r.critical_issues) == 1
        assert len(r.high_issues) == 1

    def test_security_issue_frozen(self) -> None:
        issue = SecurityIssue(Severity.HIGH, "r", 1, "msg")
        with pytest.raises(AttributeError):
            issue.rule = "other"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Dangerous imports
# ---------------------------------------------------------------------------


class TestDangerousImports:
    def test_import_pickle(self) -> None:
        code = "import pickle\ndata = pickle.loads(b'')"
        result = CodeSecurityValidator().validate(code)
        assert not result.is_safe
        assert any(i.rule == "dangerous-import" and "pickle" in i.message for i in result.issues)

    def test_import_subprocess(self) -> None:
        code = "import subprocess"
        result = CodeSecurityValidator().validate(code)
        assert not result.is_safe
        assert any("subprocess" in i.message for i in result.issues)

    def test_from_import_ctypes(self) -> None:
        code = "from ctypes import cdll"
        result = CodeSecurityValidator().validate(code)
        assert not result.is_safe
        assert any("ctypes" in i.message for i in result.issues)

    def test_from_import_importlib(self) -> None:
        code = "from importlib import import_module"
        result = CodeSecurityValidator().validate(code)
        assert not result.is_safe
        assert any("importlib" in i.message for i in result.issues)

    def test_safe_imports_pass(self) -> None:
        code = textwrap.dedent("""\
            import os
            import json
            from pathlib import Path
        """)
        result = CodeSecurityValidator().validate(code)
        dangerous_import_issues = _issues_with_rule(result, "dangerous-import")
        assert len(dangerous_import_issues) == 0


# ---------------------------------------------------------------------------
# Dangerous calls (eval / exec / etc.)
# ---------------------------------------------------------------------------


class TestDangerousCalls:
    def test_eval_flagged(self) -> None:
        code = "result = eval(user_input)"
        result = CodeSecurityValidator().validate(code)
        assert not result.is_safe
        found = _issues_with_rule(result, "dangerous-call")
        assert any("eval" in i.message for i in found)

    def test_exec_flagged(self) -> None:
        code = "exec(some_code)"
        result = CodeSecurityValidator().validate(code)
        assert not result.is_safe
        found = _issues_with_rule(result, "dangerous-call")
        assert any("exec" in i.message for i in found)

    def test_compile_flagged(self) -> None:
        code = "compile('print(1)', '<string>', 'exec')"
        result = CodeSecurityValidator().validate(code)
        assert not result.is_safe

    def test_os_system_flagged(self) -> None:
        code = "import os\nos.system('rm -rf /')"
        result = CodeSecurityValidator().validate(code)
        found = _issues_with_rule(result, "dangerous-call")
        assert any("os.system" in i.message for i in found)

    def test_getattr_flagged(self) -> None:
        code = "getattr(obj, attr)"
        result = CodeSecurityValidator().validate(code)
        assert not result.is_safe

    def test_dunder_import_flagged(self) -> None:
        code = "__import__('os')"
        result = CodeSecurityValidator().validate(code)
        assert not result.is_safe

    def test_safe_calls_pass(self) -> None:
        code = textwrap.dedent("""\
            x = len([1, 2, 3])
            y = str(42)
            z = int("10")
        """)
        result = CodeSecurityValidator().validate(code)
        assert result.is_safe


# ---------------------------------------------------------------------------
# Safe code passes
# ---------------------------------------------------------------------------


class TestSafeCode:
    def test_simple_function(self) -> None:
        code = textwrap.dedent("""\
            def add(a: int, b: int) -> int:
                return a + b
        """)
        result = CodeSecurityValidator().validate(code)
        assert result.is_safe
        assert result.issues == []
        assert result.sanitized_code is None

    def test_class_definition(self) -> None:
        code = textwrap.dedent("""\
            class Greeter:
                def __init__(self, name: str) -> None:
                    self.name = name

                def greet(self) -> str:
                    return f"Hello, {self.name}!"
        """)
        result = CodeSecurityValidator().validate(code)
        assert result.is_safe

    def test_stdlib_usage(self) -> None:
        code = textwrap.dedent("""\
            import json
            import os
            from pathlib import Path

            data = json.loads('{"key": "value"}')
            home = Path.home()
        """)
        result = CodeSecurityValidator().validate(code)
        assert result.is_safe


# ---------------------------------------------------------------------------
# Shell injection detection
# ---------------------------------------------------------------------------


class TestShellInjection:
    def test_subprocess_shell_true(self) -> None:
        code = textwrap.dedent("""\
            import subprocess
            subprocess.run(cmd, shell=True)
        """)
        result = CodeSecurityValidator().validate(code)
        shell_issues = _issues_with_rule(result, "shell-injection")
        assert len(shell_issues) >= 1
        assert shell_issues[0].severity == Severity.CRITICAL

    def test_subprocess_popen_shell_true(self) -> None:
        code = textwrap.dedent("""\
            import subprocess
            p = subprocess.Popen(cmd, shell=True)
        """)
        result = CodeSecurityValidator().validate(code)
        shell_issues = _issues_with_rule(result, "shell-injection")
        assert len(shell_issues) >= 1

    def test_subprocess_shell_false_ok(self) -> None:
        code = textwrap.dedent("""\
            import subprocess
            subprocess.run(["ls", "-la"], shell=False)
        """)
        result = CodeSecurityValidator().validate(code)
        shell_issues = _issues_with_rule(result, "shell-injection")
        assert len(shell_issues) == 0


# ---------------------------------------------------------------------------
# SQL injection detection
# ---------------------------------------------------------------------------


class TestSQLInjection:
    def test_percent_format_in_query(self) -> None:
        code = 'query = "SELECT * FROM users WHERE id = %s" % user_id'
        result = CodeSecurityValidator().validate(code)
        sql_issues = _issues_with_rule(result, "sql-injection")
        assert len(sql_issues) >= 1

    def test_format_call_in_query(self) -> None:
        code = 'query = "SELECT * FROM users WHERE name = {}".format(name)'
        result = CodeSecurityValidator().validate(code)
        sql_issues = _issues_with_rule(result, "sql-injection")
        assert len(sql_issues) >= 1

    def test_fstring_sql(self) -> None:
        code = 'query = f"DELETE FROM orders WHERE id = {order_id}"'
        result = CodeSecurityValidator().validate(code)
        sql_issues = _issues_with_rule(result, "sql-injection")
        assert len(sql_issues) >= 1

    def test_parameterised_query_ok(self) -> None:
        code = textwrap.dedent("""\
            cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        """)
        result = CodeSecurityValidator().validate(code)
        sql_issues = _issues_with_rule(result, "sql-injection")
        assert len(sql_issues) == 0


# ---------------------------------------------------------------------------
# Path traversal detection
# ---------------------------------------------------------------------------


class TestPathTraversal:
    def test_dot_dot_slash(self) -> None:
        code = 'path = "../../etc/passwd"'
        result = CodeSecurityValidator().validate(code)
        pt_issues = _issues_with_rule(result, "path-traversal")
        assert len(pt_issues) >= 1

    def test_dot_dot_backslash(self) -> None:
        code = r'path = "..\\..\\windows\\system32"'
        result = CodeSecurityValidator().validate(code)
        pt_issues = _issues_with_rule(result, "path-traversal")
        assert len(pt_issues) >= 1

    def test_safe_relative_path(self) -> None:
        code = 'path = "data/config.json"'
        result = CodeSecurityValidator().validate(code)
        pt_issues = _issues_with_rule(result, "path-traversal")
        assert len(pt_issues) == 0


# ---------------------------------------------------------------------------
# Hardcoded secrets detection
# ---------------------------------------------------------------------------


class TestHardcodedSecrets:
    def test_api_key_detected(self) -> None:
        code = 'api_key = "sk_live_abc123def456ghi789"'
        result = CodeSecurityValidator().validate(code)
        sec_issues = _issues_with_rule(result, "hardcoded-secret")
        assert len(sec_issues) >= 1
        assert sec_issues[0].severity == Severity.CRITICAL

    def test_password_detected(self) -> None:
        code = 'password = "SuperS3cret!"'
        result = CodeSecurityValidator().validate(code)
        sec_issues = _issues_with_rule(result, "hardcoded-secret")
        assert len(sec_issues) >= 1

    def test_env_var_lookup_ok(self) -> None:
        code = 'api_key = os.environ["API_KEY"]'
        result = CodeSecurityValidator().validate(code)
        sec_issues = _issues_with_rule(result, "hardcoded-secret")
        assert len(sec_issues) == 0


# ---------------------------------------------------------------------------
# Sanitisation
# ---------------------------------------------------------------------------


class TestSanitization:
    def test_dangerous_lines_commented_out(self) -> None:
        code = "safe = 1\nresult = eval(x)\nsafe2 = 2"
        result = CodeSecurityValidator().validate(code)
        assert result.sanitized_code is not None
        lines = result.sanitized_code.splitlines()
        assert lines[0] == "safe = 1"
        assert lines[1].startswith("# REMOVED (security):")
        assert lines[2] == "safe2 = 2"


# ---------------------------------------------------------------------------
# Syntax errors
# ---------------------------------------------------------------------------


class TestSyntaxError:
    def test_syntax_error_flagged(self) -> None:
        code = "def broken(:\n    pass"
        result = CodeSecurityValidator().validate(code)
        assert not result.is_safe
        assert any(i.rule == "syntax-error" for i in result.issues)


# ---------------------------------------------------------------------------
# Unsupported language
# ---------------------------------------------------------------------------


class TestUnsupportedLanguage:
    def test_unsupported_language_raises(self) -> None:
        with pytest.raises(ValueError, match="Unsupported language"):
            CodeSecurityValidator().validate("code", language="javascript")


# ---------------------------------------------------------------------------
# Secure code templates
# ---------------------------------------------------------------------------


class TestSecureCodeTemplate:
    def test_http_client_template(self) -> None:
        tmpl = SecureCodeTemplate()
        code = tmpl.get_template("http_client")
        assert "verify=True" in code
        assert "timeout" in code
        # Template code itself should be safe
        result = CodeSecurityValidator().validate(code)
        dangerous_imports = _issues_with_rule(result, "dangerous-import")
        assert len(dangerous_imports) == 0

    def test_file_read_template(self) -> None:
        tmpl = SecureCodeTemplate()
        code = tmpl.get_template("file_read")
        assert "resolve()" in code
        assert "startswith" in code

    def test_sql_query_template(self) -> None:
        tmpl = SecureCodeTemplate()
        code = tmpl.get_template("sql_query")
        # Must use parameterised queries
        assert "params" in code
        assert "execute(query, params)" in code
        # Must not trigger SQL injection
        result = CodeSecurityValidator().validate(code)
        sql_issues = _issues_with_rule(result, "sql-injection")
        assert len(sql_issues) == 0

    def test_subprocess_template(self) -> None:
        tmpl = SecureCodeTemplate()
        code = tmpl.get_template("subprocess")
        assert "shell=False" in code
        assert "ALLOWED_COMMANDS" in code

    def test_env_config_template(self) -> None:
        tmpl = SecureCodeTemplate()
        code = tmpl.get_template("env_config")
        assert "os.environ" in code

    def test_custom_kwargs(self) -> None:
        tmpl = SecureCodeTemplate()
        code = tmpl.get_template("http_client", timeout="10.0")
        assert "10.0" in code
        # Default was overridden
        assert "30.0" not in code

    def test_unknown_template_raises(self) -> None:
        tmpl = SecureCodeTemplate()
        with pytest.raises(KeyError, match="Unknown template"):
            tmpl.get_template("nonexistent")

    def test_wrap_with_sandbox(self) -> None:
        inner = "x = 1\ny = 2"
        wrapped = SecureCodeTemplate.wrap_with_sandbox(inner)
        assert "_sandbox_result" in wrapped
        assert "_sandbox_error" in wrapped
        assert "    x = 1" in wrapped
        assert "except Exception" in wrapped
