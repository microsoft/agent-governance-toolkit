# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Local-first code policy checker for the Agent OS CLI.

Defines ``PolicyViolation``, ``PolicyChecker``, and the helper
``load_cli_policy_rules()`` used by the ``agentos check`` and
``agentos review`` commands.
"""

from __future__ import annotations

import os
import re
import subprocess
import warnings
from pathlib import Path
from typing import Any


# ============================================================================
# PolicyViolation
# ============================================================================


class PolicyViolation:
    """Represents a policy violation found in code."""

    def __init__(self, line: int, code: str, violation: str, policy: str,
                 severity: str = 'high', suggestion: str | None = None) -> None:
        self.line = line
        self.code = code
        self.violation = violation
        self.policy = policy
        self.severity = severity
        self.suggestion = suggestion

    def to_dict(self) -> dict[str, Any]:
        """Convert violation to dictionary for JSON output."""
        return {
            "line": self.line,
            "code": self.code,
            "violation": self.violation,
            "policy": self.policy,
            "severity": self.severity,
            "suggestion": self.suggestion
        }


# ============================================================================
# Rule Loading
# ============================================================================


def load_cli_policy_rules(path: str) -> list[dict[str, Any]]:
    """Load CLI policy checker rules from a YAML file.

    Args:
        path: Path to a YAML file with a ``rules`` section.

    Returns:
        List of rule dicts suitable for ``PolicyChecker``.

    Raises:
        FileNotFoundError: If the config file does not exist.
        ValueError: If the YAML is missing the ``rules`` section.
    """
    import yaml

    if not os.path.exists(path):
        raise FileNotFoundError(f"CLI policy rules config not found: {path}")

    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh.read())

    if not isinstance(data, dict) or "rules" not in data:
        raise ValueError(f"YAML file must contain a 'rules' section: {path}")

    return data["rules"]


# ============================================================================
# PolicyChecker
# ============================================================================


class PolicyChecker:
    """Local-first code policy checker."""

    def __init__(self, rules: list[dict[str, Any]] | None = None) -> None:
        if rules is not None:
            self.rules = rules
        else:
            self.rules = self._load_default_rules()

    def _load_default_rules(self) -> list[dict[str, Any]]:
        """Load default safety rules.

        .. deprecated::
            Uses built-in sample rules. For production use, load an explicit
            config with ``load_cli_policy_rules()``.
        """
        warnings.warn(
            "PolicyChecker._load_default_rules() uses built-in sample rules that may not "
            "cover all security violations. For production use, load an "
            "explicit config with load_cli_policy_rules(). "
            "See examples/policies/cli-security-rules.yaml for a sample configuration.",
            stacklevel=2,
        )
        return [
            # Destructive SQL
            {
                'name': 'block-destructive-sql',
                'pattern': r'\bDROP\s+(TABLE|DATABASE|SCHEMA|INDEX)\s+',
                'message': 'Destructive SQL: DROP operation detected',
                'severity': 'critical',
                'suggestion': '-- Consider using soft delete or archiving instead',
                'languages': ['sql', 'python', 'javascript', 'typescript', 'php', 'ruby', 'java']
            },
            {
                'name': 'block-destructive-sql',
                'pattern': r'\bDELETE\s+FROM\s+\w+\s*(;|$|WHERE\s+1\s*=\s*1)',
                'message': 'Destructive SQL: DELETE without proper WHERE clause',
                'severity': 'critical',
                'suggestion': '-- Add a specific WHERE clause to limit deletion',
                'languages': ['sql', 'python', 'javascript', 'typescript', 'php', 'ruby', 'java']
            },
            {
                'name': 'block-destructive-sql',
                'pattern': r'\bTRUNCATE\s+TABLE\s+',
                'message': 'Destructive SQL: TRUNCATE operation detected',
                'severity': 'critical',
                'suggestion': '-- Consider archiving data before truncating',
                'languages': ['sql', 'python', 'javascript', 'typescript', 'php', 'ruby', 'java']
            },
            # File deletion
            {
                'name': 'block-file-deletes',
                'pattern': r'\brm\s+(-rf|-fr|--recursive\s+--force)\s+',
                'message': 'Destructive operation: Recursive force delete (rm -rf)',
                'severity': 'critical',
                'suggestion': '# Use safer alternatives like trash-cli or move to backup',
                'languages': ['bash', 'shell', 'sh', 'zsh']
            },
            {
                'name': 'block-file-deletes',
                'pattern': r'\bshutil\s*\.\s*rmtree\s*\(',
                'message': 'Recursive directory deletion (shutil.rmtree)',
                'severity': 'high',
                'suggestion': '# Consider using send2trash for safer deletion',
                'languages': ['python']
            },
            {
                'name': 'block-file-deletes',
                'pattern': r'\bos\s*\.\s*(remove|unlink|rmdir)\s*\(',
                'message': 'File/directory deletion operation detected',
                'severity': 'medium',
                'languages': ['python']
            },
            # Secret exposure
            {
                'name': 'block-secret-exposure',
                'pattern': r'(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*["\'][a-zA-Z0-9_-]{20,}["\']',
                'message': 'Hardcoded API key detected',
                'severity': 'critical',
                'suggestion': '# Use environment variables: os.environ["API_KEY"]',
                'languages': None  # All languages
            },
            {
                'name': 'block-secret-exposure',
                'pattern': r'(password|passwd|pwd)\s*[=:]\s*["\'][^"\']+["\']',
                'message': 'Hardcoded password detected',
                'severity': 'critical',
                'suggestion': '# Use environment variables or a secrets manager',
                'languages': None
            },
            {
                'name': 'block-secret-exposure',
                'pattern': r'AKIA[0-9A-Z]{16}',
                'message': 'AWS Access Key ID detected in code',
                'severity': 'critical',
                'languages': None
            },
            {
                'name': 'block-secret-exposure',
                'pattern': r'-----BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----',
                'message': 'Private key detected in code',
                'severity': 'critical',
                'languages': None
            },
            {
                'name': 'block-secret-exposure',
                'pattern': r'gh[pousr]_[A-Za-z0-9_]{36,}',
                'message': 'GitHub token detected in code',
                'severity': 'critical',
                'languages': None
            },
            # Privilege escalation
            {
                'name': 'block-privilege-escalation',
                'pattern': r'\bsudo\s+',
                'message': 'Privilege escalation: sudo command detected',
                'severity': 'high',
                'suggestion': '# Avoid sudo in scripts - run with appropriate permissions',
                'languages': ['bash', 'shell', 'sh', 'zsh']
            },
            {
                'name': 'block-privilege-escalation',
                'pattern': r'\bchmod\s+777\s+',
                'message': 'Insecure permissions: chmod 777 detected',
                'severity': 'high',
                'suggestion': '# Use more restrictive permissions: chmod 755 or chmod 644',
                'languages': ['bash', 'shell', 'sh', 'zsh']
            },
            # Code injection
            {
                'name': 'block-arbitrary-exec',
                'pattern': r'\beval\s*\(',
                'message': 'Code injection risk: eval() usage detected',
                'severity': 'high',
                'suggestion': '# Remove eval() and use safer alternatives',
                'languages': ['python', 'javascript', 'typescript', 'php', 'ruby']
            },
            {
                'name': 'block-arbitrary-exec',
                'pattern': r'\bos\s*\.\s*system\s*\([^)]*(\+|%|\.format|f["\'])',
                'message': 'Command injection risk: os.system with dynamic input',
                'severity': 'critical',
                'suggestion': '# Use subprocess with shell=False and proper argument handling',
                'languages': ['python']
            },
            {
                'name': 'block-arbitrary-exec',
                'pattern': r'\bexec\s*\(',
                'message': 'Code injection risk: exec() usage detected',
                'severity': 'high',
                'suggestion': '# Remove exec() and use safer alternatives',
                'languages': ['python']
            },
            # SQL injection
            {
                'name': 'block-sql-injection',
                'pattern': r'["\']\s*\+\s*[^"\']+\s*\+\s*["\'].*(?:SELECT|INSERT|UPDATE|DELETE)',
                'message': 'SQL injection risk: String concatenation in SQL query',
                'severity': 'high',
                'suggestion': '# Use parameterized queries instead',
                'languages': ['python', 'javascript', 'typescript', 'php', 'ruby', 'java']
            },
            # XSS
            {
                'name': 'block-xss',
                'pattern': r'\.innerHTML\s*=',
                'message': 'XSS risk: innerHTML assignment detected',
                'severity': 'medium',
                'suggestion': '// Use textContent or a sanitization library',
                'languages': ['javascript', 'typescript']
            },
        ]

    def _get_language(self, filepath: str) -> str:
        """Detect language from file extension."""
        ext_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.jsx': 'javascript',
            '.tsx': 'typescript',
            '.sql': 'sql',
            '.sh': 'shell',
            '.bash': 'bash',
            '.zsh': 'zsh',
            '.php': 'php',
            '.rb': 'ruby',
            '.java': 'java',
            '.cs': 'csharp',
            '.go': 'go',
        }
        ext = Path(filepath).suffix.lower()
        return ext_map.get(ext, 'unknown')

    def check_file(self, filepath: str) -> list[PolicyViolation]:
        """Check a file for policy violations."""
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"File not found: {filepath}")

        language = self._get_language(filepath)
        content = path.read_text(encoding='utf-8', errors='ignore')
        lines = content.split('\n')

        violations = []

        for rule in self.rules:
            # Check language filter
            if rule['languages'] and language not in rule['languages']:
                continue

            pattern = re.compile(rule['pattern'], re.IGNORECASE)

            for i, line in enumerate(lines, 1):
                if pattern.search(line):
                    violations.append(PolicyViolation(
                        line=i,
                        code=line.strip(),
                        violation=rule['message'],
                        policy=rule['name'],
                        severity=rule['severity'],
                        suggestion=rule.get('suggestion')
                    ))

        return violations

    def check_staged_files(self) -> dict[str, list[PolicyViolation]]:
        """Check all staged git files for violations."""
        try:
            result = subprocess.run(
                ['git', 'diff', '--cached', '--name-only'],
                capture_output=True, text=True, check=True
            )
            files = [f for f in result.stdout.strip().split('\n') if f]
        except subprocess.CalledProcessError:
            return {}

        all_violations = {}
        for filepath in files:
            if Path(filepath).exists():
                violations = self.check_file(filepath)
                if violations:
                    all_violations[filepath] = violations

        return all_violations
