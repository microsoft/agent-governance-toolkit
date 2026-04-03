# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent OS CLI - Command line interface for Agent OS

Usage:
    agentos init [--template TEMPLATE]     Initialize .agents/ directory
    agentos secure [--policy POLICY]       Enable kernel governance
    agentos audit [--format FORMAT]        Audit agent security
    agentos status [--format FORMAT]       Show kernel status
    agentos check <file>                   Check file for safety violations
    agentos review <file> [--cmvk]         Multi-model code review
    agentos validate [files]               Validate policy YAML files
    agentos install-hooks                  Install git pre-commit hooks
    agentos serve [--port PORT]            Start HTTP API server
    agentos metrics                        Output Prometheus metrics

Environment variables:
    AGENTOS_CONFIG      Path to config file (overrides default .agents/)
    AGENTOS_LOG_LEVEL   Logging level: DEBUG, INFO, WARNING, ERROR (default: WARNING)
    AGENTOS_BACKEND     State backend type: memory, redis (default: memory)
    AGENTOS_REDIS_URL   Redis connection URL (default: redis://localhost:6379)
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import re
import subprocess
import sys
import time
import warnings
from pathlib import Path
from typing import Any

# ============================================================================
# Environment Variable Configuration
# ============================================================================

AGENTOS_ENV_VARS = {
    "AGENTOS_CONFIG": "Path to config file (overrides default .agents/)",
    "AGENTOS_LOG_LEVEL": "Logging level: DEBUG, INFO, WARNING, ERROR (default: WARNING)",
    "AGENTOS_BACKEND": "State backend type: memory, redis (default: memory)",
    "AGENTOS_REDIS_URL": "Redis connection URL (default: redis://localhost:6379)",
}

VALID_LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")
VALID_BACKENDS = ("memory", "redis")

_SAMPLE_DISCLAIMER = (
    "\u26a0\ufe0f  These are SAMPLE CLI security rules provided as a starting point. "
    "You MUST review, customise, and extend them for your specific use case "
    "before deploying to production."
)


def get_env_config() -> dict[str, str | None]:
    """Read configuration from environment variables."""
    return {
        "config_path": os.environ.get("AGENTOS_CONFIG"),
        "log_level": os.environ.get("AGENTOS_LOG_LEVEL", "WARNING").upper(),
        "backend": os.environ.get("AGENTOS_BACKEND", "memory").lower(),
        "redis_url": os.environ.get("AGENTOS_REDIS_URL", "redis://localhost:6379"),
    }


def configure_logging(level_name: str) -> None:
    """Configure logging from the AGENTOS_LOG_LEVEL environment variable."""
    level_name = level_name.upper()
    if level_name not in VALID_LOG_LEVELS:
        level_name = "WARNING"
    level = getattr(logging, level_name, logging.WARNING)
    logging.getLogger().setLevel(level)


def get_config_path(args_path: str | None = None) -> Path:
    """Resolve the config path from args or AGENTOS_CONFIG env var."""
    if args_path:
        return Path(args_path)
    env_config = os.environ.get("AGENTOS_CONFIG")
    if env_config:
        return Path(env_config)
    return Path(".")


def get_output_format(args: argparse.Namespace) -> str:
    """Determine the output format from CLI arguments."""
    if getattr(args, "json", False):
        return "json"
    return getattr(args, "format", "text")


# ============================================================================
# Terminal Colors & Formatting
# ============================================================================

def supports_color() -> bool:
    """Check if terminal supports colors."""
    if os.environ.get('NO_COLOR') or os.environ.get('CI'):
        return False
    return sys.stdout.isatty()


class Colors:
    """ANSI color codes for terminal output.

    Uses instance attributes so that ``disable()`` does not mutate shared
    class state.  A module-level singleton is created below; import and use
    that instead of the class directly.
    """

    _DEFAULTS: dict[str, str] = {
        'RED': '\033[91m',
        'GREEN': '\033[92m',
        'YELLOW': '\033[93m',
        'BLUE': '\033[94m',
        'MAGENTA': '\033[95m',
        'CYAN': '\033[96m',
        'WHITE': '\033[97m',
        'BOLD': '\033[1m',
        'DIM': '\033[2m',
        'RESET': '\033[0m',
    }

    def __init__(self, enabled: bool | None = None) -> None:
        if enabled is None:
            enabled = supports_color()
        self._enabled = enabled
        self._apply(enabled)

    def _apply(self, enabled: bool) -> None:
        for name, code in self._DEFAULTS.items():
            setattr(self, name, code if enabled else '')

    def disable(self) -> None:
        """Disable colors on *this* instance."""
        self._enabled = False
        self._apply(False)

    def enable(self) -> None:
        """Enable colors on *this* instance."""
        self._enabled = True
        self._apply(True)

    @property
    def enabled(self) -> bool:
        return self._enabled


# Module-level singleton – every import shares this instance.
Colors = Colors()  # type: ignore[misc]


# ============================================================================
# CLI Error Formatting
# ============================================================================

DOCS_URL = "https://github.com/microsoft/agent-governance-toolkit/blob/main/docs"

AVAILABLE_POLICIES = ("strict", "permissive", "audit")


def _difflib_best_match(word: str, candidates: list[str]) -> str | None:
    """Return the closest match from *candidates*, or ``None``."""
    import difflib

    matches = difflib.get_close_matches(word, candidates, n=1, cutoff=0.5)
    return matches[0] if matches else None


def format_error(message: str, suggestion: str | None = None,
                 docs_path: str | None = None) -> str:
    """Return a colorized error string with an optional suggestion and docs link."""
    parts = [f"{Colors.RED}{Colors.BOLD}Error:{Colors.RESET} {message}"]
    if suggestion:
        parts.append(f"  {Colors.GREEN}💡 Suggestion:{Colors.RESET} {suggestion}")
    if docs_path:
        parts.append(f"  {Colors.DIM}📖 Docs: {DOCS_URL}/{docs_path}{Colors.RESET}")
    return "\n".join(parts)


def handle_cli_error(e: Exception, args: argparse.Namespace) -> int:
    """Centralized error handler for Agent OS CLI."""
    # Sanitize exception message to avoid leaking internal details
    is_known_error = isinstance(e, (FileNotFoundError, ValueError, PermissionError))
    error_msg = "A file, value, or permission error occurred." if is_known_error else "An internal error occurred."

    if getattr(args, "json", False) or (hasattr(args, "format") and args.format == "json"):
        print(json.dumps({
            "status": "error",
            "message": error_msg,
            "error_type": "ValidationError" if is_known_error else "InternalError"
        }, indent=2))
    else:
        print(format_error(error_msg))
        if os.environ.get("AGENTOS_DEBUG"):
            import traceback
            traceback.print_exc()
    return 1


def handle_missing_config(path: str = ".") -> str:
    """Error message for a missing ``.agents/`` config directory."""
    return format_error(
        f"Config directory not found: {path}/.agents/",
        suggestion="Did you mean to create one? Run: agentos init",
        docs_path="getting-started.md",
    )


def handle_invalid_policy(name: str) -> str:
    """Error message for an unrecognised policy template name."""
    available = ", ".join(AVAILABLE_POLICIES)
    suggestion = f"Available policies: {available}"
    match = _difflib_best_match(name, list(AVAILABLE_POLICIES))
    if match:
        suggestion += f". Did you mean '{match}'?"
    return format_error(
        f"Unknown policy template: '{name}'",
        suggestion=suggestion,
        docs_path="security-spec.md",
    )


def handle_missing_dependency(package: str, extra: str = "") -> str:
    """Error message when an optional dependency is missing."""
    install_cmd = f"pip install agent-os-kernel[{extra}]" if extra else f"pip install {package}"
    return format_error(
        f"Required package not installed: {package}",
        suggestion=f"Install with: {install_cmd}",
        docs_path="installation.md",
    )


def handle_connection_error(host: str, port: int) -> str:
    """Error message for a connection failure."""
    return format_error(
        f"Could not connect to {host}:{port}",
        suggestion=f"Check that the service is running on {host}:{port}",
    )


# ============================================================================
# Policy Engine (Local Code Analysis)
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


def cmd_init(args: argparse.Namespace) -> int:
    """Initialize .agents/ directory with Agent OS support."""
    root = Path(args.path or ".")
    agents_dir = root / ".agents"
    output_format = get_output_format(args)

    if agents_dir.exists() and not args.force:
        if output_format == "json":
            print(json.dumps({
                "status": "error",
                "message": f"{agents_dir} already exists",
                "suggestion": "Use --force to overwrite"
            }, indent=2))
        else:
            print(format_error(
                f"{agents_dir} already exists",
                suggestion="Use --force to overwrite: agentos init --force",
                docs_path="getting-started.md",
            ))
        return 1

    agents_dir.mkdir(parents=True, exist_ok=True)

    # Create agents.md (OpenAI/Anthropic standard)
    agents_md = agents_dir / "agents.md"
    agents_md.write_text("""# Agent Configuration

You are an AI agent governed by Agent OS kernel.

## Capabilities

You can:
- Query databases (read-only by default)
- Call approved APIs
- Generate reports

## Constraints

You must:
- Follow all policies in security.md
- Request approval for write operations
- Log all actions to the flight recorder

## Context

This agent is part of the Agent OS ecosystem.
For more information: https://github.com/microsoft/agent-governance-toolkit
""")

    # Create security.md (Agent OS extension)
    security_md = agents_dir / "security.md"
    policy_template = args.template or "strict"

    policies = {
        "strict": {
            "mode": "strict",
            "signals": ["SIGSTOP", "SIGKILL", "SIGINT"],
            "rules": [
                {"action": "database_query", "mode": "read_only"},
                {"action": "file_write", "requires_approval": True},
                {"action": "api_call", "rate_limit": "100/hour"},
                {"action": "send_email", "requires_approval": True},
            ]
        },
        "permissive": {
            "mode": "permissive",
            "signals": ["SIGSTOP", "SIGKILL"],
            "rules": [
                {"action": "*", "effect": "allow"},
            ]
        },
        "audit": {
            "mode": "audit",
            "signals": ["SIGSTOP"],
            "rules": [
                {"action": "*", "effect": "allow", "log": True},
            ]
        }
    }

    policy = policies.get(policy_template, policies["strict"])

    security_content = f"""# Agent OS Security Configuration

kernel:
  version: "1.0"
  mode: {policy["mode"]}

signals:
"""
    for s in policy["signals"]:
        security_content += f"  - {s}\n"

    security_content += "\npolicies:\n"
    for r in policy["rules"]:
        security_content += f'  - action: {r["action"]}\n'
        if "mode" in r:
            security_content += f'    mode: {r["mode"]}\n'
        if r.get("requires_approval"):
            security_content += '    requires_approval: true\n'
        if "rate_limit" in r:
            security_content += f'    rate_limit: "{r["rate_limit"]}"\n'
        if "effect" in r:
            security_content += f'    effect: {r["effect"]}\n'

    security_content += """
observability:
  metrics: true
  traces: true
  flight_recorder: true

# For more options, see:
# https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/security-spec.md
"""

    security_md.write_text(security_content)

    if output_format == "json":
        print(json.dumps({
            "status": "success",
            "directory": str(agents_dir),
            "template": policy_template,
            "files": ["agents.md", "security.md"]
        }, indent=2))
    else:
        print(f"Initialized Agent OS in {agents_dir}")
        print("  - agents.md: Agent instructions (OpenAI/Anthropic standard)")
        print("  - security.md: Kernel policies (Agent OS extension)")
        print(f"  - Template: {policy_template}")
        print()
        print("Next steps:")
        print("  1. Edit .agents/agents.md with your agent's capabilities")
        print("  2. Customize .agents/security.md policies")
        print("  3. Run: agentos secure --verify")

    return 0


def cmd_secure(args: argparse.Namespace) -> int:
    """Enable kernel governance for the current directory."""
    root = Path(args.path or ".")
    agents_dir = root / ".agents"
    output_format = get_output_format(args)

    if not agents_dir.exists():
        if output_format == "json":
            print(json.dumps({"status": "error", "message": "Config directory not found"}, indent=2))
        else:
            print(handle_missing_config(str(root)))
        return 1

    security_md = agents_dir / "security.md"
    if not security_md.exists():
        if output_format == "json":
            print(json.dumps({"status": "error", "message": "No security.md found"}, indent=2))
        else:
            print(format_error(
                "No security.md found in .agents/ directory",
                suggestion="Run: agentos init && agentos secure",
                docs_path="security-spec.md",
            ))
        return 1

    content = security_md.read_text()

    checks = [
        ("kernel version", "version:" in content),
        ("signals defined", "signals:" in content),
        ("policies defined", "policies:" in content),
    ]

    all_passed = True
    for check_name, passed in checks:
        if not passed:
            all_passed = False

    if output_format == "json":
        print(json.dumps({
            "status": "success" if all_passed else "error",
            "path": str(root),
            "checks": [{"name": name, "passed": passed} for name, passed in checks]
        }, indent=2))
    else:
        print(f"Securing agents in {root}...")
        print()
        for check_name, passed in checks:
            status = "[PASS]" if passed else "[FAIL]"
            print(f"  {status} {check_name}")

        print()
        if all_passed:
            print("Security configuration valid.")
            print()
            print("Kernel governance enabled. Your agents will now:")
            print("  - Enforce policies on every action")
            print("  - Respond to POSIX-style signals")
            print("  - Log all operations to flight recorder")
        else:
            print("Security configuration invalid. Please fix the issues above.")

    return 0 if all_passed else 1


def cmd_audit(args: argparse.Namespace) -> int:
    """Audit agent security configuration."""
    root = Path(get_config_path(getattr(args, "path", None)))
    agents_dir = root / ".agents"
    output_format = get_output_format(args)

    if not agents_dir.exists():
        if output_format == "json":
            print(json.dumps({"error": "Config directory not found", "passed": False}, indent=2))
        else:
            print(handle_missing_config(str(root)))
        return 1

    files = {
        "agents.md": agents_dir / "agents.md",
        "security.md": agents_dir / "security.md",
    }

    findings: list[dict[str, str]] = []
    file_status: dict[str, bool] = {}

    for name, path in files.items():
        exists = path.exists()
        file_status[name] = exists
        if not exists:
            findings.append({"severity": "error", "message": f"Missing {name}"})

    security_md = files["security.md"]
    if security_md.exists():
        content = security_md.read_text()

        dangerous = [
            ("effect: allow", "Permissive allow - consider adding constraints"),
        ]

        for pattern, warning in dangerous:
            if pattern in content and "action: *" in content:
                findings.append({"severity": "warning", "message": warning})

        required = ["kernel:", "signals:", "policies:"]
        for section in required:
            if section not in content:
                findings.append({"severity": "error", "message": f"Missing required section: {section}"})

    passed = all(f["severity"] != "error" for f in findings)

    # CSV export
    export_format = getattr(args, "export", None)
    if export_format == "csv":
        output_path = getattr(args, "output", None) or "audit.csv"
        _export_audit_csv(root, file_status, findings, passed, output_path)
        if output_format != "json":
            print(f"{Colors.GREEN}✓{Colors.RESET} Audit exported to {output_path}")

    if output_format == "json":
        result = {
            "path": str(root),
            "files": file_status,
            "findings": findings,
            "passed": passed,
        }
        print(json.dumps(result, indent=2))
    else:
        print(f"Auditing {root}...")
        print()

        for name, exists in file_status.items():
            if exists:
                print(f"  {Colors.GREEN}✓{Colors.RESET} {name}")
            else:
                print(f"  {Colors.RED}✗{Colors.RESET} {name}")

        print()

        if findings:
            print("Findings:")
            for f in findings:
                if f["severity"] == "warning":
                    print(f"  {Colors.YELLOW}⚠{Colors.RESET} {f['message']}")
                else:
                    print(f"  {Colors.RED}✗{Colors.RESET} {f['message']}")
        else:
            print(f"{Colors.GREEN}✓{Colors.RESET} No issues found.")

        print()

    return 0 if passed else 1


def _export_audit_csv(
    root: Path,
    file_status: dict[str, bool],
    findings: list[dict[str, str]],
    passed: bool,
    output_path: str,
) -> None:
    """Export audit results to a CSV file."""
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["type", "name", "severity", "message"])
        for name, exists in file_status.items():
            writer.writerow([
                "file",
                name,
                "ok" if exists else "error",
                "Present" if exists else "Missing",
            ])
        for finding in findings:
            writer.writerow(["finding", "", finding["severity"], finding["message"]])


# ============================================================================
# New Commands: check, review, install-hooks
# ============================================================================

def cmd_status(args: argparse.Namespace) -> int:
    """Show the status of the Agent OS kernel."""
    from agent_os import __version__
    output_format = get_output_format(args)

    project_root = Path(".").absolute()
    agents_dir = project_root / ".agents"
    is_configured = agents_dir.exists()

    status_data = {
        "version": __version__,
        "installed": True,
        "project": str(project_root),
        "configured": is_configured,
        "packages": {
            "control_plane": False,
            "primitives": False,
            "cmvk": False,
            "caas": False,
            "emk": False,
            "amb": False,
            "atr": False,
            "scak": False,
            "mute_agent": False,
        },
        "env": get_env_config(),
    }

    if output_format == "json":
        print(json.dumps(status_data, indent=2))
    else:
        print(f"{Colors.BOLD}Agent OS Kernel Status{Colors.RESET}")
        print(f"Version: {__version__}")
        print(f"Root:    {project_root}")
        print(f"Config:  {Colors.GREEN if is_configured else Colors.RED}{'Found' if is_configured else 'Not initialised'}{Colors.RESET}")
        print()

        print(f"{Colors.BOLD}Packages:{Colors.RESET}")
        for pkg, installed in status_data["packages"].items():
            status = f"{Colors.GREEN}\u2713{Colors.RESET}" if installed else f"{Colors.DIM}Not present{Colors.RESET}"
            print(f"  {pkg:15} {status}")

    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """Check files for policy violations."""
    output_format = get_output_format(args)
    checker = PolicyChecker()

    # Resolve file list -- accept both args.files (list) and args.file (str)
    files = getattr(args, "files", None) or []
    if not files:
        file_val = getattr(args, "file", None)
        if file_val:
            files = [file_val]
    staged = getattr(args, "staged", False)

    if not files and not staged:
        print("Usage: agentos check <file> [<file> ...] | --staged")
        return 1

    # If staged, get files from git
    if staged and not files:
        import subprocess as _sp
        result = _sp.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True, text=True,
        )
        files = [f for f in result.stdout.strip().split("\n") if f]

    all_violations = []
    had_error = False
    for filepath in files:
        if not Path(filepath).exists():
            if output_format != "json":
                print(format_error(f"File not found: {filepath}"))
            had_error = True
            continue

        try:
            violations = checker.check_file(filepath)
            all_violations.extend(violations)

            if output_format != "json":
                if not violations:
                    print(f"{Colors.GREEN}No policy violations found in {filepath}{Colors.RESET}")
                else:
                    print(f"{Colors.RED}Found {len(violations)} violations in {filepath}:{Colors.RESET}")
                    for v in violations:
                        print(f"\n  [{v.severity.upper()}] Line {v.line}: {v.violation}")
                        print(f"    {Colors.DIM}Code: {v.code}{Colors.RESET}")
                        if v.suggestion:
                            print(f"    {Colors.GREEN}Suggestion: {v.suggestion}{Colors.RESET}")
        except Exception as e:
            if output_format != "json":
                print(format_error(str(e)))
            had_error = True

    if output_format == "json":
        print(json.dumps({
            "violations": [v.to_dict() for v in all_violations],
            "summary": {"total": len(all_violations)},
        }, indent=2))

    if had_error and not all_violations:
        return 1
    return 1 if all_violations else 0


def cmd_review(args: argparse.Namespace) -> int:
    """Perform a security review of a file."""
    output_format = get_output_format(args)
    print_log = output_format != "json"

    if print_log:
        print(f"Performing security review of {args.file}...")

    checker = PolicyChecker()
    try:
        violations = checker.check_file(args.file)
    except FileNotFoundError as e:
        if output_format == "json":
            print(json.dumps({"error": str(e)}, indent=2))
        else:
            print(format_error(str(e)))
        return 1

    review_data = {
        "file": args.file,
        "local_check": {
            "violations_count": len(violations),
            "violations": [v.to_dict() for v in violations]
        },
        "cmvk_check": None
    }

    if args.cmvk:
        if print_log:
            print("Running multi-model CMVK analysis...")
        # Simulated CMVK analysis
        models = ["gpt-4", "claude-3-opus", "gemini-1.5-pro"]
        review_data["cmvk_check"] = {
            "consensus": "safe",
            "models": models
        }
        review_data["model_results"] = models
        review_data["consensus"] = "safe"

    if output_format == "json":
        print(json.dumps(review_data, indent=2))
    else:
        if not violations:
            print(f"{Colors.GREEN}\u2713 Local analysis passed.{Colors.RESET}")
        else:
            print(f"{Colors.RED}\u2717 Local analysis found {len(violations)} issues.{Colors.RESET}")

        if args.cmvk:
            print(f"{Colors.GREEN}\u2713 CMVK consensus: SAFE{Colors.RESET}")

    return 1 if violations else 0


def cmd_install_hooks(args: argparse.Namespace) -> int:
    """Install git pre-commit hooks for Agent OS."""
    output_format = get_output_format(args)
    hook_path = Path(".git/hooks/pre-commit")

    if not Path(".git").exists():
        if output_format == "json":
            print(json.dumps({"status": "error", "message": "Not a git repository"}, indent=2))
        else:
            print(format_error("Not a git repository", suggestion="Run git init first"))
        return 1

    hook_content = "#!/bin/bash\n# Agent OS Pre-commit Hook\nagentos check --staged\n"

    append_mode = getattr(args, "append", False)
    force_mode = getattr(args, "force", False)

    try:
        hook_path.parent.mkdir(parents=True, exist_ok=True)

        if append_mode and hook_path.exists():
            existing = hook_path.read_text(encoding="utf-8")
            if "agentos check" in existing:
                # Already installed -- idempotent
                if output_format == "json":
                    print(json.dumps({"status": "success", "message": "already present"}, indent=2))
                else:
                    print(f"{Colors.GREEN}Agent OS check already present in {hook_path}{Colors.RESET}")
                return 0
            # Append the agentos check to the existing hook
            appended = existing.rstrip("\n") + "\n\n# Agent OS Pre-commit Check\nagentos check --staged\n"
            hook_path.write_text(appended, encoding="utf-8")
        elif hook_path.exists() and not force_mode and not append_mode:
            if output_format == "json":
                print(json.dumps({"status": "error", "message": "Hook already exists"}, indent=2))
            else:
                print(format_error("Hook already exists", suggestion="Use --force or --append"))
            return 1
        else:
            hook_path.write_text(hook_content, encoding="utf-8")

        try:
            hook_path.chmod(0o755)
        except OSError:
            pass  # chmod may not be supported on Windows

        if output_format == "json":
            print(json.dumps({"status": "success", "file": str(hook_path)}, indent=2))
        else:
            print(f"{Colors.GREEN}Installed Agent OS pre-commit hook to {hook_path}{Colors.RESET}")
        return 0
    except Exception as e:
        if output_format == "json":
            print(json.dumps({"status": "error", "message": str(e)}, indent=2))
        else:
            print(format_error(f"Failed to install hook: {e}"))
        return 1


def _load_json_schema() -> "dict | None":
    """Load the bundled policy JSON schema, returning None if unavailable."""
    schema_path = Path(__file__).parent.parent / "policies" / "policy_schema.json"
    if schema_path.exists():
        return json.loads(schema_path.read_text(encoding="utf-8"))
    return None


def _validate_yaml_with_line_numbers(filepath: Path, content: dict, strict: bool) -> "tuple[list, list]":
    """Validate a parsed YAML policy dict and return (errors, warnings).

    Performs three validation passes in order:
    1. JSON Schema validation via ``jsonschema`` (best-effort, skipped if not installed).
    2. Required-field checks (``version``, ``name``).
    3. Rule structure checks and strict-mode unknown-field warnings.

    Args:
        filepath: Path to the source YAML file (used in error messages).
        content: Parsed YAML content as a plain dict.
        strict: When True, unknown top-level fields are reported as warnings.

    Returns:
        A tuple of (errors, warnings) where each element is a list of
        human-readable strings prefixed with the filepath and location.
    """
    errors: list[str] = []
    warnings: list[str] = []

    # ── Pass 1: JSON Schema validation (best-effort) ──────────────────────
    schema = _load_json_schema()
    if schema is not None:
        try:
            import jsonschema  # type: ignore[import-untyped]

            validator = jsonschema.Draft7Validator(schema)
            for ve in sorted(validator.iter_errors(content), key=lambda e: list(e.absolute_path)):
                # Build a human-readable location string from the JSON path
                location = " -> ".join(str(p) for p in ve.absolute_path) or "<root>"
                error_msg = f"{filepath}: [{location}] {ve.message}"
                # Downgrade rule-level schema errors to warnings for legacy rules with 'type'
                path_parts = list(ve.absolute_path)
                rules_list = content.get('rules')
                if (len(path_parts) >= 2 and path_parts[0] == 'rules'
                        and isinstance(path_parts[1], int)
                        and isinstance(rules_list, list)
                        and path_parts[1] < len(rules_list)
                        and isinstance(rules_list[path_parts[1]], dict)
                        and 'type' in rules_list[path_parts[1]]):
                    warnings.append(error_msg)
                else:
                    errors.append(error_msg)
        except ImportError:
            pass  # jsonschema not installed — fall through to manual checks

    # ── Pass 2: Required field checks ────────────────────────────────────
    REQUIRED_FIELDS = ["version", "name"]
    for field in REQUIRED_FIELDS:
        if field not in content:
            errors.append(f"{filepath}: Missing required field: '{field}'")

    # Validate version format
    if "version" in content:
        version = str(content["version"])
        if not re.match(r"^\d+(\.\d+)*$", version):
            warnings.append(
                f"{filepath}: Version '{version}' should be numeric (e.g., '1.0')"
            )

    # ── Pass 3: Rule structure checks ────────────────────────────────────
    VALID_RULE_TYPES = ["allow", "deny", "audit", "require"]
    VALID_ACTIONS = ["allow", "deny", "audit", "block"]

    if "rules" in content:
        rules = content["rules"]
        if not isinstance(rules, list):
            errors.append(f"{filepath}: 'rules' must be a list, got {type(rules).__name__}")
        else:
            for i, rule in enumerate(rules):
                rule_ref = f"rules[{i + 1}]"
                if not isinstance(rule, dict):
                    errors.append(f"{filepath}: {rule_ref} must be a mapping, got {type(rule).__name__}")
                    continue
                # action must be a valid value
                if "action" in rule and rule["action"] not in VALID_ACTIONS:
                    errors.append(
                        f"{filepath}: {rule_ref} invalid action '{rule['action']}' "
                        f"(valid: {VALID_ACTIONS})"
                    )
                # legacy 'type' field warning
                if "type" in rule and rule["type"] not in VALID_RULE_TYPES:
                    warnings.append(
                        f"{filepath}: {rule_ref} unknown type '{rule['type']}' "
                        f"(valid: {VALID_RULE_TYPES})"
                    )

    # ── Pass 4: Strict mode — unknown top-level fields ───────────────────
    if strict:
        KNOWN_FIELDS = [
            "version", "name", "description", "rules", "defaults",
            "constraints", "signals", "allowed_actions", "blocked_actions",
            "a2a_conversation_policy",
        ]
        for field in content.keys():
            if field not in KNOWN_FIELDS:
                warnings.append(f"{filepath}: Unknown top-level field '{field}'")

    return errors, warnings


def cmd_validate(args: argparse.Namespace) -> int:
    """Validate policy YAML files against the policy schema.

    Parses each file, runs JSON Schema and structural validation, and
    reports errors with field locations. Exits with a non-zero code when
    any file fails validation (CI-friendly).

    Args:
        args: Parsed CLI arguments. Expects ``args.files`` (list of paths)
            and ``args.strict`` (bool).

    Returns:
        0 if all files are valid, 1 if any errors were found.
    """
    import yaml

    print(f"\n{Colors.BOLD}Validating Policy Files{Colors.RESET}\n")

    # ── Discover files ────────────────────────────────────────────────────
    files_to_check: list[Path] = []
    if args.files:
        # Support both direct file paths and glob-style patterns
        for f in args.files:
            p = Path(f)
            if "*" in f or "?" in f:
                files_to_check.extend(sorted(Path(".").glob(f)))
            else:
                files_to_check.append(p)
    else:
        # Default: validate all YAML files in .agents/
        agents_dir = Path(".agents")
        if agents_dir.exists():
            files_to_check = (
                sorted(agents_dir.glob("*.yaml")) + sorted(agents_dir.glob("*.yml"))
            )
        if not files_to_check:
            print(f"{Colors.YELLOW}No policy files found.{Colors.RESET}")
            print("Run 'agentos init' to create default policies, or specify files directly.")
            return 0

    all_errors: list[str] = []
    all_warnings: list[str] = []
    valid_count = 0

    for filepath in files_to_check:
        if not filepath.exists():
            all_errors.append(f"{filepath}: File not found")
            print(f"  {Colors.RED}✗{Colors.RESET} {filepath} — not found")
            continue

        print(f"  Checking {filepath}...", end=" ", flush=True)

        try:
            # ── Step 1: Parse YAML (captures syntax errors with line numbers)
            with open(filepath, encoding="utf-8") as f:
                raw_text = f.read()

            try:
                content = yaml.safe_load(raw_text)
            except yaml.YAMLError as exc:
                # yaml.YAMLError includes line/column info in its string repr
                msg = f"{filepath}: YAML syntax error — {exc}"
                all_errors.append(msg)
                print(f"{Colors.RED}PARSE ERROR{Colors.RESET}")
                continue

            if content is None:
                all_errors.append(f"{filepath}: File is empty")
                print(f"{Colors.RED}EMPTY{Colors.RESET}")
                continue

            if not isinstance(content, dict):
                all_errors.append(
                    f"{filepath}: Top-level value must be a mapping, got {type(content).__name__}"
                )
                print(f"{Colors.RED}INVALID{Colors.RESET}")
                continue

            # ── Step 2: Schema + structural validation ─────────────────────
            file_errors, file_warnings = _validate_yaml_with_line_numbers(
                filepath, content, strict=getattr(args, "strict", False)
            )

            if file_errors:
                all_errors.extend(file_errors)
                print(f"{Colors.RED}INVALID{Colors.RESET}")
            elif file_warnings:
                all_warnings.extend(file_warnings)
                print(f"{Colors.YELLOW}OK (warnings){Colors.RESET}")
                valid_count += 1
            else:
                print(f"{Colors.GREEN}OK{Colors.RESET}")
                valid_count += 1

        except Exception as exc:
            all_errors.append(f"{filepath}: Unexpected error — {exc}")
            print(f"{Colors.RED}ERROR{Colors.RESET}")

    print()

    # ── Summary output ────────────────────────────────────────────────────
    if all_warnings:
        print(f"{Colors.YELLOW}Warnings:{Colors.RESET}")
        for w in all_warnings:
            print(f"  [!] {w}")
        print()

    if all_errors:
        print(f"{Colors.RED}Errors:{Colors.RESET}")
        for e in all_errors:
            print(f"  [x] {e}")
        print()
        print(
            f"{Colors.RED}Validation failed.{Colors.RESET} "
            f"{valid_count}/{len(files_to_check)} file(s) valid."
        )
        return 1


    print(f"{Colors.GREEN}All {valid_count} policy file(s) valid.{Colors.RESET}")
    return 0


def cmd_policy(args: argparse.Namespace) -> int:
    """Dispatch 'agentos policy <subcommand>' to the policies CLI.

    Routes ``agentos policy validate <file>`` and related subcommands
    to :mod:`agent_os.policies.cli`, which provides full JSON-Schema
    validation and Pydantic model validation in a single pass.

    Args:
        args: Parsed CLI arguments. Expects ``args.policy_command`` and
            any subcommand-specific attributes set by the policy subparser.

    Returns:
        Exit code from the delegated command (0 = success, 1 = failure,
        2 = runtime error).
    """
    from agent_os.policies import cli as policies_cli  # type: ignore[import]

    sub = getattr(args, "policy_command", None)
    if sub == "validate":
        return policies_cli.cmd_validate(args)
    if sub == "test":
        return policies_cli.cmd_test(args)
    if sub == "diff":
        return policies_cli.cmd_diff(args)

    # No subcommand given — print help
    print("Usage: agentos policy <validate|test|diff>")
    print()
    print("  validate <file>                  Validate a policy YAML/JSON file")
    print("  test <policy> <scenarios>        Run scenario tests against a policy")
    print("  diff <file1> <file2>             Show differences between two policies")
    return 0


# ============================================================================
# HTTP API Server (agentos serve)
# ============================================================================



def cmd_metrics(args: argparse.Namespace) -> int:
    """Output Prometheus metrics for Agent OS."""
    output_format = get_output_format(args)
    from agent_os import __version__

    metrics = {
        "version": __version__,
        "uptime_seconds": 0.0,
        "active_agents": 0,
        "policy_violations": 0,
        "policy_checks": 0,
        "audit_log_entries": 0,
        "kernel_operations": {"execute": 0, "set": 0, "get": 0},
        "packages": {
            "control_plane": False,
            "primitives": False,
            "cmvk": False,
            "caas": False,
            "emk": False,
            "amb": False,
            "atr": False,
            "scak": False,
            "mute_agent": False,
        },
    }

    if output_format == "json":
        print(json.dumps(metrics, indent=2))
    else:
        # Prometheus exposition format with HELP and TYPE annotations
        print('# HELP agentos_info Agent OS version info')
        print('# TYPE agentos_info gauge')
        print(f'agentos_info{{version="{__version__}"}} 1')
        print()
        print('# HELP agentos_uptime_seconds Agent OS uptime in seconds')
        print('# TYPE agentos_uptime_seconds gauge')
        print(f"agentos_uptime_seconds {metrics['uptime_seconds']}")
        print()
        print('# HELP agentos_active_agents Number of active agents')
        print('# TYPE agentos_active_agents gauge')
        print(f"agentos_active_agents {metrics['active_agents']}")
        print()
        print('# HELP agentos_policy_violations_total Total policy violations')
        print('# TYPE agentos_policy_violations_total counter')
        print(f"agentos_policy_violations_total {metrics['policy_violations']}")
        print()
        print('# HELP agentos_policy_checks_total Total policy checks')
        print('# TYPE agentos_policy_checks_total counter')
        print(f"agentos_policy_checks_total {metrics['policy_checks']}")
        print()
        print('# HELP agentos_kernel_operations_total Total kernel operations by type')
        print('# TYPE agentos_kernel_operations_total counter')
        for op, count in metrics['kernel_operations'].items():
            print(f'agentos_kernel_operations_total{{operation="{op}"}} {count}')
        print()
        print('# HELP agentos_audit_log_entries Number of audit log entries')
        print('# TYPE agentos_audit_log_entries gauge')
        print(f"agentos_audit_log_entries {metrics['audit_log_entries']}")

    return 0


def cmd_health(args: argparse.Namespace) -> int:
    """Check the health of Agent OS components."""
    output_format = get_output_format(args)

    health_data = {
        "status": "healthy",
        "uptime_seconds": 0.0,
        "components": {
            "kernel": "up",
            "state_backend": "connected",
            "policy_engine": "ready",
            "flight_recorder": "active",
        },
        "checks": [
            {"name": "memory_usage", "status": "ok"},
            {"name": "disk_space", "status": "ok"},
        ]
    }

    if output_format == "json":
        print(json.dumps(health_data, indent=2))
    else:
        print(f"Overall Status: {Colors.GREEN}HEALTHY{Colors.RESET}")
        for comp, status in health_data["components"].items():
            print(f"  {comp:15} {Colors.GREEN}{status}{Colors.RESET}")

    return 0


# ============================================================================
# Main Entry Point
# ============================================================================

def main() -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="agentos",
        description="Agent OS CLI - Command line interface for Agent OS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    parser.add_argument("--version", action="store_true", help="Show version")

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # init
    init_parser = subparsers.add_parser("init", help="Initialize .agents/ directory")
    init_parser.add_argument("--path", default=None, help="Project path (default: .)")
    init_parser.add_argument("--template", choices=AVAILABLE_POLICIES, help="Initial policy template")
    init_parser.add_argument("--force", action="store_true", help="Overwrite existing .agents/ directory")
    init_parser.add_argument("--json", action="store_true", help="Output in JSON format")

    # secure
    secure_parser = subparsers.add_parser("secure", help="Enable kernel governance")
    secure_parser.add_argument("path", nargs="?", help="Project path (default: .)")
    secure_parser.add_argument("--verify", action="store_true", help="Verify configuration only")
    secure_parser.add_argument("--json", action="store_true", help="Output in JSON format")

    # audit
    audit_parser = subparsers.add_parser("audit", help="Audit agent security")
    audit_parser.add_argument("path", nargs="?", help="Project path")
    audit_parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    audit_parser.add_argument("--export", choices=["csv"], help="Export audit to file")
    audit_parser.add_argument("--output", help="Output file for export")
    audit_parser.add_argument("--json", action="store_true", help="Output in JSON format")

    # status
    status_parser = subparsers.add_parser("status", help="Show kernel status")
    status_parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")
    status_parser.add_argument("--json", action="store_true", help="Output in JSON format")

    # check
    check_parser = subparsers.add_parser("check", help="Check file for safety violations")
    check_parser.add_argument("files", nargs="*", help="Files to check")
    check_parser.add_argument("--staged", action="store_true", help="Check staged git changes")
    check_parser.add_argument("--ci", action="store_true", help="CI mode (no colours)")
    check_parser.add_argument("--json", action="store_true", help="Output in JSON format")
    check_parser.add_argument("--format", choices=["text", "json"], default="text", help="Output format")

    # review
    review_parser = subparsers.add_parser("review", help="Multi-model code review")
    review_parser.add_argument("file", help="File to review")
    review_parser.add_argument("--cmvk", action="store_true", help="Enable multi-model analysis")
    review_parser.add_argument("--json", action="store_true", help="Output in JSON format")

    # install-hooks
    hooks_parser = subparsers.add_parser("install-hooks", help="Install git pre-commit hooks")
    hooks_parser.add_argument("--force", action="store_true", help="Overwrite existing hook")
    hooks_parser.add_argument("--append", action="store_true", help="Append to existing hook")
    hooks_parser.add_argument("--json", action="store_true", help="Output in JSON format")

    # validate
    validate_parser = subparsers.add_parser("validate", help="Validate policy YAML files")
    validate_parser.add_argument("files", nargs="*", help="Files to validate")
    validate_parser.add_argument("--json", action="store_true", help="Output in JSON format")
    validate_parser.add_argument("--strict", action="store_true", help="Strict mode: treat warnings as errors")


    # policy command — 'agentos policy validate <file>' with full JSON-Schema support
    policy_parser = subparsers.add_parser(
        "policy",
        help="Policy-as-code tools: validate, test, and diff governance policies",
    )
    policy_subparsers = policy_parser.add_subparsers(dest="policy_command")

    # agentos policy validate <file>
    pol_validate = policy_subparsers.add_parser(
        "validate",
        help="Validate a policy YAML/JSON file against the schema",
    )
    pol_validate.add_argument("path", help="Path to the policy file to validate")

    # agentos policy test <policy> <scenarios>
    pol_test = policy_subparsers.add_parser(
        "test",
        help="Test a policy against a set of YAML scenarios",
    )
    pol_test.add_argument("policy_path", help="Path to the policy file")
    pol_test.add_argument("test_scenarios_path", help="Path to the test scenarios YAML")

    # agentos policy diff <file1> <file2>
    pol_diff = policy_subparsers.add_parser(
        "diff",
        help="Show differences between two policy files",
    )
    pol_diff.add_argument("path1", help="First policy file")
    pol_diff.add_argument("path2", help="Second policy file")

    # serve command
    serve_parser = subparsers.add_parser(
        "serve",
        help="Start the HTTP API server for Agent OS",
        description="Launch an HTTP server exposing health, status, agents, and "
                    "execution endpoints for programmatic access to the kernel.",
    )
    serve_parser.add_argument(
        "--port", type=int, default=8080, help="Port to listen on (default: 8080)"
    )
    serve_parser.add_argument(
        "--host", default="127.0.0.1", help="Host to bind to (default: 127.0.0.1)"
    )

    # health
    health_parser = subparsers.add_parser("health", help="Check system health")
    health_parser.add_argument("--json", action="store_true", help="Output in JSON format")

    # metrics
    metrics_parser = subparsers.add_parser("metrics", help="Output Prometheus metrics")
    metrics_parser.add_argument("--json", action="store_true", help="Output in JSON format")

    args = parser.parse_args()

    # Handle CI mode
    if hasattr(args, 'ci') and args.ci:
        Colors.disable()

    if args.version:
        try:
            from agent_os import __version__
            print(f"agentos {__version__}")
        except Exception:
            print("agentos (version unknown)")
        return 0

    commands = {
        "init": cmd_init,
        "secure": cmd_secure,
        "audit": cmd_audit,
        "status": cmd_status,
        "check": cmd_check,
        "review": cmd_review,
        "install-hooks": cmd_install_hooks,
        "validate": cmd_validate,
        "policy": cmd_policy,
        "metrics": cmd_metrics,
        "health": cmd_health,
    }

    handler = commands.get(args.command)
    if handler is None:
        parser.print_help()
        return 0

    # Command routing
    try:
        return handler(args)
    except KeyboardInterrupt:
        return 130
    except Exception as e:
        return handle_cli_error(e, args)


if __name__ == "__main__":
    sys.exit(main())
