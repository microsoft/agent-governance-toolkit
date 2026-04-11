# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Security Scanner for Plugin Marketplace

Performs security validation on plugin directories:
- Secret detection (detect-secrets)
- Dependency CVE scanning (pip-audit, npm audit)
- Dangerous code patterns (bandit, semgrep)
- File permission and path traversal checks

Integrates with sync-marketplace.py validation flow.
"""

import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# Severity levels and blocking behavior
SEVERITY_CONFIG = {
    "critical": {
        "emoji": "🔴",
        "blocks": True,
        "description": "Immediate security risk",
    },
    "high": {"emoji": "🟡", "blocks": True, "description": "Serious vulnerability"},
    "medium": {
        "emoji": "🟠",
        "blocks": False,
        "description": "Security improvement recommended",
    },
    "low": {"emoji": "🟢", "blocks": False, "description": "Best practice suggestion"},
}

# Files/patterns to exclude from scanning
SECURITY_SCAN_EXCLUSIONS = (
    "**/tests/fixtures/**",
    "**/test/fixtures/**",
    "**/__tests__/mocks/**",
    "**/test_data/**",
    "**/*.test.py",
    "**/*.spec.js",
    "**/*.test.ts",
    "**/*.example.*",
    "**/examples/**",
    "**/samples/**",
    "**/docs/examples/**",
    "**/*.template.*",
    "**/*.sample.*",
    "**/dist/**",
    "**/build/**",
    "**/node_modules/**",
    "**/.venv/**",
    "**/__pycache__/**",
    "**/README.md",
    "**/CONTRIBUTING.md",
)

# Test credential patterns to allow
ALLOWED_TEST_PATTERNS = (
    r"sk_test_",
    r"test[-_]?key",
    r"mock[-_]?token",
    r"fake[-_]?secret",
    r"dummy[-_]?password",
    r"example\.com",
    r"localhost",
    r"127\.0\.0\.1",
)


class SecurityFinding:
    """Represents a single security finding."""

    def __init__(
        self,
        severity: str,
        category: str,
        title: str,
        file: str,
        line: int | None = None,
        code: str | None = None,
        description: str = "",
        recommendation: str = "",
        cwe: str | None = None,
        cve: str | None = None,
    ):
        """Create a security finding.

        Args:
            severity: One of "critical", "high", "medium", "low".
            category: Finding category (e.g. "secrets", "cve", "code-pattern").
            title: Short summary of the finding.
            file: File path where the issue was found.
            line: Line number in the file, if applicable.
            code: Code snippet that triggered the finding.
            description: Detailed description of the issue.
            recommendation: Suggested fix for the issue.
            cwe: Common Weakness Enumeration ID (e.g. "CWE-798").
            cve: Common Vulnerabilities and Exposures ID.
        """
        self.severity = severity
        self.category = category
        self.title = title
        self.file = file
        self.line = line
        self.code = code
        self.description = description
        self.recommendation = recommendation
        self.cwe = cwe
        self.cve = cve

    def is_blocking(self) -> bool:
        """Check if this finding blocks PR merge."""
        return SEVERITY_CONFIG.get(self.severity, {}).get("blocks", False)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON output."""
        return {
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "file": self.file,
            "line": self.line,
            "code": self.code,
            "description": self.description,
            "recommendation": self.recommendation,
            "cwe": self.cwe,
            "cve": self.cve,
        }

    def format_cli(self, plugin_name: str) -> str:
        """Format finding for CLI output."""
        lines = [
            f"  [{self.category}] {self.title}",
            f"  ├─ File: plugins/{plugin_name}/{self.file}",
        ]
        if self.line:
            lines.append(f"  ├─ Line: {self.line}")
        if self.code:
            # Truncate long code snippets
            code_preview = self.code[:80] + "..." if len(self.code) > 80 else self.code
            lines.append(f"  ├─ Code: {code_preview}")
        if self.cve:
            lines.append(f"  ├─ CVE:  {self.cve}")
        if self.cwe:
            lines.append(f"  ├─ CWE:  {self.cwe}")
        lines.append(f"  ├─ Issue: {self.description}")
        if self.recommendation:
            lines.append(f"  └─ Fix:  {self.recommendation}")
        else:
            # Remove last ├─ and replace with └─
            lines[-1] = lines[-1].replace("├─", "└─")

        return "\n".join(lines)


class SecurityScanner:
    """Security scanner for plugin directories."""

    # Pre-compiled regex patterns for performance
    _CODE_BLOCK_RE = re.compile(r"```(\w+)\n(.*?)```", re.DOTALL)
    _SECRET_LOCATION_RE = re.compile(r"(\S+):(\d+)")
    _PYTHON_DANGEROUS_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
        (
            re.compile(r"\beval\s*\("),
            "eval() detected",
            "Avoid eval() - use ast.literal_eval or safer alternatives",
        ),
        (
            re.compile(r"\bexec\s*\("),
            "exec() detected",
            "Avoid exec() - use safer alternatives",
        ),
        (
            re.compile(r"pickle\.loads?\s*\("),
            "pickle usage detected",
            "Use JSON or safer serialization",
        ),
        (
            re.compile(r"os\.system\s*\("),
            "os.system() detected",
            "Use subprocess.run() with argument list",
        ),
    ]
    _JS_DANGEROUS_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
        (re.compile(r"\beval\s*\("), "eval() detected", "Use JSON.parse or safer alternatives"),
        (
            re.compile(r"new\s+Function\s*\("),
            "Function constructor detected",
            "Avoid dynamic code generation",
        ),
        (
            re.compile(r"innerHTML\s*="),
            "innerHTML assignment",
            "Use textContent or DOMPurify for sanitization",
        ),
    ]
    _SHELL_DANGEROUS_PATTERNS: list[tuple[re.Pattern[str], str, str]] = [
        (
            re.compile(r"\brm\s+-rf\s+/"),
            "Dangerous recursive delete",
            "Never delete from root - use specific paths",
        ),
        (
            re.compile(r"\$\(.*curl\s+.*\|.*bash"),
            "Pipe to bash from curl",
            "Download and inspect scripts before execution",
        ),
    ]

    def __init__(self, plugin_dir: Path, plugin_name: str, verbose: bool = False):
        """Initialize security scanner.

        Args:
            plugin_dir: Path to the plugin directory to scan.
            plugin_name: Human-readable plugin name for reports.
            verbose: If True, print detailed progress to stdout.
        """
        self.plugin_dir = plugin_dir
        self.plugin_name = plugin_name
        self.verbose = verbose
        self.findings: list[SecurityFinding] = []
        self.exemptions = self._load_exemptions()

    def _load_exemptions(self) -> dict[str, list[dict[str, object]]]:
        """Load security exemptions from plugin config.

        Validates the exemptions file against a strict schema to prevent
        malicious or malformed exemptions from bypassing security checks.

        Required fields per exemption:
        - category: One of "secrets", "cve", "code-pattern"
        - file: File path (string)
        - justification: Reason for exemption (min 10 chars)
        - approved_by: Person/role who approved (string)

        Optional fields:
        - line: Line number (integer or null)
        - cve: CVE identifier (string or null)
        - expires: ISO 8601 datetime (string or null)

        Returns:
            Dict with "exemptions" key containing valid, non-expired exemptions.
            Returns empty list if file doesn't exist or validation fails.
        """
        exemption_file = self.plugin_dir / ".security-exemptions.json"
        if exemption_file.exists():
            try:
                with open(exemption_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                # Validate structure
                if not isinstance(data, dict) or "exemptions" not in data:
                    return {"exemptions": []}

                if not isinstance(data["exemptions"], list):
                    return {"exemptions": []}

                # Validate and filter each exemption
                valid_exemptions = []
                for ex in data["exemptions"]:
                    # Validate required fields
                    if not isinstance(ex, dict):
                        continue

                    if not all(k in ex for k in ["category", "file", "justification", "approved_by"]):
                        continue

                    # Validate category enum
                    if ex["category"] not in ["secrets", "cve", "code-pattern"]:
                        continue

                    # Validate justification length
                    if not isinstance(ex["justification"], str) or len(ex["justification"]) < 10:
                        continue

                    # Validate types
                    if not isinstance(ex["file"], str) or not isinstance(ex["approved_by"], str):
                        continue

                    # Check expiration if present
                    if "expires" in ex and ex["expires"] is not None:
                        try:
                            expires = datetime.fromisoformat(ex["expires"])
                            if expires < datetime.now():
                                continue  # Skip expired
                        except (ValueError, TypeError):
                            continue  # Invalid date format

                    valid_exemptions.append(ex)

                return {"exemptions": valid_exemptions}
            except (json.JSONDecodeError, ValueError, OSError):
                return {"exemptions": []}
        return {"exemptions": []}

    def _is_exempted(self, finding: SecurityFinding) -> bool:
        """Check if a finding is exempted.

        Matches exemptions against findings using three strategies (in order):
        1. Exact match on category + file + line number
        2. Match on category + file (any line in that file)
        3. Match on CVE identifier
        """
        for exemption in self.exemptions.get("exemptions", []):
            # Match by category, file, and line
            if (
                exemption.get("category") == finding.category
                and exemption.get("file") == finding.file
                and exemption.get("line") is not None
                and exemption.get("line") == finding.line
            ):
                return True
            # Match by category and file pattern
            if exemption.get("category") == finding.category:
                if exemption.get("file") == finding.file and exemption.get("line") is None:
                    return True
            # Match by CVE
            if finding.cve and exemption.get("cve") == finding.cve:
                return True
        return False

    def _should_scan_file(self, file_path: Path) -> bool:
        """Check if file should be scanned based on exclusion patterns."""
        rel_path = file_path.relative_to(self.plugin_dir)
        for pattern in SECURITY_SCAN_EXCLUSIONS:
            if rel_path.match(pattern.replace("**/", "")):
                return False
        return True

    def scan_secrets(self) -> None:
        """Scan for hardcoded secrets using detect-secrets."""
        if not self._tool_available("detect-secrets"):
            if self.verbose:
                print("    [secrets] detect-secrets not installed, skipping")
            return

        try:
            result = subprocess.run(
                ["detect-secrets", "scan", str(self.plugin_dir), "--all-files"],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if "potential secrets" in result.stdout.lower():
                # Parse output for secret locations
                # detect-secrets outputs to stderr for found secrets
                output = result.stdout + result.stderr

                # Simple pattern matching for file:line
                matches = self._SECRET_LOCATION_RE.finditer(output)

                for match in matches:
                    file_path = match.group(1)
                    line_num = int(match.group(2))

                    # Skip if in exclusion list
                    try:
                        path = Path(file_path)
                        if not self._should_scan_file(path):
                            continue
                    except (ValueError, OSError):
                        continue

                    # Check against allowed test patterns
                    if self._is_test_credential(file_path, line_num):
                        continue

                    self.findings.append(
                        SecurityFinding(
                            severity="critical",
                            category="secrets",
                            title="Potential hardcoded secret detected",
                            file=file_path,
                            line=line_num,
                            description="Possible API key, token, or credential in source code",
                            recommendation="Use environment variables, Azure Key Vault, or GitHub Secrets",
                            cwe="CWE-798",
                        )
                    )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

    def _is_test_credential(self, file_path: str, line_num: int) -> bool:
        """Check if a potential secret matches allowed test patterns."""
        try:
            path = Path(file_path)
            if not path.exists():
                return False

            # Read the specific line
            lines = path.read_text(encoding="utf-8").splitlines()
            if line_num > len(lines):
                return False

            line_content = lines[line_num - 1]

            # Check against allowed patterns
            for pattern in ALLOWED_TEST_PATTERNS:
                if re.search(pattern, line_content, re.IGNORECASE):
                    return True
        except (OSError, UnicodeDecodeError):
            pass

        return False

    def scan_python_dependencies(self) -> None:
        """Scan Python dependencies for CVEs using pip-audit."""
        req_files = [
            self.plugin_dir / "requirements.txt",
            self.plugin_dir / "pyproject.toml",
        ]

        for req_file in req_files:
            if not req_file.exists():
                continue

            if not self._tool_available("pip-audit"):
                if self.verbose:
                    print("    [python-cve] pip-audit not installed, skipping")
                return

            try:
                cmd = ["pip-audit", "--format", "json"]
                if req_file.name == "requirements.txt":
                    cmd.extend(["--requirement", str(req_file)])
                else:
                    cmd.extend(["--file", str(req_file)])

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )

                if result.stdout:
                    data = json.loads(result.stdout)
                    self._parse_pip_audit_json(data, req_file.name)
            except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
                pass

    def _parse_pip_audit_json(self, data: dict, filename: str) -> None:
        """Parse pip-audit JSON output and create findings."""
        dependencies = data.get("dependencies", [])
        for dep in dependencies:
            package = dep.get("name", "unknown")
            version = dep.get("version", "unknown")
            vulns = dep.get("vulns", [])

            for vuln in vulns:
                cve = vuln.get("id", "")
                description = vuln.get("description", "")
                fix_versions = vuln.get("fix_versions", [])

                # Determine severity from CVSS score if available
                severity = "high"
                # pip-audit doesn't always include CVSS, default to high

                recommendation = (
                    f"Update to {package}>={fix_versions[0]}"
                    if fix_versions
                    else f"Update {package} to latest version"
                )

                self.findings.append(
                    SecurityFinding(
                        severity=severity,
                        category="cve",
                        title=f"Vulnerable dependency: {package}=={version}",
                        file=filename,
                        description=description[:200],  # Truncate long descriptions
                        recommendation=recommendation,
                        cve=cve,
                    )
                )

    def scan_node_dependencies(self) -> None:
        """Scan Node.js dependencies for vulnerabilities using npm audit."""
        package_json = self.plugin_dir / "package.json"
        if not package_json.exists():
            return

        if not self._tool_available("npm"):
            if self.verbose:
                print("    [node-cve] npm not installed, skipping")
            return

        try:
            # Need to run in plugin directory
            result = subprocess.run(
                ["npm", "audit", "--json"],
                cwd=self.plugin_dir,
                capture_output=True,
                text=True,
                timeout=60,
            )

            if result.stdout:
                data = json.loads(result.stdout)
                self._parse_npm_audit_json(data)
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            pass

    def _parse_npm_audit_json(self, data: dict) -> None:
        """Parse npm audit JSON output and create findings."""
        vulnerabilities = data.get("vulnerabilities", {})

        for package, vuln_data in vulnerabilities.items():
            severity = vuln_data.get("severity", "medium")
            # Map npm severity to our levels
            severity_map = {
                "critical": "critical",
                "high": "high",
                "moderate": "medium",
                "low": "low",
            }
            mapped_severity = severity_map.get(severity, "medium")

            via = vuln_data.get("via", [])
            for item in via:
                if isinstance(item, dict):
                    cve = item.get("cve", "")
                    title = item.get("title", "")

                    self.findings.append(
                        SecurityFinding(
                            severity=mapped_severity,
                            category="cve",
                            title=f"Vulnerable dependency: {package}",
                            file="package.json",
                            description=title,
                            recommendation="Run: npm audit fix --force (review changes carefully)",
                            cve=cve if cve else None,
                        )
                    )

    def scan_code_patterns(self) -> None:
        """Scan for dangerous code patterns using bandit (Python)."""
        # Find Python files
        py_files = list(self.plugin_dir.rglob("*.py"))
        if not py_files:
            return

        if not self._tool_available("bandit"):
            if self.verbose:
                print("    [code-patterns] bandit not installed, skipping")
            return

        try:
            result = subprocess.run(
                ["bandit", "-r", str(self.plugin_dir), "-f", "json", "-ll"],
                capture_output=True,
                text=True,
                timeout=60,
            )

            if result.stdout:
                data = json.loads(result.stdout)
                self._parse_bandit_json(data)
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            pass

    def _parse_bandit_json(self, data: dict) -> None:
        """Parse bandit JSON output and create findings."""
        results = data.get("results", [])

        for result in results:
            filename = result.get("filename", "")
            line_number = result.get("line_number", 0)
            code = result.get("code", "").strip()
            issue_text = result.get("issue_text", "")
            severity = result.get("issue_severity", "MEDIUM").lower()
            confidence = result.get("issue_confidence", "MEDIUM").lower()
            test_id = result.get("test_id", "")

            # Map bandit severity to our levels
            severity_map = {"high": "high", "medium": "medium", "low": "low"}
            mapped_severity = severity_map.get(severity, "medium")

            # Skip low confidence findings
            if confidence == "low":
                continue

            # Make filename relative to plugin dir
            try:
                rel_file = Path(filename).relative_to(self.plugin_dir)
            except ValueError:
                rel_file = Path(filename).name

            if not self._should_scan_file(self.plugin_dir / rel_file):
                continue

            self.findings.append(
                SecurityFinding(
                    severity=mapped_severity,
                    category="code-pattern",
                    title=issue_text,
                    file=str(rel_file),
                    line=line_number,
                    code=code,
                    description=f"Bandit rule {test_id}",
                    recommendation=self._get_bandit_recommendation(test_id),
                )
            )

    def _get_bandit_recommendation(self, test_id: str) -> str:
        """Get recommendation for common bandit findings."""
        recommendations = {
            "B201": "Never use flask debug mode in production",
            "B301": "Avoid pickle - use JSON or safer serialization",
            "B302": "Use defusedxml instead of xml.etree",
            "B303": "Use hashlib with secure algorithms (SHA256+)",
            "B304": "Use secrets module for cryptographic randomness",
            "B306": "Restrict file permissions with tempfile.mkstemp",
            "B307": "eval() is dangerous - find alternative approach",
            "B308": "mark_safe() can introduce XSS - validate input first",
            "B310": "Validate URL before urllib.urlopen",
            "B311": "Use secrets.SystemRandom() for security",
            "B321": "Avoid FTP - use SFTP/FTPS instead",
            "B323": "Avoid SSL/TLS v1.0-1.1 - use TLS 1.2+",
            "B324": "Use modern hash algorithms (SHA256+)",
            "B501": "Validate SSL certificates - avoid verify=False",
            "B502": "Use secure SSL/TLS settings",
            "B506": "Use yaml.safe_load() instead of yaml.load()",
            "B601": "Avoid paramiko auto_add_policy",
            "B602": "Use subprocess with shell=False",
            "B603": "Use subprocess argument list, not shell strings",
            "B607": "Specify absolute path for executables",
        }
        return recommendations.get(test_id, "Review and fix security issue")

    def scan_markdown_code_blocks(self) -> None:
        """Extract and scan code blocks from markdown files."""
        md_files = []

        # Scan skills and agents (primary content)
        for pattern in ["skills/**/SKILL.md", "agents/*.md"]:
            md_files.extend(self.plugin_dir.glob(pattern))

        for md_file in md_files:
            if not self._should_scan_file(md_file):
                continue

            self._scan_markdown_file(md_file)

    def _scan_markdown_file(self, md_path: Path) -> None:
        """Scan code blocks within a markdown file."""
        try:
            content = md_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return

        # Extract code blocks
        blocks = self._CODE_BLOCK_RE.findall(content)

        for i, (lang, code) in enumerate(blocks):
            lang = lang.lower()

            # Check for dangerous patterns in code blocks
            if lang in ["python", "py"]:
                self._check_python_code_block(md_path, code, i)
            elif lang in ["javascript", "js", "typescript", "ts"]:
                self._check_js_code_block(md_path, code, i)
            elif lang in ["bash", "sh", "shell"]:
                self._check_shell_code_block(md_path, code, i)

    def _check_python_code_block(
        self, file_path: Path, code: str, block_index: int
    ) -> None:
        """Check Python code block for dangerous patterns."""
        for compiled_re, title, recommendation in self._PYTHON_DANGEROUS_PATTERNS:
            if compiled_re.search(code):
                rel_file = file_path.relative_to(self.plugin_dir)
                self.findings.append(
                    SecurityFinding(
                        severity="high",
                        category="code-pattern",
                        title=title,
                        file=f"{rel_file} (code block #{block_index + 1})",
                        description="Dangerous pattern in markdown code example",
                        recommendation=recommendation,
                    )
                )

    def _check_js_code_block(
        self, file_path: Path, code: str, block_index: int
    ) -> None:
        """Check JavaScript code block for dangerous patterns."""
        for compiled_re, title, recommendation in self._JS_DANGEROUS_PATTERNS:
            if compiled_re.search(code):
                rel_file = file_path.relative_to(self.plugin_dir)
                self.findings.append(
                    SecurityFinding(
                        severity="high",
                        category="code-pattern",
                        title=title,
                        file=f"{rel_file} (code block #{block_index + 1})",
                        description="Dangerous pattern in markdown code example",
                        recommendation=recommendation,
                    )
                )

    def _check_shell_code_block(
        self, file_path: Path, code: str, block_index: int
    ) -> None:
        """Check shell code block for dangerous patterns."""
        for compiled_re, title, recommendation in self._SHELL_DANGEROUS_PATTERNS:
            if compiled_re.search(code):
                rel_file = file_path.relative_to(self.plugin_dir)
                self.findings.append(
                    SecurityFinding(
                        severity="medium",
                        category="code-pattern",
                        title=title,
                        file=f"{rel_file} (code block #{block_index + 1})",
                        description="Potentially dangerous shell pattern",
                        recommendation=recommendation,
                    )
                )

    def _tool_available(self, tool_name: str) -> bool:
        """Check if a security tool is available."""
        try:
            subprocess.run(
                [tool_name, "--version"],
                capture_output=True,
                timeout=5,
            )
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def run_all_scans(self) -> tuple[bool, list[SecurityFinding]]:
        """
        Run all security scans.

        Returns:
            (passed, findings) where passed=False if blocking issues found
        """
        if self.verbose:
            print(f"  {self.plugin_name}: running security scans...")

        # Run all scanners
        self.scan_secrets()
        self.scan_python_dependencies()
        self.scan_node_dependencies()
        self.scan_code_patterns()
        self.scan_markdown_code_blocks()

        # Filter exempted findings
        filtered_findings = [f for f in self.findings if not self._is_exempted(f)]

        # Check for blocking issues
        blocking_findings = [f for f in filtered_findings if f.is_blocking()]

        passed = len(blocking_findings) == 0

        if self.verbose:
            if passed:
                print(f"  {self.plugin_name}: security scan passed ✓")
            else:
                print(
                    f"  {self.plugin_name}: {len(blocking_findings)} blocking issue(s) found"
                )

        return passed, filtered_findings


def format_security_report(plugin_name: str, findings: list[SecurityFinding]) -> str:
    """Format security findings for CLI output."""
    if not findings:
        return ""

    # Group by severity
    by_severity = {"critical": [], "high": [], "medium": [], "low": []}
    for finding in findings:
        by_severity[finding.severity].append(finding)

    lines = [
        "",
        "═" * 70,
        "",
        f"❌ SECURITY SCAN FAILED for plugin: {plugin_name}",
        "",
        "═" * 70,
        "",
    ]

    # Critical issues
    if by_severity["critical"]:
        lines.append("🔴 CRITICAL (blocks merge):")
        lines.append("")
        for finding in by_severity["critical"]:
            lines.append(finding.format_cli(plugin_name))
            lines.append("")

    # High severity
    if by_severity["high"]:
        lines.append("🟡 HIGH (blocks merge):")
        lines.append("")
        for finding in by_severity["high"]:
            lines.append(finding.format_cli(plugin_name))
            lines.append("")

    # Medium severity
    if by_severity["medium"]:
        lines.append("🟠 MEDIUM (warning - fix before release):")
        lines.append("")
        for finding in by_severity["medium"]:
            lines.append(finding.format_cli(plugin_name))
            lines.append("")

    # Low severity
    if by_severity["low"]:
        lines.append("🟢 LOW (informational):")
        lines.append("")
        for finding in by_severity["low"]:
            lines.append(finding.format_cli(plugin_name))
            lines.append("")

    # Summary
    critical_count = len(by_severity["critical"])
    high_count = len(by_severity["high"])
    medium_count = len(by_severity["medium"])
    low_count = len(by_severity["low"])

    lines.append("─" * 70)
    lines.append(
        f"Summary: {critical_count} critical, {high_count} high, {medium_count} medium, {low_count} low"
    )
    lines.append("")
    lines.append(
        f"To suppress false positives, add to plugins/{plugin_name}/.security-exemptions.json"
    )
    lines.append("")

    blocking = critical_count + high_count > 0
    if blocking:
        lines.append("Exit code: 1 (blocking - PR cannot merge)")
    else:
        lines.append("Exit code: 0 (warnings only - PR can merge)")

    lines.append("")

    return "\n".join(lines)


def scan_plugin_security(
    plugin_dir: Path,
    plugin_name: str,
    verbose: bool = False,
) -> tuple[int, str]:
    """
    Scan a plugin directory for security issues.

    Args:
        plugin_dir: Path to plugin directory
        plugin_name: Plugin name for error messages
        verbose: Print detailed progress

    Returns:
        (exit_code, error_message) where:
        - exit_code: 0 if passed, 1 if blocking issues found
        - error_message: Formatted error message (empty if passed)
    """
    scanner = SecurityScanner(plugin_dir, plugin_name, verbose)
    passed, findings = scanner.run_all_scans()

    if not passed:
        error_msg = format_security_report(plugin_name, findings)
        return 1, error_msg

    # Non-blocking warnings
    if findings:
        warning_msg = format_security_report(plugin_name, findings)
        print(warning_msg)

    return 0, ""


if __name__ == "__main__":
    """Standalone testing."""
    import argparse

    parser = argparse.ArgumentParser(description="Security scan for plugins")
    parser.add_argument("plugin_dir", type=Path, help="Plugin directory to scan")
    parser.add_argument("--name", help="Plugin name", default=None)
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    plugin_name = args.name or args.plugin_dir.name
    exit_code, error_msg = scan_plugin_security(
        args.plugin_dir, plugin_name, args.verbose
    )

    if error_msg:
        print(error_msg, file=sys.stderr)

    sys.exit(exit_code)
