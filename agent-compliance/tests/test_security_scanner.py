# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for security scanner."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_compliance.security import (
    SecurityFinding,
    SecurityScanner,
    format_security_report,
)


class TestSecurityFinding:
    """Tests for SecurityFinding class."""

    def test_is_blocking_critical(self):
        """Test that critical findings are blocking."""
        finding = SecurityFinding(
            severity="critical",
            category="secrets",
            title="Hardcoded API key",
            file="config.py",
            line=10,
        )
        assert finding.is_blocking() is True

    def test_is_blocking_high(self):
        """Test that high severity findings are blocking."""
        finding = SecurityFinding(
            severity="high",
            category="cve",
            title="Vulnerable dependency",
            file="requirements.txt",
        )
        assert finding.is_blocking() is True

    def test_is_not_blocking_medium(self):
        """Test that medium severity findings are not blocking."""
        finding = SecurityFinding(
            severity="medium",
            category="code-pattern",
            title="Weak crypto",
            file="utils.py",
        )
        assert finding.is_blocking() is False

    def test_is_not_blocking_low(self):
        """Test that low severity findings are not blocking."""
        finding = SecurityFinding(
            severity="low",
            category="code-pattern",
            title="Best practice suggestion",
            file="main.py",
        )
        assert finding.is_blocking() is False

    def test_to_dict(self):
        """Test conversion to dictionary."""
        finding = SecurityFinding(
            severity="critical",
            category="secrets",
            title="Hardcoded secret",
            file="config.py",
            line=42,
            code="API_KEY = 'sk_live_12345'",
            description="Hardcoded API key detected",
            recommendation="Use environment variables",
            cwe="CWE-798",
            cve="CVE-2024-12345",
        )
        result = finding.to_dict()
        assert result["severity"] == "critical"
        assert result["category"] == "secrets"
        assert result["title"] == "Hardcoded secret"
        assert result["file"] == "config.py"
        assert result["line"] == 42
        assert result["code"] == "API_KEY = 'sk_live_12345'"
        assert result["cwe"] == "CWE-798"
        assert result["cve"] == "CVE-2024-12345"

    def test_format_cli(self):
        """Test CLI formatting."""
        finding = SecurityFinding(
            severity="high",
            category="cve",
            title="Vulnerable dependency",
            file="requirements.txt",
            line=5,
            description="CVE in requests library",
            recommendation="Update to requests>=2.31.0",
            cve="CVE-2023-32681",
        )
        formatted = finding.format_cli("test-plugin")
        assert "[cve] Vulnerable dependency" in formatted
        assert "plugins/test-plugin/requirements.txt" in formatted
        assert "Line: 5" in formatted
        assert "CVE-2023-32681" in formatted
        assert "Update to requests>=2.31.0" in formatted


class TestSecurityScanner:
    """Tests for SecurityScanner class."""

    def setup_method(self):
        """Ensure clean state before each test."""
        # SecurityScanner uses instance state, but guard against any
        # module-level or class-level mutation leaking between tests.
        pass

    def test_scanner_initialization(self, tmp_path):
        """Test scanner initialization."""
        plugin_dir = tmp_path / "test-plugin"
        plugin_dir.mkdir()
        
        scanner = SecurityScanner(plugin_dir, "test-plugin", verbose=False)
        assert scanner.plugin_dir == plugin_dir
        assert scanner.plugin_name == "test-plugin"
        assert scanner.verbose is False
        assert scanner.findings == []
        assert scanner.exemptions == {"exemptions": []}

    def test_load_exemptions_file_not_exists(self, tmp_path):
        """Test loading exemptions when file doesn't exist."""
        plugin_dir = tmp_path / "test-plugin"
        plugin_dir.mkdir()
        
        scanner = SecurityScanner(plugin_dir, "test-plugin")
        assert scanner.exemptions == {"exemptions": []}

    def test_load_exemptions_valid_file(self, tmp_path):
        """Test loading valid exemptions file."""
        plugin_dir = tmp_path / "test-plugin"
        plugin_dir.mkdir()

        exemptions_file = plugin_dir / ".security-exemptions.json"
        exemptions_data = {
            "version": "1.0",
            "exemptions": [
                {
                    "category": "secrets",
                    "file": "tests/fixtures/mock.py",
                    "line": 10,
                    "justification": "Test fixture with mock credentials",
                    "approved_by": "security-team",
                }
            ],
        }
        exemptions_file.write_text(json.dumps(exemptions_data))

        scanner = SecurityScanner(plugin_dir, "test-plugin")
        assert len(scanner.exemptions["exemptions"]) == 1
        assert scanner.exemptions["exemptions"][0]["category"] == "secrets"

    def test_load_exemptions_expired_filtered_out(self, tmp_path):
        """Test that expired exemptions are filtered out."""
        plugin_dir = tmp_path / "test-plugin"
        plugin_dir.mkdir()

        exemptions_file = plugin_dir / ".security-exemptions.json"
        exemptions_data = {
            "version": "1.0",
            "exemptions": [
                {
                    "category": "code-pattern",
                    "file": "old.py",
                    "expires": "2020-01-01",
                    "justification": "Temporary exemption for legacy code",
                    "approved_by": "security-team",
                },
                {
                    "category": "code-pattern",
                    "file": "current.py",
                    "expires": "2099-12-31",
                    "justification": "Future exemption for planned migration",
                    "approved_by": "security-team",
                },
            ],
        }
        exemptions_file.write_text(json.dumps(exemptions_data))

        scanner = SecurityScanner(plugin_dir, "test-plugin")
        # Only the non-expired exemption should be loaded
        assert len(scanner.exemptions["exemptions"]) == 1
        assert scanner.exemptions["exemptions"][0]["file"] == "current.py"

    def test_is_exempted_by_file_and_line(self, tmp_path):
        """Test exemption matching by file and line."""
        plugin_dir = tmp_path / "test-plugin"
        plugin_dir.mkdir()

        exemptions_file = plugin_dir / ".security-exemptions.json"
        exemptions_data = {
            "version": "1.0",
            "exemptions": [
                {
                    "category": "secrets",
                    "file": "config.py",
                    "line": 42,
                    "justification": "Test credential used in unit tests only",
                    "approved_by": "security-team",
                }
            ],
        }
        exemptions_file.write_text(json.dumps(exemptions_data))

        scanner = SecurityScanner(plugin_dir, "test-plugin")

        # Matching finding should be exempted
        finding = SecurityFinding(
            severity="critical",
            category="secrets",
            title="Secret detected",
            file="config.py",
            line=42,
        )
        assert scanner._is_exempted(finding) is True

        # Different file should not be exempted
        finding_different_file = SecurityFinding(
            severity="critical",
            category="secrets",
            title="Secret detected",
            file="other.py",
            line=42,
        )
        assert scanner._is_exempted(finding_different_file) is False

    def test_is_exempted_by_category(self, tmp_path):
        """Test exemption matching by category and file."""
        plugin_dir = tmp_path / "test-plugin"
        plugin_dir.mkdir()

        exemptions_file = plugin_dir / ".security-exemptions.json"
        exemptions_data = {
            "version": "1.0",
            "exemptions": [
                {
                    "category": "code-pattern",
                    "file": "demo.py",
                    "justification": "Demonstrative example not used in production",
                    "approved_by": "security-team",
                }
            ],
        }
        exemptions_file.write_text(json.dumps(exemptions_data))

        scanner = SecurityScanner(plugin_dir, "test-plugin")

        finding = SecurityFinding(
            severity="high",
            category="code-pattern",
            title="eval() usage",
            file="demo.py",
            line=10,
        )
        assert scanner._is_exempted(finding) is True

    def test_is_exempted_by_cve(self, tmp_path):
        """Test exemption matching by CVE identifier."""
        plugin_dir = tmp_path / "test-plugin"
        plugin_dir.mkdir()

        exemptions_file = plugin_dir / ".security-exemptions.json"
        exemptions_data = {
            "version": "1.0",
            "exemptions": [
                {
                    "category": "cve",
                    "file": "requirements.txt",
                    "cve": "CVE-2023-32681",
                    "justification": "Not exploitable in our usage pattern",
                    "approved_by": "security-team",
                }
            ],
        }
        exemptions_file.write_text(json.dumps(exemptions_data))

        scanner = SecurityScanner(plugin_dir, "test-plugin")

        finding = SecurityFinding(
            severity="high",
            category="cve",
            title="Vulnerable dependency",
            file="requirements.txt",
            cve="CVE-2023-32681",
        )
        assert scanner._is_exempted(finding) is True

    def test_should_scan_file_exclusions(self, tmp_path):
        """Test file exclusion patterns."""
        plugin_dir = tmp_path / "test-plugin"
        plugin_dir.mkdir()
        
        scanner = SecurityScanner(plugin_dir, "test-plugin")
        
        # Test files should be excluded
        assert scanner._should_scan_file(plugin_dir / "tests" / "fixtures" / "mock.py") is False
        assert scanner._should_scan_file(plugin_dir / "test_data" / "sample.py") is False
        assert scanner._should_scan_file(plugin_dir / "examples" / "demo.py") is False
        
        # Build artifacts should be excluded
        assert scanner._should_scan_file(plugin_dir / "dist" / "bundle.js") is False
        assert scanner._should_scan_file(plugin_dir / "node_modules" / "lib.js") is False
        
        # Regular source files should be included
        assert scanner._should_scan_file(plugin_dir / "src" / "main.py") is True
        assert scanner._should_scan_file(plugin_dir / "lib" / "utils.js") is True

    def test_is_test_credential_allowed_patterns(self, tmp_path):
        """Test allowed test credential patterns."""
        plugin_dir = tmp_path / "test-plugin"
        plugin_dir.mkdir()
        
        test_file = plugin_dir / "test.py"
        test_file.write_text('API_KEY = "sk_test_fake_key_12345"\nHOST = "localhost"\nIP = "127.0.0.1"\n')
        
        scanner = SecurityScanner(plugin_dir, "test-plugin")
        
        # Test patterns should be recognized as test credentials
        assert scanner._is_test_credential(str(test_file), 1) is True  # sk_test_
        assert scanner._is_test_credential(str(test_file), 2) is True  # localhost
        assert scanner._is_test_credential(str(test_file), 3) is True  # 127.0.0.1

    def test_check_python_code_block_eval_detection(self, tmp_path):
        """Test Python code block dangerous pattern detection."""
        plugin_dir = tmp_path / "test-plugin"
        plugin_dir.mkdir()
        
        md_file = plugin_dir / "README.md"
        
        scanner = SecurityScanner(plugin_dir, "test-plugin")
        
        # Code with eval() should be detected
        code_with_eval = "result = eval(user_input)"
        scanner._check_python_code_block(md_file, code_with_eval, 0)
        
        assert len(scanner.findings) == 1
        assert scanner.findings[0].title == "eval() detected"
        assert scanner.findings[0].severity == "high"

    def test_check_python_code_block_exec_detection(self, tmp_path):
        """Test Python exec() pattern detection."""
        plugin_dir = tmp_path / "test-plugin"
        plugin_dir.mkdir()
        
        md_file = plugin_dir / "README.md"
        
        scanner = SecurityScanner(plugin_dir, "test-plugin")
        
        code_with_exec = "exec(malicious_code)"
        scanner._check_python_code_block(md_file, code_with_exec, 0)
        
        assert len(scanner.findings) == 1
        assert scanner.findings[0].title == "exec() detected"

    def test_check_js_code_block_eval_detection(self, tmp_path):
        """Test JavaScript eval() detection."""
        plugin_dir = tmp_path / "test-plugin"
        plugin_dir.mkdir()
        
        md_file = plugin_dir / "README.md"
        
        scanner = SecurityScanner(plugin_dir, "test-plugin")
        
        code_with_eval = "const result = eval(userInput);"
        scanner._check_js_code_block(md_file, code_with_eval, 0)
        
        assert len(scanner.findings) == 1
        assert scanner.findings[0].title == "eval() detected"

    def test_check_shell_code_block_dangerous_rm(self, tmp_path):
        """Test shell script dangerous pattern detection."""
        plugin_dir = tmp_path / "test-plugin"
        plugin_dir.mkdir()
        
        md_file = plugin_dir / "README.md"
        
        scanner = SecurityScanner(plugin_dir, "test-plugin")
        
        code_with_rm = "rm -rf /"
        scanner._check_shell_code_block(md_file, code_with_rm, 0)
        
        assert len(scanner.findings) == 1
        assert scanner.findings[0].title == "Dangerous recursive delete"
        assert scanner.findings[0].severity == "medium"

    def test_get_bandit_recommendation(self, tmp_path):
        """Test bandit recommendation lookup."""
        plugin_dir = tmp_path / "test-plugin"
        plugin_dir.mkdir()
        
        scanner = SecurityScanner(plugin_dir, "test-plugin")
        
        # Test known rule
        rec = scanner._get_bandit_recommendation("B307")
        assert "eval()" in rec
        
        # Test unknown rule
        rec_unknown = scanner._get_bandit_recommendation("B999")
        assert "Review and fix" in rec_unknown

    def test_scan_markdown_file(self, tmp_path):
        """Test scanning markdown files for dangerous code patterns."""
        plugin_dir = tmp_path / "test-plugin"
        plugin_dir.mkdir()
        
        skill_dir = plugin_dir / "skills" / "demo"
        skill_dir.mkdir(parents=True)
        
        skill_file = skill_dir / "SKILL.md"
        skill_file.write_text("""# Demo Skill

```python
result = eval(user_input)
```

```javascript
const data = eval(userCode);
```

```bash
rm -rf /
```
""")
        
        scanner = SecurityScanner(plugin_dir, "test-plugin")
        scanner._scan_markdown_file(skill_file)
        
        # Should find all three dangerous patterns
        assert len(scanner.findings) == 3
        titles = [f.title for f in scanner.findings]
        assert "eval() detected" in titles
        assert "Dangerous recursive delete" in titles

    def test_scan_empty_file(self, tmp_path):
        """Test scanning an empty file produces no findings."""
        plugin_dir = tmp_path / "test-plugin"
        skill_dir = plugin_dir / "skills" / "empty"
        skill_dir.mkdir(parents=True)

        empty_file = skill_dir / "SKILL.md"
        empty_file.write_text("")

        scanner = SecurityScanner(plugin_dir, "test-plugin")
        scanner._scan_markdown_file(empty_file)

        assert scanner.findings == []

    def test_scan_comments_only_file(self, tmp_path):
        """Test scanning a markdown file with only comments and no code blocks."""
        plugin_dir = tmp_path / "test-plugin"
        skill_dir = plugin_dir / "skills" / "comments"
        skill_dir.mkdir(parents=True)

        md_file = skill_dir / "SKILL.md"
        md_file.write_text(
            "# My Skill\n\n"
            "<!-- This is an HTML comment -->\n\n"
            "Some descriptive text.\n\n"
            "<!-- Another comment -->\n"
        )

        scanner = SecurityScanner(plugin_dir, "test-plugin")
        scanner._scan_markdown_file(md_file)

        assert scanner.findings == []

    def test_scan_binary_file_skipped(self, tmp_path):
        """Test that scanning a binary file is skipped gracefully."""
        plugin_dir = tmp_path / "test-plugin"
        skill_dir = plugin_dir / "skills" / "bin"
        skill_dir.mkdir(parents=True)

        bin_file = skill_dir / "SKILL.md"
        bin_file.write_bytes(b"\x00\x01\x02\xff\xfe\xfd")

        scanner = SecurityScanner(plugin_dir, "test-plugin")
        scanner._scan_markdown_file(bin_file)

        # Binary content triggers UnicodeDecodeError and is skipped
        assert scanner.findings == []

    def test_exemption_with_expired_date(self, tmp_path):
        """Test that an expired exemption does not suppress findings."""
        plugin_dir = tmp_path / "test-plugin"
        plugin_dir.mkdir()

        exemptions_file = plugin_dir / ".security-exemptions.json"
        exemptions_data = {
            "version": "1.0",
            "exemptions": [
                {
                    "category": "secrets",
                    "file": "config.py",
                    "line": 5,
                    "justification": "Temporary exemption that has expired",
                    "approved_by": "security-team",
                    "expires": "2020-01-01",
                }
            ],
        }
        exemptions_file.write_text(json.dumps(exemptions_data))

        scanner = SecurityScanner(plugin_dir, "test-plugin")

        # The expired exemption should have been filtered out during load
        assert len(scanner.exemptions["exemptions"]) == 0

        finding = SecurityFinding(
            severity="critical",
            category="secrets",
            title="Secret detected",
            file="config.py",
            line=5,
        )
        assert scanner._is_exempted(finding) is False

    def test_scan_markdown_nested_code_blocks(self, tmp_path):
        """Test scanning markdown with nested triple backticks."""
        plugin_dir = tmp_path / "test-plugin"
        skill_dir = plugin_dir / "skills" / "nested"
        skill_dir.mkdir(parents=True)

        md_file = skill_dir / "SKILL.md"
        # Outer block should be detected; inner escaped backticks should not
        # cause a parser crash or false positive.
        md_file.write_text(
            "# Nested Code Blocks\n\n"
            "````python\n"
            "# This is safe code\n"
            "x = 1 + 2\n"
            "```\n"
            "# still inside outer block\n"
            "````\n\n"
            "```python\n"
            "result = eval(user_input)\n"
            "```\n"
        )

        scanner = SecurityScanner(plugin_dir, "test-plugin")
        scanner._scan_markdown_file(md_file)

        # Should detect eval() in the second (non-nested) block
        eval_findings = [f for f in scanner.findings if f.title == "eval() detected"]
        assert len(eval_findings) >= 1

    def test_severity_filtering_blocking(self, tmp_path):
        """Test that only critical/high findings block; medium/low do not."""
        plugin_dir = tmp_path / "test-plugin"
        plugin_dir.mkdir()

        scanner = SecurityScanner(plugin_dir, "test-plugin")

        scanner.findings = [
            SecurityFinding(
                severity="critical", category="secrets",
                title="Critical issue", file="a.py",
            ),
            SecurityFinding(
                severity="high", category="cve",
                title="High issue", file="b.py",
            ),
            SecurityFinding(
                severity="medium", category="code-pattern",
                title="Medium issue", file="c.py",
            ),
            SecurityFinding(
                severity="low", category="code-pattern",
                title="Low issue", file="d.py",
            ),
        ]

        blocking = [f for f in scanner.findings if f.is_blocking()]
        non_blocking = [f for f in scanner.findings if not f.is_blocking()]

        assert len(blocking) == 2
        assert all(f.severity in ("critical", "high") for f in blocking)
        assert len(non_blocking) == 2
        assert all(f.severity in ("medium", "low") for f in non_blocking)


class TestFormatSecurityReport:
    """Tests for format_security_report function."""

    def test_format_empty_findings(self):
        """Test formatting with no findings."""
        report = format_security_report("test-plugin", [])
        assert report == ""

    def test_format_critical_findings(self):
        """Test formatting with critical findings."""
        findings = [
            SecurityFinding(
                severity="critical",
                category="secrets",
                title="Hardcoded API key",
                file="config.py",
                line=10,
                description="API key in source",
                recommendation="Use environment variables",
            )
        ]
        report = format_security_report("test-plugin", findings)
        
        assert "❌ SECURITY SCAN FAILED" in report
        assert "🔴 CRITICAL" in report
        assert "Hardcoded API key" in report
        assert "Exit code: 1" in report

    def test_format_multiple_severity_levels(self):
        """Test formatting with mixed severity levels."""
        findings = [
            SecurityFinding(
                severity="critical",
                category="secrets",
                title="Critical issue",
                file="a.py",
            ),
            SecurityFinding(
                severity="high",
                category="cve",
                title="High issue",
                file="b.py",
            ),
            SecurityFinding(
                severity="medium",
                category="code-pattern",
                title="Medium issue",
                file="c.py",
            ),
            SecurityFinding(
                severity="low",
                category="code-pattern",
                title="Low issue",
                file="d.py",
            ),
        ]
        report = format_security_report("test-plugin", findings)
        
        assert "🔴 CRITICAL" in report
        assert "🟡 HIGH" in report
        assert "🟠 MEDIUM" in report
        assert "🟢 LOW" in report
        assert "Summary: 1 critical, 1 high, 1 medium, 1 low" in report

    def test_format_warnings_only_no_blocking(self):
        """Test formatting with only warnings (no blocking issues)."""
        findings = [
            SecurityFinding(
                severity="medium",
                category="code-pattern",
                title="Medium issue",
                file="a.py",
            ),
            SecurityFinding(
                severity="low",
                category="code-pattern",
                title="Low issue",
                file="b.py",
            ),
        ]
        report = format_security_report("test-plugin", findings)
        
        assert "🟠 MEDIUM" in report
        assert "🟢 LOW" in report
        assert "Exit code: 0" in report
        assert "warnings only" in report
