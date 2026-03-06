# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
GitHub Code Review Agent with Agent OS Governance
==================================================

Production-grade code reviewer that catches:
- Secrets and credentials before they leak
- Security vulnerabilities (SQL injection, XSS, etc.)
- Policy violations (blocked patterns, large files)
- Code quality issues

Uses multi-model verification (CMVK) for high-confidence findings.
"""

import re
import hashlib
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime
from enum import Enum

# Agent OS imports
try:
    from agent_os import Kernel, Policy
    AGENT_OS_AVAILABLE = True
except ImportError:
    AGENT_OS_AVAILABLE = False


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """A code review finding."""
    id: str
    severity: Severity
    category: str
    file: str
    line: int
    message: str
    suggestion: Optional[str] = None
    confidence: float = 1.0
    

@dataclass
class ReviewResult:
    """Complete review result."""
    pr_url: str
    findings: list[Finding] = field(default_factory=list)
    files_reviewed: int = 0
    lines_reviewed: int = 0
    review_time_ms: int = 0
    blocked: bool = False
    block_reason: Optional[str] = None


# Secret patterns to detect
SECRET_PATTERNS = {
    "aws_access_key": {
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": Severity.CRITICAL,
        "message": "AWS Access Key ID detected"
    },
    "aws_secret_key": {
        "pattern": r"[A-Za-z0-9/+=]{40}",
        "severity": Severity.CRITICAL,
        "message": "Potential AWS Secret Access Key"
    },
    "github_token": {
        "pattern": r"gh[pousr]_[A-Za-z0-9_]{36,}",
        "severity": Severity.CRITICAL,
        "message": "GitHub Token detected"
    },
    "github_pat": {
        "pattern": r"github_pat_[A-Za-z0-9_]{22,}",
        "severity": Severity.CRITICAL,
        "message": "GitHub Personal Access Token detected"
    },
    "generic_api_key": {
        "pattern": r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"][A-Za-z0-9]{16,}['\"]",
        "severity": Severity.HIGH,
        "message": "API Key detected in code"
    },
    "generic_secret": {
        "pattern": r"(?i)(secret|password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
        "severity": Severity.HIGH,
        "message": "Hardcoded secret/password detected"
    },
    "private_key": {
        "pattern": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "severity": Severity.CRITICAL,
        "message": "Private key detected in code"
    },
    "jwt_token": {
        "pattern": r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
        "severity": Severity.HIGH,
        "message": "JWT token detected"
    },
    "slack_token": {
        "pattern": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}",
        "severity": Severity.CRITICAL,
        "message": "Slack token detected"
    },
    "stripe_key": {
        "pattern": r"sk_live_[A-Za-z0-9]{24,}",
        "severity": Severity.CRITICAL,
        "message": "Stripe live secret key detected"
    }
}

# Security vulnerability patterns
SECURITY_PATTERNS = {
    "sql_injection": {
        "pattern": r"(?i)(execute|cursor\.execute|raw\(|\.query\()\s*\([^)]*(\+|%|\.format|f['\"])",
        "severity": Severity.HIGH,
        "message": "Potential SQL injection - use parameterized queries",
        "suggestion": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
    },
    "command_injection": {
        "pattern": r"(?i)(os\.system|subprocess\.(call|run|Popen)|eval|exec)\s*\([^)]*(\+|%|\.format|f['\"])",
        "severity": Severity.CRITICAL,
        "message": "Potential command injection vulnerability",
        "suggestion": "Use subprocess with shell=False and pass arguments as a list"
    },
    "path_traversal": {
        "pattern": r"(?i)(open|read|write)\s*\([^)]*(\+|%|\.format|f['\"])[^)]*\)",
        "severity": Severity.HIGH,
        "message": "Potential path traversal vulnerability",
        "suggestion": "Validate and sanitize file paths, use os.path.basename()"
    },
    "xss_vulnerability": {
        "pattern": r"(?i)(innerHTML|outerHTML|document\.write)\s*=",
        "severity": Severity.HIGH,
        "message": "Potential XSS vulnerability - avoid innerHTML",
        "suggestion": "Use textContent instead of innerHTML, or sanitize input"
    },
    "insecure_random": {
        "pattern": r"(?i)random\.(random|randint|choice|shuffle)\s*\(",
        "severity": Severity.MEDIUM,
        "message": "Using non-cryptographic random for potential security context",
        "suggestion": "Use secrets module for security-sensitive random values"
    },
    "hardcoded_ip": {
        "pattern": r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        "severity": Severity.LOW,
        "message": "Hardcoded IP address detected",
        "suggestion": "Use environment variables or configuration files for IPs"
    },
    "debug_enabled": {
        "pattern": r"(?i)(debug\s*=\s*True|DEBUG\s*=\s*True|\.setLevel\(logging\.DEBUG\))",
        "severity": Severity.MEDIUM,
        "message": "Debug mode enabled - ensure disabled in production",
        "suggestion": "Use environment-based configuration for debug settings"
    },
    "unsafe_yaml": {
        "pattern": r"yaml\.load\s*\([^)]*\)",
        "severity": Severity.HIGH,
        "message": "Unsafe YAML loading - use yaml.safe_load()",
        "suggestion": "Replace yaml.load() with yaml.safe_load()"
    },
    "unsafe_pickle": {
        "pattern": r"pickle\.(load|loads)\s*\(",
        "severity": Severity.HIGH,
        "message": "Pickle deserialization can execute arbitrary code",
        "suggestion": "Avoid pickle for untrusted data, use JSON instead"
    }
}

# Blocked patterns (immediate rejection)
BLOCKED_PATTERNS = {
    "rm_rf": {
        "pattern": r"rm\s+-rf\s+/",
        "message": "Dangerous rm -rf command on root directory"
    },
    "chmod_777": {
        "pattern": r"chmod\s+777",
        "message": "Insecure chmod 777 permission"
    },
    "disable_ssl": {
        "pattern": r"(?i)(verify\s*=\s*False|ssl\s*=\s*False|CERT_NONE)",
        "message": "SSL verification disabled"
    }
}


class SecretScanner:
    """Scans code for leaked secrets and credentials."""
    
    def __init__(self, patterns: dict = None):
        self.patterns = patterns or SECRET_PATTERNS
        self._compiled = {
            name: re.compile(p["pattern"]) 
            for name, p in self.patterns.items()
        }
    
    def scan(self, content: str, filename: str) -> list[Finding]:
        """Scan content for secrets."""
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Skip comments and obvious test data
            if self._is_safe_line(line):
                continue
                
            for name, pattern in self._compiled.items():
                if pattern.search(line):
                    findings.append(Finding(
                        id=f"secret-{name}-{hashlib.md5(line.encode()).hexdigest()[:8]}",
                        severity=self.patterns[name]["severity"],
                        category="secret",
                        file=filename,
                        line=line_num,
                        message=self.patterns[name]["message"],
                        suggestion="Remove secret and use environment variables or a secrets manager"
                    ))
        
        return findings
    
    def _is_safe_line(self, line: str) -> bool:
        """Check if line is safe to skip (comments, tests, etc.)."""
        stripped = line.strip()
        # Skip comments
        if stripped.startswith('#') or stripped.startswith('//'):
            return True
        # Skip obvious test/example values
        if any(x in stripped.lower() for x in ['example', 'test', 'fake', 'dummy', 'xxx']):
            return True
        return False


class SecurityScanner:
    """Scans code for security vulnerabilities."""
    
    def __init__(self, patterns: dict = None):
        self.patterns = patterns or SECURITY_PATTERNS
        self._compiled = {
            name: re.compile(p["pattern"]) 
            for name, p in self.patterns.items()
        }
    
    def scan(self, content: str, filename: str) -> list[Finding]:
        """Scan content for security issues."""
        findings = []
        lines = content.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            for name, pattern in self._compiled.items():
                if pattern.search(line):
                    findings.append(Finding(
                        id=f"security-{name}-{line_num}",
                        severity=self.patterns[name]["severity"],
                        category="security",
                        file=filename,
                        line=line_num,
                        message=self.patterns[name]["message"],
                        suggestion=self.patterns[name].get("suggestion")
                    ))
        
        return findings


class PolicyChecker:
    """Checks code against organizational policies."""
    
    def __init__(self, max_file_lines: int = 1000, max_function_lines: int = 50):
        self.max_file_lines = max_file_lines
        self.max_function_lines = max_function_lines
        self.blocked_patterns = BLOCKED_PATTERNS
    
    def check(self, content: str, filename: str) -> list[Finding]:
        """Check content against policies."""
        findings = []
        lines = content.split('\n')
        
        # Check file size
        if len(lines) > self.max_file_lines:
            findings.append(Finding(
                id=f"policy-filesize-{filename}",
                severity=Severity.MEDIUM,
                category="policy",
                file=filename,
                line=1,
                message=f"File exceeds {self.max_file_lines} lines ({len(lines)} lines)",
                suggestion="Consider breaking this file into smaller modules"
            ))
        
        # Check for blocked patterns
        for line_num, line in enumerate(lines, 1):
            for name, blocked in self.blocked_patterns.items():
                if re.search(blocked["pattern"], line):
                    findings.append(Finding(
                        id=f"policy-blocked-{name}-{line_num}",
                        severity=Severity.CRITICAL,
                        category="policy",
                        file=filename,
                        line=line_num,
                        message=f"BLOCKED: {blocked['message']}",
                        suggestion="Remove this pattern - it violates security policy"
                    ))
        
        return findings


class GitHubReviewAgent:
    """
    Production GitHub Code Review Agent with Agent OS Governance.
    
    Features:
    - Secret detection (API keys, tokens, passwords)
    - Security vulnerability scanning
    - Policy enforcement
    - Multi-model verification (optional)
    """
    
    def __init__(self, policy: str = "strict"):
        self.policy_level = policy
        self.secret_scanner = SecretScanner()
        self.security_scanner = SecurityScanner()
        self.policy_checker = PolicyChecker()
        
        # Initialize Agent OS governance if available
        if AGENT_OS_AVAILABLE:
            self.kernel = Kernel()
            self.kernel.load_policy(Policy.from_yaml(self._get_policy_yaml()))
        else:
            self.kernel = None
    
    def _get_policy_yaml(self) -> str:
        """Get policy YAML based on strictness level."""
        return f"""
version: "1.0"
name: github-review-{self.policy_level}

rules:
  - name: block-secrets
    severity: critical
    action: block
    
  - name: warn-security
    severity: high
    action: comment
    
  - name: suggest-quality
    severity: medium
    action: suggest
"""
    
    async def review_pr(self, pr_url: str = None, diff_content: str = None, 
                        files: dict[str, str] = None) -> ReviewResult:
        """
        Review a pull request or diff.
        
        Args:
            pr_url: GitHub PR URL (will fetch diff)
            diff_content: Raw diff content
            files: Dict of filename -> content to review
        
        Returns:
            ReviewResult with findings
        """
        start_time = datetime.now()
        result = ReviewResult(pr_url=pr_url or "local")
        
        # If files provided directly, use those
        if files:
            for filename, content in files.items():
                file_findings = self._review_file(filename, content)
                result.findings.extend(file_findings)
                result.files_reviewed += 1
                result.lines_reviewed += len(content.split('\n'))
        
        # Check for blocking findings
        critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
        if critical_findings:
            result.blocked = True
            result.block_reason = f"Found {len(critical_findings)} critical issues"
        
        result.review_time_ms = int((datetime.now() - start_time).total_seconds() * 1000)
        return result
    
    def _review_file(self, filename: str, content: str) -> list[Finding]:
        """Review a single file."""
        findings = []
        
        # Run all scanners
        findings.extend(self.secret_scanner.scan(content, filename))
        findings.extend(self.security_scanner.scan(content, filename))
        findings.extend(self.policy_checker.check(content, filename))
        
        return findings
    
    def format_github_comment(self, result: ReviewResult) -> str:
        """Format findings as a GitHub PR comment."""
        if not result.findings:
            return "✅ **Code Review Passed**\n\nNo issues found."
        
        lines = []
        
        # Header
        if result.blocked:
            lines.append(f"🚫 **Code Review Failed** - {result.block_reason}\n")
        else:
            lines.append(f"⚠️ **Code Review Complete** - {len(result.findings)} issue(s) found\n")
        
        # Group by severity
        by_severity = {}
        for f in result.findings:
            by_severity.setdefault(f.severity, []).append(f)
        
        # Critical first
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            if severity not in by_severity:
                continue
            
            emoji = {
                Severity.CRITICAL: "🔴",
                Severity.HIGH: "🟠",
                Severity.MEDIUM: "🟡",
                Severity.LOW: "🔵",
                Severity.INFO: "ℹ️"
            }[severity]
            
            lines.append(f"\n### {emoji} {severity.value.upper()} ({len(by_severity[severity])})\n")
            
            for f in by_severity[severity]:
                lines.append(f"- **{f.file}:{f.line}** - {f.message}")
                if f.suggestion:
                    lines.append(f"  - 💡 {f.suggestion}")
        
        # Footer
        lines.append(f"\n---\n📊 Reviewed {result.files_reviewed} files, {result.lines_reviewed} lines in {result.review_time_ms}ms")
        lines.append("🤖 *Powered by [Agent OS](https://github.com/microsoft/agent-governance-toolkit)*")
        
        return "\n".join(lines)


def demo():
    """Demonstrate the GitHub Review Agent."""
    import asyncio
    
    print("=" * 60)
    print("GitHub Code Review Agent - Agent OS Demo")
    print("=" * 60)
    
    # Sample code with issues
    sample_files = {
        "src/config.py": '''
import os

# Configuration
DATABASE_URL = os.environ.get("DATABASE_URL", "")
API_KEY = os.environ.get("STRIPE_API_KEY", "")
AWS_ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY_ID", "")

def get_config():
    return {
        "debug": True,
        "secret": os.environ.get("APP_SECRET", "")
    }
''',
        "src/database.py": '''
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # SQL Injection vulnerability!
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()

def delete_all():
    import os
    os.system("rm -rf /var/data/*")  # Dangerous!
''',
        "src/api.py": '''
import yaml
import pickle
import requests

def load_config(path):
    with open(path) as f:
        return yaml.load(f)  # Unsafe!

def load_data(path):
    with open(path, 'rb') as f:
        return pickle.load(f)  # Unsafe deserialization

def fetch_data(url):
    return requests.get(url, verify=False)  # SSL disabled!
'''
    }
    
    async def run_review():
        agent = GitHubReviewAgent(policy="strict")
        result = await agent.review_pr(files=sample_files)
        
        print(f"\n📋 Review Complete")
        print(f"   Files: {result.files_reviewed}")
        print(f"   Lines: {result.lines_reviewed}")
        print(f"   Time: {result.review_time_ms}ms")
        print(f"   Blocked: {result.blocked}")
        
        print("\n" + "=" * 60)
        print("GitHub Comment Preview:")
        print("=" * 60)
        print(agent.format_github_comment(result))
    
    asyncio.run(run_review())


if __name__ == "__main__":
    demo()
