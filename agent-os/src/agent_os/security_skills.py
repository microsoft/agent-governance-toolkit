# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Security Skills — static analysis checks for agent code.

Codifies patterns discovered during security audits into reusable
scan functions that can run in CI, pre-commit hooks, or agent-based
code review workflows.

Each skill returns a list of :class:`SecurityFinding` objects with
severity, description, and line number information.

Architecture:
    scan_file(path)
        ├─ check_stub_security()      — verify/validate stubs returning True
        ├─ check_unsafe_pickle()      — pickle.loads without HMAC
        ├─ check_hardcoded_denylist() — inline security pattern lists
        ├─ check_unbounded_collections() — dicts/lists without size cap
        ├─ check_ssrf_urls()          — URLs from input without guard
        ├─ check_missing_circuit_breaker() — external calls without backoff
        ├─ check_redos_patterns()     — regex without complexity limits
        ├─ check_hardcoded_secrets()  — API keys, tokens in source
        ├─ check_trust_without_crypto() — trust decisions without signatures
        └─ check_error_info_leak()    — exceptions leaking internals
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Sequence


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class SecurityFinding:
    """A single security issue found during scanning."""

    rule_id: str
    title: str
    severity: Severity
    description: str
    file_path: str = ""
    line_number: int = 0
    suggestion: str = ""
    owasp_risks: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Individual skill checks
# ---------------------------------------------------------------------------

def _find_line(source: str, pattern: re.Pattern[str]) -> int:
    """Return 1-based line number of first match, or 0."""
    for i, line in enumerate(source.splitlines(), 1):
        if pattern.search(line):
            return i
    return 0


_STUB_PATTERN = re.compile(
    r"def\s+(verify|validate|authenticate|check_permission|"
    r"is_authorized|is_trusted|authorize)\s*\([^)]*\)\s*"
    r"(?:->.*?)?:\s*\n\s+(?:#[^\n]*)?\s*return\s+True"
)


def check_stub_security(source: str, path: str = "") -> list[SecurityFinding]:
    """Detect security functions that unconditionally return True."""
    findings: list[SecurityFinding] = []
    for m in _STUB_PATTERN.finditer(source):
        fn_name = m.group(1)
        line = source[:m.start()].count("\n") + 1
        findings.append(SecurityFinding(
            rule_id="SKILL-001",
            title=f"Stub security function: {fn_name}()",
            severity=Severity.CRITICAL,
            description=(
                f"Function '{fn_name}()' unconditionally returns True. "
                "An attacker can bypass this security boundary entirely. "
                "This was the root cause of a real-world identity fabrication "
                "vulnerability in agent trust handshakes."
            ),
            file_path=path,
            line_number=line,
            suggestion=(
                "Implement actual verification logic with cryptographic "
                "challenge-response or registry lookup."
            ),
            owasp_risks=("AT02", "AT07"),
        ))
    return findings


_PICKLE_LOAD = re.compile(r"pickle\.loads?\s*\(")
_HMAC_CHECK = re.compile(
    r"hmac\.(new|compare_digest)|verify.*signature|verify.*integrity",
    re.IGNORECASE,
)


def check_unsafe_pickle(source: str, path: str = "") -> list[SecurityFinding]:
    """Detect pickle.loads without HMAC verification."""
    if not _PICKLE_LOAD.search(source):
        return []
    if _HMAC_CHECK.search(source):
        return []
    line = _find_line(source, _PICKLE_LOAD)
    return [SecurityFinding(
        rule_id="SKILL-002",
        title="pickle.loads() without integrity verification",
        severity=Severity.CRITICAL,
        description=(
            "pickle.loads() is called without HMAC or signature verification. "
            "Tampered pickle data enables arbitrary code execution."
        ),
        file_path=path,
        line_number=line,
        suggestion="Sign data with HMAC-SHA256 and verify before deserializing.",
        owasp_risks=("AT02", "AT07"),
    )]


_DENYLIST_PATTERN = re.compile(
    r"(?:dangerous_patterns|blocked_patterns|destructive_patterns|"
    r"sensitive_keywords|HARM_PATTERNS|ILLEGAL_PATTERNS|"
    r"MALWARE_PATTERNS|BLOCKED_)\s*=\s*\["
)


def check_hardcoded_denylist(source: str, path: str = "") -> list[SecurityFinding]:
    """Detect hardcoded security deny-lists in source."""
    findings: list[SecurityFinding] = []
    for m in _DENYLIST_PATTERN.finditer(source):
        line = source[:m.start()].count("\n") + 1
        findings.append(SecurityFinding(
            rule_id="SKILL-003",
            title="Hardcoded security deny-list",
            severity=Severity.HIGH,
            description=(
                "Security patterns are hardcoded in source. Attackers with "
                "read access can reverse-engineer bypass strategies."
            ),
            file_path=path,
            line_number=line,
            suggestion=(
                "Externalize into YAML config loaded at runtime. Keep "
                "built-in defaults in a dataclass but warn when used."
            ),
            owasp_risks=("AT01", "AT08"),
        ))
    return findings


_CACHE_DICT = re.compile(
    r"(?:self\.)?_(?:cache|sessions|pending|peers|clients|buckets|"
    r"tokens|challenges|nonces|attempts)\s*[=:]\s*(?:\{\}|dict\(\)|defaultdict)"
)
_EVICTION = re.compile(
    r"\.pop\(|\.popitem\(|max_size|maxsize|_MAX_|_evict|_cleanup|"
    r"LRUCache|lru_cache|OrderedDict|_max_\w+\s*=",
    re.IGNORECASE,
)


def check_unbounded_collections(
    source: str, path: str = ""
) -> list[SecurityFinding]:
    """Detect security-sensitive dicts/lists without size limits."""
    if not _CACHE_DICT.search(source):
        return []
    if _EVICTION.search(source):
        return []
    line = _find_line(source, _CACHE_DICT)
    return [SecurityFinding(
        rule_id="SKILL-004",
        title="Unbounded security-sensitive collection",
        severity=Severity.MEDIUM,
        description=(
            "A dict/list used for caching or session tracking grows "
            "without size limit. An attacker can exhaust memory."
        ),
        file_path=path,
        line_number=line,
        suggestion="Add _MAX_ENTRIES and evict oldest entries when full.",
        owasp_risks=("AT05",),
    )]


_URL_FROM_INPUT = re.compile(
    r"(?:server_url|endpoint|url|base_url)\s*[:=].*"
    r"(?:args|params|request|input|config)",
    re.IGNORECASE,
)
_SSRF_GUARD = re.compile(
    r"(?:localhost|127\.0\.0\.1|169\.254|::1|0\.0\.0\.0).*block|"
    r"ssrf|_BLOCKED_HOSTS|validate_url|_is_safe_url",
    re.IGNORECASE,
)


def check_ssrf_urls(source: str, path: str = "") -> list[SecurityFinding]:
    """Detect URLs from input used without SSRF validation."""
    if not _URL_FROM_INPUT.search(source):
        return []
    if _SSRF_GUARD.search(source):
        return []
    line = _find_line(source, _URL_FROM_INPUT)
    return [SecurityFinding(
        rule_id="SKILL-005",
        title="SSRF-vulnerable URL handling",
        severity=Severity.HIGH,
        description=(
            "A URL derived from user/agent input is used without SSRF "
            "validation. Attackers can reach internal services (cloud "
            "metadata endpoints, localhost admin panels)."
        ),
        file_path=path,
        line_number=line,
        suggestion="Block reserved/internal addresses before making requests.",
        owasp_risks=("AT02", "AT07"),
    )]


_EXTERNAL_CALL = re.compile(
    r"httpx\.|aiohttp\.|requests\.|fetch\(|urllib|invoke_tool|call_tool",
    re.IGNORECASE,
)
_CIRCUIT_BREAKER = re.compile(
    r"circuit.?breaker|CircuitBreaker|_failures.*threshold|"
    r"backoff|retry.*max|tenacity",
    re.IGNORECASE,
)


def check_missing_circuit_breaker(
    source: str, path: str = ""
) -> list[SecurityFinding]:
    """Detect external calls without circuit breaker."""
    if not _EXTERNAL_CALL.search(source):
        return []
    if _CIRCUIT_BREAKER.search(source):
        return []
    line = _find_line(source, _EXTERNAL_CALL)
    return [SecurityFinding(
        rule_id="SKILL-006",
        title="External calls without circuit breaker",
        severity=Severity.MEDIUM,
        description=(
            "External service calls lack circuit breaker pattern. "
            "Failing downstream services cause cascading failures."
        ),
        file_path=path,
        line_number=line,
        suggestion=(
            "Track consecutive failures per endpoint and stop calling "
            "after threshold is exceeded."
        ),
        owasp_risks=("AT05", "AT10"),
    )]


_REGEX_COMPILE = re.compile(r"re\.compile\(\s*['\"](.+?)['\"]\s*\)")
_REDOS_INDICATORS = re.compile(r"(\.\+|\.\*)\1|(\([^)]+\))\+\+|\(\?!.*\)\+")


def check_redos_patterns(source: str, path: str = "") -> list[SecurityFinding]:
    """Detect regex patterns susceptible to catastrophic backtracking."""
    findings: list[SecurityFinding] = []
    for m in _REGEX_COMPILE.finditer(source):
        pattern_str = m.group(1)
        if _REDOS_INDICATORS.search(pattern_str):
            line = source[:m.start()].count("\n") + 1
            findings.append(SecurityFinding(
                rule_id="SKILL-007",
                title="Potential ReDoS pattern",
                severity=Severity.MEDIUM,
                description=(
                    f"Regex '{pattern_str[:60]}...' has nested quantifiers "
                    "that may cause catastrophic backtracking (ReDoS)."
                ),
                file_path=path,
                line_number=line,
                suggestion=(
                    "Use atomic groups, possessive quantifiers, or "
                    "re2/regex library with backtracking limits."
                ),
                owasp_risks=("AT05",),
            ))
    return findings


_SECRET_PATTERNS = [
    (re.compile(r"""(?:api[_-]?key|secret[_-]?key|password|token)\s*=\s*['"][A-Za-z0-9+/=_-]{16,}['"]""", re.IGNORECASE), "Hardcoded secret/API key"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key ID"),
    (re.compile(r"gh[ps]_[A-Za-z0-9]{36}"), "GitHub token"),
    (re.compile(r"sk-[A-Za-z0-9]{32,}"), "OpenAI API key"),
]


def check_hardcoded_secrets(source: str, path: str = "") -> list[SecurityFinding]:
    """Detect hardcoded API keys, tokens, and secrets."""
    findings: list[SecurityFinding] = []
    for pattern, label in _SECRET_PATTERNS:
        for m in pattern.finditer(source):
            # Skip test files and example placeholders
            if "test" in path.lower() or "example" in path.lower():
                continue
            if "YOUR_" in m.group(0) or "PLACEHOLDER" in m.group(0):
                continue
            line = source[:m.start()].count("\n") + 1
            findings.append(SecurityFinding(
                rule_id="SKILL-008",
                title=f"Hardcoded secret: {label}",
                severity=Severity.CRITICAL,
                description=(
                    f"Possible hardcoded credential ({label}) in source. "
                    "Secrets in code are exposed through version control."
                ),
                file_path=path,
                line_number=line,
                suggestion="Use environment variables or Azure Key Vault.",
                owasp_risks=("AT02",),
            ))
    return findings


_TRUST_DECISION = re.compile(
    r"(?:trust_score|trust_level|verified|is_trusted)\s*=\s*"
    r"(?:True|['\"]trusted['\"]|\d{3,})",
    re.IGNORECASE,
)
_CRYPTO_VERIFY = re.compile(
    r"ed25519|nacl|verify_key|signature.*verify|"
    r"cryptograph|verify_signature|_verify_ed25519",
    re.IGNORECASE,
)


def check_trust_without_crypto(
    source: str, path: str = ""
) -> list[SecurityFinding]:
    """Detect trust decisions made without cryptographic verification."""
    if not _TRUST_DECISION.search(source):
        return []
    if _CRYPTO_VERIFY.search(source):
        return []
    line = _find_line(source, _TRUST_DECISION)
    return [SecurityFinding(
        rule_id="SKILL-009",
        title="Trust decision without cryptographic verification",
        severity=Severity.HIGH,
        description=(
            "Trust score, level, or verification status is assigned without "
            "cryptographic proof (Ed25519, HMAC). Attackers can fabricate "
            "trusted identities."
        ),
        file_path=path,
        line_number=line,
        suggestion=(
            "Require Ed25519 signature verification before assigning "
            "trust scores. Use challenge-response for peer verification."
        ),
        owasp_risks=("AT02", "AT07"),
    )]


_EXCEPTION_EXPOSE = re.compile(
    r"""(?:str\((?:e|err|exc|exception)\)|(?:e|err|exc)\.(?:args|message)|"""
    r"""repr\((?:e|err|exc)\))"""
)
_SANITIZE_ERROR = re.compile(
    r"sanitize|truncat|strip|redact|type\(.*\)\.__name__",
    re.IGNORECASE,
)


def check_error_info_leak(source: str, path: str = "") -> list[SecurityFinding]:
    """Detect exception details leaked to callers."""
    if not _EXCEPTION_EXPOSE.search(source):
        return []
    if _SANITIZE_ERROR.search(source):
        return []
    line = _find_line(source, _EXCEPTION_EXPOSE)
    return [SecurityFinding(
        rule_id="SKILL-010",
        title="Exception details exposed to caller",
        severity=Severity.MEDIUM,
        description=(
            "Full exception details (str(e), repr(e)) are returned or "
            "logged at user-visible level. Internal paths, stack frames, "
            "and SQL queries may leak to attackers."
        ),
        file_path=path,
        line_number=line,
        suggestion=(
            "Return only type(e).__name__ to callers. Log full details "
            "at DEBUG level only."
        ),
        owasp_risks=("AT02",),
    )]


# ---------------------------------------------------------------------------
# Aggregate scanner
# ---------------------------------------------------------------------------

ALL_CHECKS: list[Callable[[str, str], list[SecurityFinding]]] = [
    check_stub_security,
    check_unsafe_pickle,
    check_hardcoded_denylist,
    check_unbounded_collections,
    check_ssrf_urls,
    check_missing_circuit_breaker,
    check_redos_patterns,
    check_hardcoded_secrets,
    check_trust_without_crypto,
    check_error_info_leak,
]


def scan_source(source: str, path: str = "") -> list[SecurityFinding]:
    """Run all security skills against source code.

    Args:
        source: Raw Python source text.
        path: Optional file path for findings metadata.

    Returns:
        List of all findings across all checks.
    """
    findings: list[SecurityFinding] = []
    for check in ALL_CHECKS:
        findings.extend(check(source, path))
    return findings


def scan_file(file_path: str | Path) -> list[SecurityFinding]:
    """Scan a single Python file.

    Args:
        file_path: Path to the .py file to scan.

    Returns:
        List of findings. Empty list if file cannot be read.
    """
    p = Path(file_path)
    if not p.exists() or not p.suffix == ".py":
        return []
    try:
        source = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return scan_source(source, str(p))


def scan_directory(
    directory: str | Path,
    *,
    exclude_tests: bool = False,
    exclude_patterns: Sequence[str] = ("__pycache__", ".git", "node_modules"),
) -> list[SecurityFinding]:
    """Recursively scan all Python files in a directory.

    Args:
        directory: Root directory to scan.
        exclude_tests: Skip files with 'test' in the name.
        exclude_patterns: Directory name patterns to skip.

    Returns:
        Aggregated findings across all scanned files.
    """
    root = Path(directory)
    findings: list[SecurityFinding] = []
    for py_file in root.rglob("*.py"):
        if any(pat in str(py_file) for pat in exclude_patterns):
            continue
        if exclude_tests and "test" in py_file.name.lower():
            continue
        findings.extend(scan_file(py_file))
    return findings


def format_findings(findings: list[SecurityFinding]) -> str:
    """Format findings as a human-readable report.

    Args:
        findings: List of SecurityFinding objects.

    Returns:
        Markdown-formatted report string.
    """
    if not findings:
        return "✅ **Security scan passed.** No issues found."

    by_severity = {s: [] for s in Severity}
    for f in findings:
        by_severity[f.severity].append(f)

    counts = {s.value: len(fs) for s, fs in by_severity.items() if fs}
    summary_parts = [f"{v} {k}" for k, v in counts.items()]
    header = (
        f"❌ **Security scan found {len(findings)} issue(s)**: "
        + ", ".join(summary_parts) + ".\n"
    )

    lines = [header]
    icons = {
        Severity.CRITICAL: "🔴",
        Severity.HIGH: "🟠",
        Severity.MEDIUM: "🟡",
        Severity.LOW: "🔵",
    }

    for f in sorted(findings, key=lambda x: list(Severity).index(x.severity)):
        icon = icons.get(f.severity, "⚪")
        loc = f"{f.file_path}:{f.line_number}" if f.line_number else f.file_path
        lines.append(f"### {icon} [{f.rule_id}] {f.title}")
        if loc:
            lines.append(f"**Location:** `{loc}`")
        lines.append(f.description)
        if f.suggestion:
            lines.append(f"\n**Suggested fix:** {f.suggestion}")
        if f.owasp_risks:
            lines.append(
                "**OWASP Agentic Top-10:** "
                + ", ".join(f"`{r}`" for r in f.owasp_risks)
            )
        lines.append("---")

    return "\n".join(lines)
