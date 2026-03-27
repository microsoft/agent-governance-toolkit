# Agent Compliance — Coding Agent Instructions

## Project Overview

Agent Compliance (`agent-governance-toolkit`) provides **runtime policy enforcement, governance attestation validation, and security scanning** for AI agent systems. This package ensures agents operate within organizational compliance boundaries and security policies.

**Core Capabilities:**

- **Governance Attestation Validation:** PR checklist validation for organizational governance requirements
- **Security Scanning:** Automated detection of secrets, CVEs, dangerous code patterns, and unsafe operations
- **Runtime Policy Enforcement:** OWASP ASI 2026 controls and integrity verification

## Build & Test Commands

```bash
# Install dependencies (development mode)
pip install -e ".[dev]"

# Run all tests
pytest tests/ -v

# Run tests with coverage
pytest tests/ --cov=src/agent_compliance --cov-report=html --cov-branch

# Type checking
pyright src/

# Lint and format
ruff check . --fix
ruff format .
```

## Code Style

- **Formatter/Linter:** Ruff (line-length: 100, target: Python 3.10+)
- **Type checker:** Pyright basic mode with ignore for missing stubs
- **Docstrings:** Google-style for public APIs
- **Imports:** Sorted alphabetically, grouped (stdlib → third-party → first-party → local)

## Key Files

| File | Purpose |
|------|---------|
| `src/agent_compliance/governance/attestation_validator.py` | PR governance attestation validation logic |
| `src/agent_compliance/security/scanner.py` | Security scanning engine (secrets, CVEs, code patterns) |
| `src/agent_compliance/security/schemas/` | JSON schemas for security exemptions |
| `tests/test_governance_attestation.py` | Attestation validation test suite (17 tests) |
| `tests/test_security_scanner.py` | Security scanner test suite (25 tests) |

## Coding Conventions

- All public APIs must have type hints
- Use `dataclasses` for simple data structures, Pydantic for validation-heavy ones
- SecurityFinding fields: `severity`, `category`, `title`, `file`, `line`, `code`, `description`, `recommendation`, `cwe`, `cve`
- Severity levels: `critical`, `high`, `medium`, `low` (critical/high block PRs)
- AttestationResult fields: `valid`, `errors`, `warnings`, `sections_found`

## Security Scanning

### What Gets Scanned

- Python files (`*.py`)
- JavaScript/TypeScript (`*.js`, `*.ts`)
- Shell scripts (`*.sh`, `*.bash`)
- PowerShell (`*.ps1`)
- Dependency files (`requirements.txt`, `package.json`, `pyproject.toml`)
- **Code blocks in markdown files** (skills and agents)

### What's Excluded

- Test fixtures (`**/tests/fixtures/**`, `**/test_data/**`)
- Example files (`**/examples/**`, `**/*.example.*`)
- Build artifacts (`**/dist/**`, `**/node_modules/**`, `**/__pycache__/**`)
- Documentation (most `README.md`, `docs/**/*.md`)

### Severity Configuration

```python
SEVERITY_CONFIG = {
    "critical": {"blocks": True},   # Hardcoded secrets, RCE, CVSS ≥ 9.0
    "high": {"blocks": True},       # Command injection, SQL injection, CVSS 7.0-8.9
    "medium": {"blocks": False},    # Weak crypto, CVSS 4.0-6.9
    "low": {"blocks": False},       # Best practices, CVSS < 4.0
}
```

## Governance Attestation

### Required Sections (Default)

1. Security review
2. Privacy review
3. CELA review
4. Responsible AI review
5. Accessibility review
6. Release Readiness / Safe Deployment
7. Org-specific Launch Gates

### Validation Rules

- Each section must have **exactly one** checkbox marked
- Section titles must be at the start of lines (after `##`)
- Checkboxes can have leading whitespace
- Case-insensitive matching (`[x]` or `[X]`)

## Testing Requirements

- All new features **must** include corresponding tests
- **Attestation tests:** Cover valid/invalid sections, checkbox counts, edge cases (CRLF, special chars)
- **Security tests:** Cover finding creation, exemption matching, pattern detection, formatting
- Run tests before committing: `pytest tests/ -v`
- Aim for >90% code coverage on new code

## Exemption System

Security exemptions use `.security-exemptions.json`:

```json
{
  "version": "1.0",
  "exemptions": [
    {
      "tool": "detect-secrets",
      "file": "tests/fixtures/mock.py",
      "line": 10,
      "reason": "Test fixture with intentionally fake credentials",
      "approved_by": "security-team"
    }
  ]
}
```

### Exemption Matching

- **File + line:** Exact match
- **Category + file:** Any line in file
- **CVE identifier:** Matches across all files
- **Temporary exemptions:** Must have `expires` field (ISO 8601 date)

## GitHub Actions

### action/governance-attestation

Validates PR descriptions contain properly filled governance attestation checklists.

**Inputs:**
- `pr-body`: PR body to validate (defaults to current PR)
- `required-sections`: YAML list of section titles
- `min-body-length`: Minimum PR body length (default: 40)

**Outputs:**
- `status`: `pass` or `fail`
- `errors`: Newline-separated list of errors
- `sections-found`: JSON mapping sections to checkbox counts

### action/security-scan

Scans for secrets, CVEs, and dangerous code patterns.

**Inputs:**
- `paths`: Space-separated paths to scan (required)
- `exemptions-file`: Path to exemptions JSON (default: `.security-exemptions.json`)
- `min-severity`: Minimum severity to block (default: `high`)

**Outputs:**
- `status`: `pass` or `fail`
- `findings-count`: Total findings
- `blocking-count`: Critical/high findings
- `findings`: JSON-formatted findings

## Boundaries

- **Never commit** secrets, credentials, or API keys
- **Never loosen** severity blocking thresholds without approval
- **Never skip** test coverage for new features
- Keep backward compatibility in public APIs

## Integration with External Tools

Security scanner integrates with:
- **detect-secrets:** Secret detection
- **pip-audit:** Python CVE scanning
- **npm audit:** Node.js CVE scanning
- **bandit:** Python SAST

All tool integrations gracefully handle missing tools (skip scan if not available).

## Commit Style

Use conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`

Example:
```
feat(security): add support for shell script scanning

- Add _check_shell_code_block method
- Detect dangerous rm -rf patterns
- Add tests for shell code validation
```
