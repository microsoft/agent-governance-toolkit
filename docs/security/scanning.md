# Security Scanning for Plugin Contributors

This document explains the security scanning process that runs automatically on all plugin pull requests.

## Overview

When you submit a PR that adds or modifies a plugin under `plugins/`, an automated security scan runs to detect:

- 🔴 **Hardcoded secrets** (API keys, tokens, passwords)
- 🔴 **Dependency vulnerabilities** (CVEs in Python/Node packages)
- 🟡 **Dangerous code patterns** (eval, command injection, unsafe operations)
- 🟠 **Unsafe file operations** (path traversal, unrestricted writes)

## Exit Behavior

The security scan uses the same exit behavior as other validation checks:

- ❌ **Critical/High severity** findings block PR merge (exit code 1)
- ⚠️ **Medium/Low severity** findings generate warnings but allow merge (exit code 0)
- ✅ **No findings** allows PR to merge normally

## Severity Levels

| Severity | Emoji | Action | Examples |
|----------|-------|--------|----------|
| **Critical** | 🔴 | BLOCKS MERGE | Hardcoded secrets, RCE vulnerabilities, CVSS ≥ 9.0 |
| **High** | 🟡 | BLOCKS MERGE | CVE CVSS 7.0-8.9, command injection, SQL injection |
| **Medium** | 🟠 | Warning | CVE CVSS 4.0-6.9, weak crypto, missing validation |
| **Low** | 🟢 | Info | CVE CVSS < 4.0, best practice suggestions |

## What Gets Scanned

### File Types
- ✅ Python files (`*.py`)
- ✅ JavaScript/TypeScript files (`*.js`, `*.ts`)
- ✅ Shell scripts (`*.sh`, `*.bash`)
- ✅ PowerShell scripts (`*.ps1`)
- ✅ Dependency files (`requirements.txt`, `package.json`, `pyproject.toml`)
- ✅ **Code blocks in markdown files** (skills and agents)

### Exclusions
The scanner automatically skips:
- ❌ Test fixtures and mock data (`tests/fixtures/`, `**/*.test.py`)
- ❌ Example files (`**/*.example.*`, `examples/`, `samples/`)
- ❌ Template files (`**/*.template.*`, `**/*.sample.*`)
- ❌ Build artifacts (`dist/`, `build/`, `node_modules/`)
- ❌ Documentation (most `README.md`, `docs/**/*.md`)

**Note:** Skills (`skills/*/SKILL.md`) and agents (`agents/*.md`) **ARE scanned**, including code blocks within them.

## Security Checks

### 1. Secret Detection
**Tool:** detect-secrets

**Catches:**
- API keys (AWS, Azure, Stripe, etc.)
- Authentication tokens
- Private keys
- Database passwords
- Connection strings

**Allowed patterns** (won't flag):
- Test credentials: `sk_test_*`, `test_key`, `mock_token`
- Localhost references: `127.0.0.1`, `localhost`
- Example domains: `example.com`

### 2. Dependency Vulnerability Scanning

**Python (pip-audit):**
- Scans `requirements.txt` and `pyproject.toml`
- Checks against OSV vulnerability database
- Reports CVEs with CVSS scores

**Node.js (npm audit):**
- Scans `package.json` and `package-lock.json`
- Checks npm advisory database
- Reports vulnerabilities with fix versions

### 3. Dangerous Code Patterns

**Python (bandit):**
- `eval()`, `exec()` usage
- `pickle.loads()` deserialization
- `os.system()` instead of subprocess
- Weak cryptography
- SQL injection patterns
- Insecure temporary files

**JavaScript/TypeScript:**
- `eval()` usage
- `new Function()` constructor
- `innerHTML` assignments (XSS risk)

**Shell scripts:**
- `rm -rf /` patterns
- Pipe to bash from curl

## Suppressing False Positives

If the scanner flags something that's actually safe, you can create a `.security-exemptions.json` file in your plugin directory.

### Location
```
plugins/my-plugin/.security-exemptions.json
```

### Format

```json
{
  "version": "1.0",
  "exemptions": [
    {
      "tool": "detect-secrets",
      "file": "tests/fixtures/mock_credentials.py",
      "line": 12,
      "reason": "Test fixture with intentionally fake credentials for unit tests",
      "approved_by": "security-team"
    },
    {
      "tool": "bandit",
      "file": "server/dev_mode.py",
      "rule": "B201",
      "reason": "Flask debug mode only enabled in dev environment via FLASK_ENV check",
      "approved_by": "my-alias",
      "ticket": "ADO-12345"
    },
    {
      "tool": "pip-audit",
      "package": "requests",
      "version": "2.25.0",
      "cve": "CVE-2023-32681",
      "reason": "Not exploitable - only internal API calls, no proxy usage",
      "temporary": true,
      "expires": "2026-06-30",
      "ticket": "ADO-67890"
    }
  ]
}
```

### Required Fields

| Field | Required | Description |
|-------|----------|-------------|
| `reason` | ✅ Yes | Why this is safe (minimum 10 characters) |
| `approved_by` | ⚠️ For Critical/High | Who approved this exemption |
| `ticket` | ⚠️ For Critical/High | Tracking ticket (ADO work item) |
| `expires` | ⚠️ If `temporary: true` | ISO date when exemption expires |

### Exemption Matching

Exemptions match findings by:
- **Exact match:** `file` + `line` number
- **Category match:** `category` + `file` (any line)
- **CVE match:** `cve` identifier
- **Rule match:** Tool-specific `rule` ID (e.g., `B201` for bandit)

### Temporary Exemptions

For known issues you plan to fix later:

```json
{
  "tool": "pip-audit",
  "package": "old-library",
  "cve": "CVE-2025-12345",
  "reason": "Upgrade blocked by dependency conflict - scheduled for Q2",
  "temporary": true,
  "expires": "2026-06-30",
  "ticket": "ADO-99999"
}
```

**Expired exemptions** are treated as active findings again.

## Common Scenarios

### Scenario 1: Test Credentials in Fixtures

```python
# tests/fixtures/mock_auth.py
TEST_API_KEY = "sk_test_fake_key_12345"  # ← Will be flagged
```

**Fix Option 1** - Use allowed pattern:
```python
TEST_API_KEY = "sk_test_12345"  # Starts with sk_test_ (allowed)
```

**Fix Option 2** - Add exemption:
```json
{
  "tool": "detect-secrets",
  "file": "tests/fixtures/mock_auth.py",
  "line": 3,
  "reason": "Test fixture - not a real credential"
}
```

### Scenario 2: Vulnerable Dependency

```
❌ SECURITY SCAN FAILED

🔴 CRITICAL:
  [cve] Vulnerable dependency: requests==2.25.0
  ├─ File: requirements.txt
  ├─ CVE:  CVE-2023-32681 (CVSS 7.5)
  └─ Fix:  Update to requests>=2.31.0
```

**Fix:**
```bash
# Update requirements.txt
requests>=2.31.0

# Or use pip-audit to fix automatically
pip-audit --fix
```

### Scenario 3: eval() in Code Example

If you have `eval()` in a markdown code block that's **demonstrative** (showing what NOT to do):

**Option 1** - Add a comment in the code block:
````markdown
```python
# BAD EXAMPLE - DO NOT USE IN PRODUCTION
result = eval(user_input)  # Dangerous!

# GOOD EXAMPLE - Use instead:
result = ast.literal_eval(user_input)
```
````

**Option 2** - Add exemption:
```json
{
  "tool": "bandit",
  "file": "skills/security-examples/SKILL.md",
  "rule": "B307",
  "reason": "Demonstrative bad example showing what not to do"
}
```

### Scenario 4: Legitimate Dynamic Code

Sometimes you genuinely need dynamic behavior:

```python
# BEFORE (flagged)
exec(f"import {module_name}")

# BETTER (safer)
import importlib
module = importlib.import_module(module_name)
```

If you truly need `exec()` after reviewing alternatives:

```json
{
  "tool": "bandit",
  "file": "server/plugin_loader.py",
  "line": 145,
  "rule": "B307",
  "reason": "Dynamic module loading from validated plugin registry - input sanitized with allowlist",
  "approved_by": "security-guardian",
  "ticket": "ADO-54321"
}
```

## Running Locally

Before submitting your PR, run the security scan locally:

```bash
# From repository root
python scripts/sync-marketplace.py --preview

# Skip security scanning (not recommended)
python scripts/sync-marketplace.py --no-security --preview

# Test only security scanning
python scripts/security_scanner.py plugins/my-plugin --verbose
```

## Tools Used

| Tool | Purpose | Language |
|------|---------|----------|
| [detect-secrets](https://github.com/Yelp/detect-secrets) | Secret detection | All |
| [pip-audit](https://github.com/pypa/pip-audit) | Python CVE scanning | Python |
| [npm audit](https://docs.npmjs.com/cli/v8/commands/npm-audit) | Node.js CVE scanning | Node.js |
| [bandit](https://bandit.readthedocs.io/) | Python SAST | Python |

## Getting Help

If you're blocked by security findings:

1. **Review the error message** - it includes specific recommendations
2. **Check if it's a false positive** - add to `.security-exemptions.json`
3. **Ask in the PR** - tag @security-team for guidance
4. **Read the CWE/CVE** - links provided in findings for detailed explanations

## Best Practices

### DO ✅
- Use environment variables for secrets: `os.environ.get("API_KEY")`
- Keep dependencies updated
- Use `subprocess.run()` with argument lists, not shell strings
- Validate and sanitize all user input
- Use `ast.literal_eval()` instead of `eval()`
- Store test credentials in fixture files (excluded from scanning)

### DON'T ❌
- Hardcode secrets in source code
- Use `eval()` or `exec()` with user input
- Use `os.system()` or `shell=True` in subprocess
- Trust user input without validation
- Use `pickle` for untrusted data
- Leave vulnerable dependencies unfixed

## Exemption Review

Security exemptions are reviewed:
- **Quarterly** - Expired temporary exemptions trigger new findings
- **On promotion** - All exemptions reviewed before moving to curated marketplace
- **Security audits** - Periodic review of all exempted findings

## Questions?

- **Security concerns:** Contact @security-team
- **False positives:** Add exemption and document in PR
- **Tool issues:** File an issue with the `security` label
