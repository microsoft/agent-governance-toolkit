# Security Scan GitHub Action

Automated security scanning for agent plugins and code using the Agent Governance Toolkit.

Scans for:
- 🔴 **Hardcoded secrets** (API keys, tokens, passwords)
- 🔴 **Dependency vulnerabilities** (CVEs in Python/Node packages)
- 🟡 **Dangerous code patterns** (eval, command injection, unsafe operations)
- 🟠 **Unsafe file operations** (path traversal, unrestricted writes)

## Quick Start

```yaml
- uses: microsoft/agent-governance-toolkit/action/security-scan@v2
  with:
    paths: 'plugins/'
```

## Usage Examples

### Basic plugin scan

```yaml
- name: Security Scan
  uses: microsoft/agent-governance-toolkit/action/security-scan@v2
  with:
    paths: 'plugins/my-plugin'
    plugin-name: 'my-plugin'
```

### Scan multiple directories

```yaml
- name: Security Scan
  uses: microsoft/agent-governance-toolkit/action/security-scan@v2
  with:
    paths: 'plugins/ scripts/'
```

### With custom severity threshold

```yaml
- name: Security Scan
  uses: microsoft/agent-governance-toolkit/action/security-scan@v2
  with:
    paths: 'plugins/'
    min-severity: 'critical'  # Only block on critical issues
```

### With exemptions file

```yaml
- name: Security Scan
  uses: microsoft/agent-governance-toolkit/action/security-scan@v2
  with:
    paths: 'plugins/'
    exemptions-file: '.security-exemptions.json'
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `paths` | Paths to scan (space-separated) | Yes | |
| `plugin-name` | Plugin name for error messages | No | (basename of first path) |
| `exemptions-file` | Path to exemptions JSON file | No | `.security-exemptions.json` |
| `min-severity` | Minimum severity to block (`critical`, `high`, `medium`, `low`) | No | `high` |
| `verbose` | Enable verbose output | No | `false` |
| `python-version` | Python version to use | No | `3.12` |
| `toolkit-version` | Toolkit version to install | No | (latest) |

## Outputs

| Output | Description |
|--------|-------------|
| `status` | `pass` or `fail` |
| `findings-count` | Total number of security findings |
| `blocking-count` | Number of blocking findings (critical/high) |
| `findings` | Security findings in text format |

## Severity Levels

| Severity | Emoji | Action | Examples |
|----------|-------|--------|----------|
| **Critical** | 🔴 | BLOCKS MERGE | Hardcoded secrets, RCE vulnerabilities, CVSS ≥ 9.0 |
| **High** | 🟡 | BLOCKS MERGE | CVE CVSS 7.0-8.9, command injection, SQL injection |
| **Medium** | 🟠 | Warning | CVE CVSS 4.0-6.9, weak crypto, missing validation |
| **Low** | 🟢 | Info | CVE CVSS < 4.0, best practice suggestions |

## Security Exemptions

Create `.security-exemptions.json` in your repository to suppress false positives:

```json
{
  "version": "1.0",
  "exemptions": [
    {
      "tool": "detect-secrets",
      "file": "tests/fixtures/mock_credentials.py",
      "line": 12,
      "reason": "Test fixture with intentionally fake credentials",
      "approved_by": "security-team"
    },
    {
      "tool": "pip-audit",
      "package": "requests",
      "version": "2.25.0",
      "cve": "CVE-2023-32681",
      "reason": "Not exploitable - only internal API calls",
      "temporary": true,
      "expires": "2026-06-30",
      "ticket": "ADO-67890"
    }
  ]
}
```

See [schema](../../agent-governance-python/agent-compliance/src/agent_compliance/security/schemas/security-exemptions.schema.json) for full format.

## Complete Workflow Example

```yaml
name: Security Scan

on:
  pull_request:
    paths: ['plugins/**', 'scripts/**']

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Security Scan
        uses: microsoft/agent-governance-toolkit/action/security-scan@v2
        with:
          paths: 'plugins/'
          exemptions-file: '.security-exemptions.json'
          verbose: 'true'
      
      - name: Comment on PR (on failure)
        if: failure()
        uses: actions/github-script@v7
        with:
          script: |
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: '❌ Security scan failed. Please review the findings and update your PR.'
            })
```

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

## Tools Used

| Tool | Purpose |
|------|---------|
| [detect-secrets](https://github.com/Yelp/detect-secrets) | Secret detection |
| [pip-audit](https://github.com/pypa/pip-audit) | Python CVE scanning |
| [npm audit](https://docs.npmjs.com/cli/v8/commands/npm-audit) | Node.js CVE scanning |
| [bandit](https://bandit.readthedocs.io/) | Python SAST |

## License

MIT License - see [LICENSE](../../LICENSE) for details.
