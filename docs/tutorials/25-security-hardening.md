<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# Tutorial 25 — Security Hardening

A practical guide to hardening agent deployments using the Agent Governance
Toolkit's built-in security tooling. This tutorial covers secret scanning,
dependency review, static analysis, fuzz testing, supply chain security, and
branch protection — everything you need to secure a production agent system.

> **Scope:** CI/CD security, dependency management, code analysis, fuzzing
> **Frameworks:** Gitleaks, Dependabot, CodeQL, ClusterFuzzLite, OpenSSF Scorecard
> **Audience:** Platform engineers and security teams deploying governed agents

---

## What You'll Learn

| Section | Topic |
|---------|-------|
| [Security Overview](#security-overview) | Defence-in-depth for agent systems |
| [Secret Scanning](#secret-scanning-with-gitleaks) | Prevent secrets from entering the repository |
| [Dependency Review](#dependency-review-and-dependabot) | Automated CVE scanning across 13 ecosystems |
| [CodeQL Analysis](#codeql-analysis) | Static analysis for Python and TypeScript |
| [Fuzz Testing](#fuzz-testing-with-clusterfuzzlite) | 7 fuzz targets for parser and policy code |
| [OpenSSF Scorecard](#openssf-scorecard) | Automated security scoring |
| [SBOM Generation](#sbom-generation) | SPDX and CycloneDX software bills of materials |
| [Branch Protection](#branch-protection-and-required-status-checks) | Enforcing CI gates |
| [Recommendations](#recommendations-for-production) | Production deployment checklist |

---

## Prerequisites

- A GitHub repository with GitHub Actions enabled
- Familiarity with CI/CD workflows
- Recommended: read [Tutorial 04 — Audit & Compliance](04-audit-and-compliance.md)

---

## Security Overview

The Agent Governance Toolkit uses a **defence-in-depth** approach with multiple
overlapping security layers:

```
  ┌─────────────────────────────────────────────────────┐
  │                   Branch Protection                 │
  │  ┌───────────────────────────────────────────────┐  │
  │  │              CI Security Gates                │  │
  │  │  ┌─────────────────────────────────────────┐  │  │
  │  │  │         Static Analysis (CodeQL)        │  │  │
  │  │  │  ┌───────────────────────────────────┐  │  │  │
  │  │  │  │     Dependency Review (Dependabot) │  │  │  │
  │  │  │  │  ┌─────────────────────────────┐  │  │  │  │
  │  │  │  │  │  Secret Scanning (Gitleaks) │  │  │  │  │
  │  │  │  │  │  ┌───────────────────────┐  │  │  │  │  │
  │  │  │  │  │  │   Fuzz Testing        │  │  │  │  │  │
  │  │  │  │  │  └───────────────────────┘  │  │  │  │  │
  │  │  │  │  └─────────────────────────────┘  │  │  │  │
  │  │  │  └───────────────────────────────────┘  │  │  │
  │  │  └─────────────────────────────────────────┘  │  │
  │  └───────────────────────────────────────────────┘  │
  └─────────────────────────────────────────────────────┘
```

---

## Secret Scanning with Gitleaks

Gitleaks detects hardcoded secrets (API keys, tokens, passwords) before they
reach the repository.

### How It Works

The toolkit includes a Gitleaks configuration that scans every commit for:
- API keys and tokens
- Connection strings
- Private keys
- Cloud credentials (AWS, Azure, GCP)

### CI Integration

```yaml
# .github/workflows/gitleaks.yml
name: Gitleaks Secret Scan
on: [push, pull_request]

jobs:
  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

### Local Pre-Commit Hook

Run Gitleaks locally before pushing:

```bash
# Install Gitleaks
brew install gitleaks  # macOS
# or download from https://github.com/gitleaks/gitleaks/releases

# Scan the repo
gitleaks detect --source . --verbose

# Scan only staged changes (pre-commit)
gitleaks protect --staged --verbose
```

### Allowlisting False Positives

Use the `.gitleaksignore` file for known false positives:

```
# .gitleaksignore
# Test fixtures with fake credentials
tests/fixtures/mock-credentials.json
```

> **Best practice:** Never add real secrets to the allowlist. Use environment
> variables or a secret manager instead.

---

## Dependency Review and Dependabot

The toolkit uses Dependabot to monitor dependencies across **13 ecosystems**:

| Ecosystem | Config File | Scope |
|-----------|-------------|-------|
| Python (pip) | `agent-governance-python/requirements/*.txt` | Core packages |
| Python (pip) | `*/requirements.txt` | Per-package |
| Node.js (npm) | `*/package.json` | TypeScript package |
| .NET (NuGet) | `*.csproj` | .NET package |
| Rust (Cargo) | `Cargo.toml` | Rust crate |
| Go (modules) | `go.mod` | Go module |
| GitHub Actions | `.github/workflows/*.yml` | CI/CD |
| Docker | `Dockerfile` | Container images |

### Dependabot Configuration

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: pip
    directory: "/"
    schedule:
      interval: weekly
    labels:
      - "dependencies"
      - "security"
    open-pull-requests-limit: 10

  - package-ecosystem: npm
    directory: "/agent-governance-typescript"
    schedule:
      interval: weekly

  - package-ecosystem: github-actions
    directory: "/"
    schedule:
      interval: weekly
```

### Dependency Confusion Prevention

The toolkit includes a script that checks for dependency confusion attacks:

```bash
python scripts/check_dependency_confusion.py
```

This verifies that internal package names don't conflict with public registries.

### Weekly Security Audit

A weekly workflow runs comprehensive dependency checks:

```yaml
# Runs every Monday at 08:00 UTC
on:
  schedule:
    - cron: '0 8 * * 1'
```

It checks for:
- Known CVEs in dependencies (via `safety` and `pip-audit`)
- Dependency confusion risks
- Weak cryptography usage (`hashlib.md5`, `hashlib.sha1`)
- Unsafe `pickle` usage in non-test code

---

## CodeQL Analysis

CodeQL performs deep static analysis to find security vulnerabilities in Python
and TypeScript code.

### Detected Vulnerability Classes

| Language | Vulnerabilities |
|----------|----------------|
| Python | SQL injection, command injection, path traversal, SSRF, XSS, unsafe deserialization |
| TypeScript | Prototype pollution, ReDoS, XSS, injection, insecure randomness |

### CI Integration

```yaml
# .github/workflows/codeql.yml
name: CodeQL Analysis
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'  # weekly

jobs:
  analyze:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    strategy:
      matrix:
        language: [python, javascript]
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
        with:
          languages: ${{ matrix.language }}
      - uses: github/codeql-action/analyze@v3
```

### Custom Queries

For agent-specific vulnerabilities, add custom CodeQL queries:

```ql
// queries/unsafe-tool-call.ql
import python

from Call call, Attribute attr
where
  attr = call.getFunc().(Attribute) and
  attr.getName() = "execute" and
  not exists(call.getArg(0).(StringLiteral))
select call, "Dynamic tool execution without static action name"
```

---

## Fuzz Testing with ClusterFuzzLite

The toolkit includes **7 fuzz targets** that test parser and policy code with
randomised inputs.

### Fuzz Targets

| Target | Component | Purpose |
|--------|-----------|---------|
| `fuzz_policy_parser` | Policy engine | Malformed YAML policy files |
| `fuzz_mcp_scanner` | MCP security | Malicious tool descriptions |
| `fuzz_prompt_injection` | Prompt guard | Adversarial prompt inputs |
| `fuzz_trust_scoring` | Trust manager | Edge-case trust calculations |
| `fuzz_audit_chain` | Audit logger | Hash-chain integrity under stress |
| `fuzz_identity` | Agent identity | Malformed DID and key inputs |
| `fuzz_context_budget` | Budget scheduler | Extreme allocation patterns |

### Running Fuzz Tests Locally

```bash
# Install the fuzzer
pip install atheris  # Python fuzzer

# Run a specific target
python -m pytest tests/fuzz/test_fuzz_policy.py -x --timeout=60
```

### CI Integration with ClusterFuzzLite

```yaml
# .github/workflows/fuzz.yml
name: ClusterFuzzLite
on:
  pull_request:
    branches: [main]

jobs:
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: google/clusterfuzzlite/actions/build_fuzzers@v1
        with:
          language: python
      - uses: google/clusterfuzzlite/actions/run_fuzzers@v1
        with:
          fuzz-seconds: 300
          mode: code-change
```

---

## OpenSSF Scorecard

The [OpenSSF Scorecard](https://securityscorecards.dev/) automatically scores
the repository's security posture across multiple dimensions.

### Scorecard Checks

| Check | What It Verifies |
|-------|-----------------|
| `Binary-Artifacts` | No checked-in binaries |
| `Branch-Protection` | Required reviews, status checks |
| `Code-Review` | All changes go through review |
| `Dangerous-Workflow` | No `pull_request_target` with secrets |
| `Dependency-Update-Tool` | Dependabot or Renovate configured |
| `Fuzzing` | Fuzz testing in CI |
| `License` | OSI-approved licence present |
| `Maintained` | Recent commits and issue responses |
| `Pinned-Dependencies` | Actions pinned to SHA |
| `SAST` | Static analysis (CodeQL) enabled |
| `Security-Policy` | SECURITY.md present |
| `Signed-Releases` | Release artifacts are signed |
| `Token-Permissions` | Minimal GitHub token permissions |
| `Vulnerabilities` | No known CVEs in dependencies |

### CI Integration

```yaml
# .github/workflows/scorecard.yml
name: OpenSSF Scorecard
on:
  push:
    branches: [main]
  schedule:
    - cron: '0 6 * * 1'

jobs:
  scorecard:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      id-token: write
    steps:
      - uses: actions/checkout@v4
      - uses: ossf/scorecard-action@v2
        with:
          results_file: scorecard-results.sarif
          publish_results: true
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: scorecard-results.sarif
```

---

## SBOM Generation

Software Bills of Materials (SBOMs) list every component in the software supply
chain. The toolkit generates both SPDX and CycloneDX formats.

### Automated SBOM Workflow

```yaml
# .github/workflows/sbom.yml (simplified)
name: SBOM Generation
on:
  release:
    types: [published]

jobs:
  sbom:
    runs-on: ubuntu-latest
    permissions:
      contents: write
      id-token: write
      attestations: write
    steps:
      - uses: actions/checkout@v4

      # Generate SPDX SBOM
      - uses: anchore/sbom-action@v0
        with:
          output-file: sbom.spdx.json
          format: spdx-json

      # Generate CycloneDX SBOM
      - uses: anchore/sbom-action@v0
        with:
          output-file: sbom.cdx.json
          format: cyclonedx-json

      # Attest SBOM to the release
      - uses: actions/attest-sbom@v2
        with:
          subject-path: sbom.spdx.json
```

For more details on SBOM signing and verification, see
[Tutorial 26 — SBOM and Signing](./26-sbom-and-signing.md).

---

## Branch Protection and Required Status Checks

### Recommended Branch Protection Rules

| Setting | Value | Reason |
|---------|-------|--------|
| Require pull request reviews | 1+ reviewers | Code review before merge |
| Dismiss stale reviews | Enabled | Re-review after changes |
| Require status checks | Enabled | CI must pass |
| Require branches up to date | Enabled | No stale merges |
| Require signed commits | Recommended | Commit integrity |
| Include administrators | Enabled | No bypass |

### Required Status Checks

Configure these as required status checks for pull requests:

```
✅ ci / lint
✅ ci / test-python
✅ ci / test-typescript
✅ ci / test-dotnet
✅ ci / security-scan
✅ gitleaks / scan
✅ codeql / analyze (python)
✅ codeql / analyze (javascript)
```

### Setting Up via GitHub CLI

```bash
# Enable branch protection
gh api repos/{owner}/{repo}/branches/main/protection \
  --method PUT \
  --field required_pull_request_reviews='{"required_approving_review_count":1}' \
  --field required_status_checks='{"strict":true,"contexts":["ci / test-python","ci / security-scan"]}' \
  --field enforce_admins=true
```

---

## Recommendations for Production

### Deployment Checklist

- [ ] **Secrets:** All secrets in a secret manager (Azure Key Vault, AWS
      Secrets Manager, HashiCorp Vault) — never in environment variables or
      config files
- [ ] **Gitleaks:** Running on every push and pull request
- [ ] **Dependabot:** Configured for all package ecosystems
- [ ] **CodeQL:** Running on push to main and weekly schedule
- [ ] **Fuzz testing:** Running on pull requests
- [ ] **SBOM:** Generated on every release
- [ ] **Branch protection:** Enabled with required reviews and status checks
- [ ] **Scorecard:** Running weekly with results published

### Security Scanning Script

The toolkit includes a built-in security scanner for plugin directories:

```bash
# Scan all packages with minimum severity of "high"
python scripts/security_scan.py . \
  --exclude-tests \
  --min-severity high \
  --format text
```

The scanner checks for:
- **Secrets** via `detect-secrets`
- **Python CVEs** via `pip-audit`
- **Node vulnerabilities** via `npm audit`
- **Dangerous code patterns** via `bandit`
- **Risky code snippets** in markdown skill files

Severity levels and blocking behaviour:

| Severity | Action |
|----------|--------|
| `critical` | Blocks merge |
| `high` | Blocks merge |
| `medium` | Warning only |
| `low` | Informational |

### Security Exemptions

For known false positives, create a `.security-exemptions.json`:

```json
{
  "version": "1.0",
  "exemptions": [
    {
      "tool": "detect-secrets",
      "category": "High Entropy String",
      "file": "tests/fixtures/mock-data.json",
      "reason": "Test fixture with fake data",
      "approved_by": "security-team",
      "ticket": "SEC-1234",
      "temporary": true,
      "expires": "2025-12-31"
    }
  ]
}
```

---

## Cross-Reference

| Concept | Tutorial |
|---------|----------|
| Audit trails | [Tutorial 04 — Audit & Compliance](./04-audit-and-compliance.md) |
| MCP security scanning | [Tutorial 07 — MCP Security Gateway](./07-mcp-security-gateway.md) |
| Compliance verification | [Tutorial 18 — Compliance Verification](./18-compliance-verification.md) |
| SBOM and signing | [Tutorial 26 — SBOM and Signing](./26-sbom-and-signing.md) |
| MCP scan CLI | [Tutorial 27 — MCP Scan CLI](./27-mcp-scan-cli.md) |
| Plugin marketplace security | [Tutorial 10 — Plugin Marketplace](./10-plugin-marketplace.md) |
| Shift-left governance | [Tutorial 45 — Shift-Left Governance](./45-shift-left-governance.md) |

---

## Next Steps

- **Run the Scorecard** locally to see your current security posture:
  ```bash
  scorecard --repo=github.com/your-org/your-repo
  ```
- **Enable Dependabot** for all package ecosystems in your repository
- **Add fuzz targets** for any custom parser or policy code
- **Configure branch protection** with the recommended settings above
- **Read Tutorial 26** ([SBOM and Signing](./26-sbom-and-signing.md)) for
  supply chain security
