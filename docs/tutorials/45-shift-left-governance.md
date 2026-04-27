<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# Tutorial 45: Shift-Left Governance

> **Time**: 25 minutes · **Level**: Intermediate · **Prerequisites**: Tutorial 01 (Policy Engine), Tutorial 25 (Security Hardening)

Catch governance violations before they reach production. This tutorial walks
through every layer of AGT's shift-left story: from pre-commit hooks that
validate policy files on your laptop, through PR-time gates that enforce
attestation and dependency review, to CI/CD checks that run security scans,
binary analysis, and supply chain verification on every build.

> **Scope:** commit-time, PR-time, CI/build-time, and release-time governance
> **Tools:** pre-commit hooks, GitHub Actions, GitHub CI workflows
> **Audience:** Platform engineers, DevOps teams, and security teams integrating AGT into their SDLC

---

## What You'll Learn

| Section | Topic |
|---------|-------|
| [Why Shift-Left?](#why-shift-left) | The case for catching violations before runtime |
| [Commit-Time](#commit-time-pre-commit-hooks) | Pre-commit hooks for policy and plugin validation |
| [PR-Time: Contributor Reputation](#pr-time-contributor-reputation) | Automated screening for coordinated inauthentic behavior |
| [PR-Time](#pr-time-gates) | Governance attestation, dependency review, secret scanning |
| [CI/Build-Time](#cibuild-time-checks) | Governance verify, policy validation, security scans, binary analysis |
| [Language-Specific Build Checks](#language-specific-build-time-enforcement) | .NET, TypeScript, Python build-time enforcement |
| [Release-Time](#release-time-gates) | SBOM generation, artifact signing, attestation |
| [Reference Architecture](#reference-architecture) | How all the pieces fit together |
| [Cross-Reference](#cross-reference) | Related tutorials |

---

## Why Shift-Left?

Most AGT tutorials focus on **runtime** governance: policy evaluation when an
agent acts, trust scoring when agents communicate, audit logging when decisions
are made. Runtime governance is essential, but it is the last line of defense.

Shift-left governance moves checks earlier in the development lifecycle:

```
  Commit        PR           CI/Build        Release        Runtime
    │            │              │               │              │
    ▼            ▼              ▼               ▼              ▼
```
  Contributor   Commit        PR           CI/Build        Release        Runtime
     │            │            │              │               │              │
     ▼            ▼            ▼              ▼               ▼              ▼
  ┌──────┐  ┌──────┐  ┌─────────┐  ┌────────────┐  ┌───────────┐  ┌──────────┐
  │reputa│  │ pre- │  │ attest  │  │ governance │  │ SBOM +    │  │ policy   │
  │tion  │  │commit│  │ + dep   │  │ verify +   │  │ signing + │  │ engine + │
  │check │  │hooks │  │ review  │  │ CodeQL +   │  │ provenance│  │ trust +  │
  │      │  │      │  │ + scans │  │ BinSkim    │  │           │  │ audit    │
  └──────┘  └──────┘  └─────────┘  └────────────┘  └───────────┘  └──────────┘
    Earliest feedback                                        Most comprehensive
```

**Why it matters:**

- A social engineering contributor caught at PR open never gets code reviewed
- A malformed policy file caught at commit time costs zero CI minutes
- A secret caught in PR review never reaches the default branch
- A dependency confusion attack blocked in CI never reaches production
- An unsigned artifact blocked at release time never reaches users

---

## Commit-Time: Pre-Commit Hooks

AGT ships three pre-commit hooks in `.pre-commit-hooks.yaml` and a
[rollout template](../operations/pre-commit-hook-template.md) with additional
quality gates.

### §1.1 Built-In Hooks

| Hook ID | What It Checks | Triggers On |
|---------|---------------|-------------|
| `validate-policy` | YAML/JSON policy file schema and structure | `*polic*.yaml`, `*polic*.yml`, `*polic*.json` |
| `validate-plugin-manifest` | Plugin manifest required fields and schema | `plugin.json`, `plugin.yaml` |
| `evaluate-plugin-policy` | Plugin manifests against a governance policy | `plugin.json`, `plugin.yaml` |

### §1.2 Setup

Add AGT as a pre-commit hook source in your `.pre-commit-config.yaml`:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/microsoft/agent-governance-toolkit
    rev: main  # pin to a release tag in production
    hooks:
      - id: validate-policy
      - id: validate-plugin-manifest
      - id: evaluate-plugin-policy
        args: ['--policy', 'policies/marketplace-policy.yaml']
```

Install and run:

```bash
pip install pre-commit
pre-commit install
pre-commit run --all-files   # validate existing files
```

### §1.3 Extended Quality Gates

The [pre-commit hook rollout template](../operations/pre-commit-hook-template.md)
adds governance-specific quality gates beyond schema validation:

| Hook | Purpose |
|------|---------|
| `agt-validate` | Runs `agent_os.cli validate --strict` on policy files |
| `agt-doctor` | Health check on pre-push (runs before pushing to remote) |
| `agency-json-required` | Ensures every plugin directory has an `agency.json` |
| `no-stubs` | Blocks `TODO`, `FIXME`, `HACK` markers in staged production code |
| `no-custom-crypto` | Blocks raw crypto imports outside security modules |
| `detect-secrets` | Secret scanning via Yelp's detect-secrets |

### §1.4 Phased Rollout

For teams adopting AGT incrementally:

1. **Week 1**: Install with `--permissive` mode, hooks warn but don't block
2. **Week 2**: Switch to `--strict` for policy validation only
3. **Week 3**: Enable all hooks as blocking
4. **Week 4**: Graduate to full blocking per the
   [graduation checklist](../operations/advisory-to-blocking-graduation.md)

---

## PR-Time: Contributor Reputation

The **leftmost** check in AGT's shift-left pipeline. Before reviewing code,
before running CI, the contributor reputation action screens the author's
GitHub profile for signals of coordinated inauthentic behavior.

### What It Detects

| Signal | Severity | Description |
|--------|----------|-------------|
| Following farming | MEDIUM/HIGH | Extreme following:follower ratios (e.g., 2000 following, 50 followers) |
| Repo velocity | MEDIUM/HIGH | Unnatural repo creation rate (e.g., 60 repos in 90 days) |
| Cross-repo spray | HIGH | Same issue template filed across dozens of repos in days |
| Credential laundering | HIGH | Citing merged PRs as credentials in spray issues across other repos |
| Governance theme concentration | MEDIUM | Repos overwhelmingly themed around governance/security topics |
| Network coordination | MEDIUM/HIGH | Shared forks, synchronized filing, co-comment patterns (opt-in) |

### Add It to Your Repo

AGT ships a reusable composite action. Add this workflow to any repository:

```yaml
# .github/workflows/contributor-check.yml
name: Contributor Reputation Check

on:
  pull_request_target:        # Use pull_request_target, not pull_request
    types: [opened]
  issues:
    types: [opened]

permissions:
  contents: read
  issues: write
  pull-requests: write

jobs:
  check:
    runs-on: ubuntu-latest
    if: github.actor != 'dependabot[bot]'
    steps:
      - name: Checkout AGT action
        uses: actions/checkout@v4
        with:
          repository: microsoft/agent-governance-toolkit
          sparse-checkout: |
            scripts
            .github/actions/contributor-check
          path: agt

      - name: Run contributor check
        uses: ./agt/.github/actions/contributor-check
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
          checks: profile,credential    # Add 'cluster' for deep analysis
          risk-threshold: MEDIUM        # MEDIUM or HIGH
```

### How It Works

1. **On every PR or issue open**, the action runs two checks (profile + credential audit) using only the GitHub REST API and Python stdlib. No dependencies to install.

2. **Risk is computed** as the max across all checks:
   - **LOW**: No action taken (silent pass)
   - **MEDIUM**: Posts a collapsible comment, adds `needs-review:MEDIUM` label
   - **HIGH**: Posts a detailed comment, adds `needs-review:HIGH` label

3. **Comments are idempotent**: re-runs update the same comment instead of creating duplicates. Old risk labels are removed before applying the current one.

4. **Cluster detection** (opt-in) maps coordination networks from a seed account via shared forks, co-comments, and synchronized filing. It is API-heavy and recommended only for manual dispatch investigations.

> **Important:** Use `pull_request_target` (not `pull_request`) so the action
> has write permissions to comment and label on fork PRs. Do not run untrusted
> PR code before this action in the same workflow.

---

## PR-Time Gates

When code reaches a pull request, three independent workflows enforce
governance before merge.

### §2.1 Governance Attestation

The **Governance Attestation** action (`action/governance-attestation/`)
validates that PR authors have completed a 7-section attestation checklist
covering security, privacy, CELA, responsible AI, accessibility, release
readiness, and org-specific launch gates.

```yaml
# .github/workflows/pr-governance.yml
name: PR Governance
on:
  pull_request:
    types: [opened, edited, synchronize]

jobs:
  attestation:
    runs-on: ubuntu-latest
    steps:
      - uses: microsoft/agent-governance-toolkit/action/governance-attestation@main
        with:
          required-sections: |
            1) Security review
            2) Privacy review
            3) CELA review
            4) Responsible AI review
            5) Accessibility review
            6) Release Readiness / Safe Deployment
            7) Org-specific Launch Gates
```

The action outputs:
- `status`: pass or fail
- `errors`: list of missing sections
- `sections-found`: JSON mapping of sections to checkbox counts

### §2.2 Dependency Review

AGT's dependency review workflow blocks PRs that introduce dependencies with
known CVEs or disallowed licences:

```yaml
# From .github/workflows/dependency-review.yml
- uses: actions/dependency-review-action@v4
  with:
    fail-on-severity: moderate
    comment-summary-in-pr: always
    allow-licenses: >
      MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC,
      PSF-2.0, Python-2.0, 0BSD, Unlicense, CC0-1.0,
      CC-BY-4.0, Zlib, BSL-1.0, MPL-2.0
```

This runs on every PR that touches dependency manifests and flags:
- Dependencies with moderate+ CVEs
- Dependencies with licences not on the allow list

### §2.3 Secret Scanning

The secret scanning workflow (`secret-scanning.yml`) runs on every PR to `main`
and weekly on schedule. It combines:

1. **Gitleaks** for pattern-based secret detection across the full git history
2. **High-entropy string scanning** for API keys, GitHub tokens, AWS keys,
   and Slack tokens using regex patterns

### §2.4 Supply Chain Checks

The supply chain check workflow (`supply-chain-check.yml`) runs when dependency
manifests change and enforces:

- **Exact version pinning**: no `^` or `~` version ranges in `package.json`
- **Lockfile presence**: every package with dependencies must have a lockfile

### §2.5 Quality Gates

The quality gates workflow (`quality-gates.yml`) runs on every PR and blocks
merge if:

| Gate | What It Catches |
|------|----------------|
| No stubs/TODOs | `TODO`, `FIXME`, `HACK` markers in production code |
| No unauthorized crypto | Raw crypto imports outside designated security modules |
| Security audit required | Changes to security-sensitive paths require audit documentation |
| Dependency audit trail | Vendored patches must have an audit trail |

These mirror the pre-commit hooks from [Section 1.3](#13-extended-quality-gates),
providing defense in depth: pre-commit catches issues at the developer's
machine, quality gates catch anything that bypasses hooks.

---

## CI/Build-Time Checks

Once a PR passes the gate workflows, the main CI pipeline and specialized
workflows perform deeper analysis.

### §3.1 Governance Verify Action

The **Agent Governance Verify** action (`action/action.yml`) is the primary
CI-time governance check. It runs the compliance CLI against your repository:

```yaml
# .github/workflows/governance-ci.yml
name: Governance CI
on: [push, pull_request]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: microsoft/agent-governance-toolkit/action@main
        with:
          command: all              # governance-verify + marketplace-verify + policy-evaluate
          policy-path: policies/    # path to policy files
          manifest-path: plugin.json
          output-format: json
          fail-on-warning: 'true'
```

The `command` input supports four modes:

| Command | What It Does |
|---------|-------------|
| `governance-verify` | Runs the full compliance verification suite |
| `marketplace-verify` | Validates a plugin manifest against marketplace requirements |
| `policy-evaluate` | Evaluates a specific policy against a context |
| `all` | Runs governance-verify, then marketplace-verify and policy-evaluate if paths are provided |

### §3.2 Security Scan Action

The **Security Scan** action (`action/security-scan/`) scans directories for
secrets, CVEs, and dangerous code patterns:

```yaml
- uses: microsoft/agent-governance-toolkit/action/security-scan@main
  with:
    paths: 'plugins/ scripts/'
    min-severity: high           # block on critical or high findings
    exemptions-file: .security-exemptions.json
```

Outputs include `findings-count`, `blocking-count`, and full `findings` in JSON
format, making it easy to integrate with dashboards or notification systems.

### §3.3 Policy Validation Workflow

The policy validation workflow (`policy-validation.yml`) triggers when any YAML
file or the policy engine source changes. It:

1. Discovers all policy files matching `*policy*` naming
2. Validates each file using `agent_os.policies.cli validate`
3. Runs policy CLI unit tests to verify evaluation behavior

This ensures that policy file changes don't break the policy engine.

### §3.4 CodeQL and Static Analysis

AGT uses CodeQL for semantic static analysis of Python and TypeScript code.
The CodeQL workflow (`codeql.yml`) runs on pushes and PRs, uploading SARIF
results to GitHub's security tab.

### §3.5 Dependency Confusion Scan

A dedicated CI job runs `scripts/check_dependency_confusion.py --strict` on
every build. This checks that:

- Internal package names don't collide with public PyPI/npm packages
- Notebook `pip install` commands only reference registered packages

### §3.6 Workflow Security Audit

When GitHub Actions workflow files change, a workflow security job scans for:

- Expression injection vulnerabilities (`${{ github.event.* }}` in `run:`)
- Overly permissive permissions
- Unpinned action references

### §3.7 .NET Binary Analysis (BinSkim)

For the .NET SDK, the CI pipeline runs Microsoft BinSkim binary analysis on
compiled assemblies:

```yaml
- name: BinSkim binary security analysis
  run: |
    dotnet tool install --global Microsoft.CodeAnalysis.BinSkim --version 4.*
    BinSkim analyze "src/AgentGovernance/bin/Release/net8.0/*.dll" \
      --output binskim-results.sarif --verbose
```

Results are uploaded as SARIF to GitHub's code scanning dashboard.

---

## Language-Specific Build-Time Enforcement

Each AGT SDK uses its language's native tooling to enforce governance standards
at compile time. These are implemented today in the repository.

### §4.1 .NET (Microsoft.AgentGovernance)

The `.NET` SDK enforces the strictest compile-time checks via MSBuild
properties in `Directory.Build.props` and `Directory.Build.targets`:

| Feature | Configuration | Effect |
|---------|--------------|--------|
| **Nullable reference types** | `<Nullable>enable</Nullable>` | Compiler warns on possible null dereference |
| **Warnings as errors** | `<TreatWarningsAsErrors>true</TreatWarningsAsErrors>` | All compiler warnings fail the build (packable projects) |
| **Strong-name signing** | `<SignAssembly>true</SignAssembly>` | Assemblies are signed with `AgentGovernance.snk` |
| **Deterministic builds** | `<ContinuousIntegrationBuild>true</ContinuousIntegrationBuild>` | Identical source produces identical binaries in CI |
| **SourceLink** | `Microsoft.SourceLink.GitHub` package | Users can step into AGT source when debugging |
| **Symbol packages** | `<IncludeSymbols>true</IncludeSymbols>` | `.snupkg` symbol packages published alongside NuGet packages |

These are enforced automatically for any project in the `agent-governance-dotnet/`
directory tree.

### §4.2 TypeScript (@microsoft/agentmesh-sdk)

The TypeScript SDK uses strict compiler settings in `tsconfig.json`:

| Feature | Configuration | Effect |
|---------|--------------|--------|
| **Strict mode** | `"strict": true` | Enables all strict type-checking options |
| **Consistent casing** | `"forceConsistentCasingInFileNames": true` | Prevents cross-platform filename issues |
| **Declaration files** | `"declaration": true` | Generates `.d.ts` files for consumers |
| **ESLint** | `@typescript-eslint/parser` + `@typescript-eslint/eslint-plugin` | Static analysis during build |

### §4.3 Python (agent-governance-python)

Python packages use typed package markers and static analysis tooling:

| Feature | Configuration | Effect |
|---------|--------------|--------|
| **py.typed marker** | `py.typed` file in package | Signals type-checker support to consumers |
| **mypy** | `tool.mypy` in `pyproject.toml` | Static type checking in dev/CI |
| **ruff** | `tool.ruff` in `pyproject.toml` | Fast Python linting, enforced in CI |

### §4.4 Recommended Extensions

The following patterns are not yet enforced in AGT's own CI but are recommended
for teams consuming AGT:

| Language | Tool | Purpose |
|----------|------|---------|
| Rust | `cargo clippy` | Lint-level warnings beyond `rustc` |
| Rust | `cargo deny` | Licence and vulnerability checks for dependencies |
| Go | `staticcheck` | Advanced static analysis beyond `go vet` |
| Go | `golangci-lint` | Aggregated linter suite |

---

## Release-Time Gates

Before artifacts reach users, the release pipeline adds a final layer of
verification. These are covered in depth by [Tutorial 26](26-sbom-and-signing.md),
but here is how they fit into the shift-left lifecycle:

| Gate | Tool | What It Produces |
|------|------|-----------------|
| SBOM generation | Anchore/Syft | SPDX and CycloneDX software bills of materials |
| Artifact signing | Sigstore (Python), ESRP (.NET) | Cryptographic proof of publisher identity |
| Build provenance | `actions/attest-build-provenance` | SLSA provenance attestation |
| SBOM attestation | `actions/attest-sbom` | Binds SBOM to the specific release artifact |
| OpenSSF Scorecard | `ossf/scorecard-action` | Automated security posture scoring |

---

## Reference Architecture

Here is how all the shift-left governance layers compose into a single pipeline:

```
Developer Machine          GitHub PR              CI Pipeline              Release
─────────────────          ─────────              ───────────              ───────
pre-commit hooks           Governance             Main CI                  SBOM
├─ validate-policy         attestation            ├─ lint (ruff, ESLint)   ├─ SPDX
├─ validate-plugin         ├─ 7-section           ├─ build (.NET, TS,      ├─ CycloneDX
│  -manifest               │  checklist           │  Rust, Go, Python)     │
├─ evaluate-plugin         │                      ├─ test (all SDKs)       Signing
│  -policy                 Dependency review      ├─ governance-verify     ├─ Sigstore
├─ agt-validate            ├─ CVE check           ├─ policy-validation     ├─ ESRP
├─ agt-doctor (pre-push)   ├─ licence check       ├─ CodeQL / SAST        │
├─ detect-secrets          │                      ├─ BinSkim (.NET)       Provenance
├─ no-stubs                Secret scanning        ├─ dependency-scan       ├─ SLSA
├─ no-custom-crypto        ├─ Gitleaks            ├─ workflow-security     ├─ SBOM
                           ├─ entropy scan        │                        │  attestation
                           │                      ├─ ci-complete gate      │
                           Supply chain check     │  (required status      Scorecard
                           ├─ version pinning     │   check)               └─ OpenSSF
                           ├─ lockfile presence   │
                           │                      Security scan action
                           Quality gates          ├─ secrets
                           ├─ no stubs            ├─ CVEs
                           ├─ no crypto           ├─ dangerous patterns
                           ├─ security audit
                           ├─ dep audit trail
```

### Required Status Checks

The CI pipeline uses a `ci-complete` gate job as a single required status check.
This job:

1. Runs `if: always()` regardless of skip conditions
2. Depends on all other CI jobs
3. Checks that no jobs failed (skipped is acceptable)
4. Reports a single pass/fail to branch protection

This pattern lets individual jobs skip based on path filters while still
enforcing that nothing that ran has failed.

---

## Cross-Reference

| Concept | Tutorial |
|---------|----------|
| Policy engine fundamentals | [Tutorial 01 -- Policy Engine](01-policy-engine.md) |
| CI/CD security tooling | [Tutorial 25 -- Security Hardening](25-security-hardening.md) |
| SBOM and artifact signing | [Tutorial 26 -- SBOM & Signing](26-sbom-and-signing.md) |
| MCP tool scanning | [Tutorial 27 -- MCP Scan CLI](27-mcp-scan-cli.md) |
| Multi-stage policy pipeline | [Tutorial 37 -- Multi-Stage Pipeline](37-multi-stage-pipeline.md) |
| .NET SDK | [Tutorial 19 -- .NET package](19-dotnet-sdk.md) |
| TypeScript SDK | [Tutorial 20 -- TypeScript package](20-typescript-sdk.md) |
| Plugin marketplace | [Tutorial 10 -- Plugin Marketplace](10-plugin-marketplace.md) |
| Pre-commit rollout template | [Operations: Pre-Commit Hook Template](../operations/pre-commit-hook-template.md) |

---

## Source Files

| Component | Location |
|-----------|----------|
| Pre-commit hooks | `.pre-commit-hooks.yaml` |
| Governance Verify action | `action/action.yml` |
| Security Scan action | `action/security-scan/action.yml` |
| Governance Attestation action | `action/governance-attestation/action.yml` |
| Policy validation workflow | `.github/workflows/policy-validation.yml` |
| Secret scanning workflow | `.github/workflows/secret-scanning.yml` |
| Dependency review workflow | `.github/workflows/dependency-review.yml` |
| Supply chain check workflow | `.github/workflows/supply-chain-check.yml` |
| Quality gates workflow | `.github/workflows/quality-gates.yml` |
| CI pipeline (all jobs) | `.github/workflows/ci.yml` |
| SBOM workflow | `.github/workflows/sbom.yml` |
| .NET build props | `agent-governance-dotnet/Directory.Build.props` |
| .NET build targets | `agent-governance-dotnet/Directory.Build.targets` |
| TS compiler config | `agent-governance-typescript/tsconfig.json` |
| TS ESLint config | `agent-governance-typescript/eslint.config.js` |
| Python package config | `agent-governance-python/agent-primitives/pyproject.toml` |
| Pre-commit rollout template | `docs/operations/pre-commit-hook-template.md` |

---

## Next Steps

- **Set up pre-commit hooks** in your repository using the
  [rollout template](../operations/pre-commit-hook-template.md)
- **Add the Governance Verify action** to your CI pipeline for automated
  compliance checks
- **Enable dependency review** to catch CVE and licence issues at PR time
- **Read Tutorial 25** ([Security Hardening](25-security-hardening.md)) for
  deeper coverage of CodeQL, fuzzing, and Scorecard
- **Read Tutorial 26** ([SBOM & Signing](26-sbom-and-signing.md)) for
  release-time artifact signing and SBOM attestation
