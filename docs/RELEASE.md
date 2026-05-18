# Release Process

This document describes how the Agent Governance Toolkit ships releases across its multi-language SDK ecosystem.

## Versioning

All packages follow [Semantic Versioning 2.0.0](https://semver.org/):

- **MAJOR**: Breaking API changes (removed public classes, changed method signatures, incompatible config format changes)
- **MINOR**: New features, new packages, new CLI commands (backward-compatible)
- **PATCH**: Bug fixes, documentation corrections, dependency updates (backward-compatible)

Each SDK package is versioned independently. There is no monorepo-wide version number.

## Release Cadence

- **Regular releases**: As needed, typically 1-2 times per month
- **Security patches**: Released within 48 hours of confirmed vulnerability
- **Dependabot updates**: Merged continuously and included in the next release

## Supported Registries

| Ecosystem | Registry | Packages |
|-----------|----------|----------|
| Python | [PyPI](https://pypi.org/) | agent-os, agent-mesh, agent-compliance, agent-sre, agent-hypervisor, agent-runtime, agent-lightning, framework integrations (40+ packages) |
| TypeScript | [npm](https://www.npmjs.com/) | @agent-governance/\* |
| .NET | [NuGet](https://www.nuget.org/) | AgentGovernance.\* |
| Rust | [crates.io](https://crates.io/) | agent-governance-\* |
| Go | Go modules | github.com/microsoft/agent-governance-toolkit/agent-governance-go/\* |
| Containers | [GitHub Container Registry](https://ghcr.io) | trust-engine, policy-server, audit-collector, api-gateway, registry, relay, governance-sidecar |

## How to Create a Release

### 1. Pre-release Checklist

- [ ] All CI checks pass on `main` (CI, CodeQL, Secret Scanning, Scorecard)
- [ ] CHANGELOG.md is updated with notable changes
- [ ] No open security advisories or critical bugs
- [ ] Version numbers bumped in affected package manifests (`pyproject.toml`, `package.json`, `*.csproj`, `Cargo.toml`)

### 2. Create a GitHub Release

1. Go to [Releases](https://github.com/microsoft/agent-governance-toolkit/releases)
2. Click "Draft a new release"
3. Create a new tag following the pattern `v<MAJOR>.<MINOR>.<PATCH>` (e.g., `v0.8.0`)
4. Use the auto-generated release notes as a starting point, then edit for clarity
5. Mark as pre-release if appropriate (e.g., `v0.8.0-rc.1`)
6. Publish the release

### 3. Automated Publishing

Publishing is triggered automatically when a GitHub Release is published:

- **Python packages**: The `publish.yml` workflow builds wheels with provenance attestation, then publishes to PyPI
- **Container images**: The `publish-containers.yml` workflow builds and pushes multi-arch images to GHCR
- **.NET packages**: Built and published to NuGet via the CI pipeline
- **npm packages**: Built and published to npm via the CI pipeline

The `workflow_dispatch` trigger on `publish.yml` also allows publishing individual packages on demand.

### 4. Post-release

- Verify packages appear on their respective registries
- Verify container images are pullable: `docker pull ghcr.io/microsoft/agent-governance-toolkit/<component>:<tag>`
- Monitor for any regression reports in the first 24 hours

## Hotfix Process

For critical bugs or security issues in a released version:

1. Create a branch from the release tag: `git checkout -b hotfix/v0.8.1 v0.8.0`
2. Apply the minimal fix with tests
3. Follow the standard release process with a PATCH version bump
4. Cherry-pick the fix back to `main` if not already there

## Supply Chain Security

Every release includes:

- **SBOM generation**: Software Bill of Materials for all packages (`sbom.yml`)
- **Provenance attestation**: Build provenance via GitHub Attestations (Sigstore-based)
- **Dependency review**: Automated review of dependency changes on every PR
- **Secret scanning**: Pre-commit and CI scanning for leaked credentials
- **OpenSSF Scorecard**: Weekly scoring with SARIF upload to GitHub Security tab
