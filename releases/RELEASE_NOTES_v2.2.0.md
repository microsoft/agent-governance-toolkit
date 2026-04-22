# Agent Governance Toolkit v2.2.0

> [!IMPORTANT]
> **Community Preview Release** — All packages published from this repository (PyPI, npm, NuGet)
> are **community preview releases** for testing and evaluation purposes only. They are **not**
> official Microsoft-signed releases. Official Microsoft-signed packages published via ESRP
> Release will be available in a future release.

## What's New

### ESRP Release Publishing Infrastructure

This release establishes the compliant publishing infrastructure required for future official
Microsoft-signed package releases:

- **PyPI publishing** migrated from GitHub Actions Trusted Publishers to Azure DevOps pipeline
  using `EsrpRelease@11` (`pipelines/pypi-publish.yml`)
- **npm publishing** pipeline created using `EsrpRelease@11` with `@microsoft` scope
  (`pipelines/npm-publish.yml`)
- **GitHub Actions** (`publish.yml`) now builds and attests packages only — actual publishing
  is done exclusively through ESRP Release ADO pipelines

### Package Metadata Compliance

All package metadata has been updated to align with Microsoft Python team and npm publishing
policies:

**Python (PyPI) — 7 packages:**
- Author updated to `Microsoft Corporation` with team distribution list email
- `Agent Governance Toolkit Team` added as maintainer across all packages
- License classifier (`License :: OSI Approved :: MIT License`) added where missing
- `Community Edition` prefix added to all package descriptions
- `agent-runtime` build fixed (proper re-export wrapper for `agent-hypervisor`)

**npm — 7 packages:**
- All scoped packages renamed to `@microsoft` (from `@agentmesh`, `@agent-os`, unscoped)
- Author set to `Microsoft Corporation` across all packages
- License corrected to MIT where mismatched (2 packages had `Apache-2.0`)
- Repository URLs corrected to `microsoft/agent-governance-toolkit`
- `Community Edition` prefix added to all package descriptions

**NuGet — 1 package:**
- Existing ESRP signing configuration retained

### Community Preview Disclaimers

Prominent disclaimers have been added to all user-facing documentation:

- Root README, CHANGELOG, PUBLISHING guide
- All 7 Python package READMEs
- All 3 npm package READMEs with user docs
- Both release notes (v1.0.0 and v2.1.0)
- PyPI and npm package descriptions (visible on registry pages)

### Publishing Documentation

- New `PUBLISHING.md` at repo root — public-facing guide covering PyPI, npm, and NuGet
  publishing requirements, metadata standards, and naming conventions
- ADO pipeline configurations with placeholder ESRP values ready for onboarding

## Packages

### Python (PyPI)

| Package | Version | Status |
|---------|---------|--------|
| `agent-os-kernel` | 2.2.0 | Community Preview |
| `agentmesh-platform` | 2.2.0 | Community Preview |
| `agent-hypervisor` | 2.2.0 | Community Preview |
| `agent-runtime` | 2.2.0 | Community Preview |
| `agent-sre` | 2.2.0 | Community Preview |
| `agent-governance-toolkit` | 2.2.0 | Community Preview |
| `agent-lightning` | 2.2.0 | Community Preview |

### npm

| Package | Version | Status |
|---------|---------|--------|
| `@microsoft/agentmesh-sdk` | 1.0.0 | Community Preview |
| `@microsoft/agentmesh-mcp-proxy` | 1.0.0 | Community Preview |
| `@microsoft/agentos-mcp-server` | 1.0.1 | Community Preview |
| `@microsoft/agentmesh-copilot-governance` | 0.1.0 | Community Preview |
| `@microsoft/agentmesh-mastra` | 0.1.0 | Community Preview |
| `@microsoft/agentmesh-api` | 0.1.0 | Community Preview |
| `@microsoft/agent-os-copilot-extension` | 1.0.0 | Community Preview |

### NuGet

| Package | Version | Status |
|---------|---------|--------|
| `Microsoft.AgentGovernance` | 2.2.0 | Community Preview |

## What's Coming

- Official Microsoft-signed releases via ESRP Release (pending onboarding approval)
- PyPI package ownership transfer to `microsoft` account
- npm `@microsoft` scope activation via ESRP
- NuGet Authenticode + NuGet package signing

## Full Changelog

See [CHANGELOG.md](CHANGELOG.md) for the complete list of changes.
