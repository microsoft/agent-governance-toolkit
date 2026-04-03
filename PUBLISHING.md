# Publishing Guide

> [!IMPORTANT]
> **Public Preview Releases** — All packages published from this repository
> are Microsoft-signed public preview releases. Publishing follows Microsoft's
> centralized publishing policies. **Do NOT publish from personal accounts.**

This document describes the requirements and compliance policies for publishing
packages from the Agent Governance Toolkit to public registries.

For all registries, the approved path is **ESRP Release** via Azure DevOps
pipelines (`pipelines/esrp-publish.yml`) unless noted otherwise.

> [!WARNING]
> **GitHub Packages** is not an approved general-purpose package registry for
> Microsoft official releases. Publish to the official registries (PyPI,
> npmjs.com, NuGet.org, crates.io, MCR). GitHub Packages may only be used for
> interim/nightly builds or basic engineering assets, not official releases.
> All official releases must be code signed via ESRP per SDL requirements.

---

## Python Packages (PyPI)

### Policy

All Python packages are published via **ESRP Release** — the only approved
method for publishing under the Microsoft PyPI account. Personal/team accounts
must not be used. See [ESRP Onboarding](https://aka.ms/esrp-onboarding).

- Packages show **"Microsoft"** as the maintainer (not individuals)
- Use a team distribution list as the email contact in metadata
- Do **not** start package names with `microsoft` or `windows` (reserved)
- If using `azure` branding, coordinate with the Azure SDK team
- GitHub Actions Trusted Publishers are **not** used for PyPI publishing

> **To delete or yank a package** published via ESRP, contact the Python team.

### Published Packages

| Package | PyPI Name | Directory |
|---------|-----------|-----------|
| Agent OS Kernel | `agent-os-kernel` | `packages/agent-os` |
| AgentMesh Platform | `agentmesh-platform` | `packages/agent-mesh` |
| Agent Hypervisor | `agent-hypervisor` | `packages/agent-hypervisor` |
| Agent Runtime | `agentmesh-runtime` | `packages/agent-runtime` |
| Agent SRE | `agent-sre` | `packages/agent-sre` |
| Agent Governance Toolkit | `agent-governance-toolkit` | `packages/agent-compliance` |
| Agent Lightning | `agentmesh-lightning` | `packages/agent-lightning` |

### Building Packages

```bash
python -m pip install --upgrade pip build
cd packages/agent-os
python -m build
```

Each package produces a wheel (`.whl`, **required**) and source distribution (`.tar.gz`).

### Metadata Requirements

- **Author**: `Microsoft Corporation`
- **Contact email**: Team distribution list (not personal)
- **License**: MIT with `License :: OSI Approved :: MIT License` classifier
- **README**: `readme = "README.md"` in `pyproject.toml`
- For Linux wheels with native extensions, use `manylinux` tags

### Conda

Conda packages may be published to the `microsoft` channel on
[anaconda.org](https://anaconda.org/microsoft) using the separate Conda process:

1. Build with `conda-build`; ensure packages work with Anaconda `defaults` channel only
2. Fill out the [online form](https://aka.ms/conda-publish) to request initial publish approval
3. Generate an API token at `anaconda.org/<USERNAME>/settings/access`
4. Publish: `anaconda --token <TOKEN> upload --user microsoft <FILES>`

Avoid depending on packages only available on `conda-forge`, as this may block
enterprise adoption. Join the **PyPI Package Owners** group on idweb for notifications.

---

## npm Packages

### Policy

All `@microsoft`-scoped npm packages are published via **ESRP Release**.
Individual/direct publishing to the `@microsoft` scope is not permitted.
See [ESRP Onboarding](https://aka.ms/esrp-onboarding).

- Packages show **"Microsoft"** as maintainer (not individuals)
- Use a team distribution list in package metadata
- Do **not** create new npm scopes without OSS Exec Council approval
- Internal packages should use the `@msinternal` scope on Azure Artifacts
- GitHub Actions is **not** used for npm publishing

> **To unpublish or deprecate**, contact `npmjs-admin@microsoft.com` with subject
> `[Package Name] NPM Package Deletion/Deprecation`. SLA: 48 hours.

### Official Microsoft npm Scopes

Only the `@microsoft` scope is used by this repository. Do not create new scopes.
See the full list of Microsoft-controlled scopes: `@microsoft`, `@azure`,
`@msinternal`, `@ospo`, `@vscode`, and others managed by specific teams.

### Published Packages

| Package | npm Name | Directory |
|---------|----------|-----------|
| AgentMesh Copilot Governance | `@microsoft/agentmesh-copilot-governance` | `packages/agentmesh-integrations/copilot-governance` |
| AgentMesh Mastra | `@microsoft/agentmesh-mastra` | `packages/agentmesh-integrations/mastra-agentmesh` |
| AgentMesh API | `@microsoft/agentmesh-api` | `packages/agent-mesh/services/api` |
| AgentMesh MCP Proxy | `@microsoft/agentmesh-mcp-proxy` | `packages/agent-mesh/packages/mcp-proxy` |
| AgentMesh SDK | `@microsoft/agentmesh-sdk` | `packages/agent-mesh/sdks/typescript` |
| Agent OS Copilot Extension | `@microsoft/agent-os-copilot-extension` | `packages/agent-os/extensions/copilot` |
| AgentOS MCP Server | `@microsoft/agentos-mcp-server` | `packages/agent-os/extensions/mcp-server` |

The VS Code and Cursor extensions are published via their respective marketplaces,
not npm.

### Building & Packing

```bash
cd packages/agent-mesh/sdks/typescript
npm ci
npm run build
npm pack
```

### Metadata Requirements

- **Scope**: `@microsoft` (ESRP reserved)
- **Author**: `Microsoft Corporation`
- **License**: `MIT`
- **Repository**: pointing to `microsoft/agent-governance-toolkit`
- **`private`**: must **not** be set to `true`

---

## .NET Packages (NuGet)

### Policy

NuGet packages are published following the process at [aka.ms/nuget](https://aka.ms/nuget).
Publishing uses the ADO pipeline (`pipelines/esrp-publish.yml` with target `nuget`).

- GitHub Actions is **not** used for NuGet publishing
- Follow Microsoft's NuGet signing and namespace reservation requirements
- Packages are published under the `Microsoft.AgentGovernance` namespace

### Published Packages

| Package | NuGet Name | Directory |
|---------|------------|-----------|
| Agent Governance .NET SDK | `Microsoft.AgentGovernance` | `packages/agent-governance-dotnet` |

---

## Rust Crate (crates.io)

### Policy

The Rust crate is published to [crates.io](https://crates.io) via **ESRP Release**
using the ADO pipeline (`pipelines/esrp-publish.yml` with target `rust`).
All crates are published under the official
[`microsoft-oss-releases`](https://crates.io/users/microsoft-oss-releases) account.

- Personal `cargo publish` with `CARGO_REGISTRY_TOKEN` is **not** used
- ESRP handles code signing, malware scanning, and code archival
- Crates must be packaged as `.crate` files via `cargo package`

> **To yank a crate**, file an IcM incident with the ESRP Release team.
> Programmatic yanking is not currently supported.

### Published Packages

| Package | Crate Name | Directory |
|---------|------------|-----------|
| AgentMesh Rust SDK | `agentmesh` | `packages/agent-mesh/sdks/rust/agentmesh` |

### Prerequisites

- ESRP Release onboarding completed (same as PyPI/npm)
- Crate is published under the `microsoft-oss-releases` crates.io account
- No additional secrets needed beyond the shared ESRP configuration

### Building Locally

```bash
cd packages/agent-mesh/sdks/rust/agentmesh
cargo build --release
cargo test --release
cargo package --list   # preview what gets published
```

### Metadata Requirements

- **License**: `MIT`
- **Repository**: pointing to `microsoft/agent-governance-toolkit`
- **`rust-version`**: minimum supported Rust version (currently `1.70`)
- **Keywords**: max 5 in `Cargo.toml`
- **Categories**: valid crates.io categories

### Version Bumping

Update `version` in `Cargo.toml` before publishing. crates.io does not allow
re-publishing the same version.

---

## Go Module

### Policy

Go modules are published via the [Go module proxy](https://proxy.golang.org).
No explicit upload is needed — the proxy indexes modules automatically when a
matching git tag is pushed.

The ADO pipeline (`pipelines/esrp-publish.yml` with target `go`) builds, tests,
and tags the module.

### Published Packages

| Package | Module Path | Directory |
|---------|-------------|-----------|
| AgentMesh Go SDK | `github.com/microsoft/agent-governance-toolkit/sdks/go` | `packages/agent-mesh/sdks/go` |

### Tag Format

Go modules in subdirectories require a tag prefixed with the module's path:

```
packages/agent-mesh/sdks/go/v0.1.0
```

### Building & Testing Locally

```bash
cd packages/agent-mesh/sdks/go
go build ./...
go vet ./...
go test -v -race ./...
```

### Triggering Proxy Indexing

After pushing a tag:

```bash
GOPROXY=https://proxy.golang.org GO111MODULE=on \
  go get github.com/microsoft/agent-governance-toolkit/sdks/go@v0.1.0
```

---

## Docker Containers (MCR)

### Policy

Docker images must be published through the **Microsoft Container Registry (MCR)**.
Do **not** publish containers to GitHub Container Registry, GitHub Packages, or
DockerHub directly. Follow onboarding at [aka.ms/mcr/onboarding](https://aka.ms/mcr/onboarding).

### Dockerfiles in This Repository

| Image | Dockerfile | Purpose |
|-------|-----------|---------|
| Agent OS | `packages/agent-os/Dockerfile` | Core governance runtime |
| Copilot Extension | `packages/agent-os/extensions/copilot/Dockerfile` | GitHub Copilot extension |
| MCP Server | `packages/agent-os/extensions/mcp-server/Dockerfile` | MCP server for Claude Desktop |
| Cloud Board | `packages/agent-os/services/cloud-board/Dockerfile` | Cloud board service |
| CMVK | `packages/agent-os/modules/cmvk/Dockerfile` | Cross-Model Verification Kernel |
| IATP | `packages/agent-os/modules/iatp/Dockerfile` | Inter-Agent Trust Protocol |
| IATP Sidecar (Go) | `packages/agent-os/modules/iatp/sidecar/go/Dockerfile` | Go trust sidecar |
| Control Plane | `packages/agent-os/modules/control-plane/Dockerfile` | Agent control plane |
| SCAK | `packages/agent-os/modules/scak/Dockerfile` | Safety-Critical Agent Kernel |
| CaaS | `packages/agent-os/modules/caas/Dockerfile` | Compliance as a Service |

### Image Requirements

- **Automated builds** — images must be built via CI, not manually pushed
- **Regular updates** — rebuild at least monthly to pick up base image patches
- **Tags** — use semver (`1.0.0`, `1.0`, `1`, `latest`) with suffix variants (e.g., `-alpine`)
- **Labels** — include at minimum:
  - `org.label-schema.vendor=Microsoft`
  - `org.label-schema.url` — where users can find info about the image
  - `org.label-schema.vcs-url` — source code URL
  - `org.label-schema.version`
  - `org.label-schema.build-date`
- **HEALTHCHECK** — include in Dockerfile for CI validation
- **Link Dockerfile** — MCR description must link to the source Dockerfile

### Best Practices

- Combine `RUN` lines to reduce layers; use `\` for readability
- Use `CMD` and/or `ENTRYPOINT` appropriately
- Reference: [Dockerfile best practices](https://docs.docker.com/engine/userguide/eng-image/dockerfile_best-practices/)

---

## Linux Packages (PMC)

### Policy

Linux-native packages (`.rpm`, `.deb`) are published through
**packages.microsoft.com (PMC)**. See [aka.ms/pmcrepo](https://aka.ms/pmcrepo)
for onboarding and publishing guidance.

This repository does not currently publish Linux packages, but if needed in
the future, follow the PMC onboarding process.

---

## Pipeline Overview

The unified ESRP pipeline (`pipelines/esrp-publish.yml`) supports these targets:

| Target | Registry | Method |
|--------|----------|--------|
| `pypi` | PyPI | ESRP Release |
| `npm` | npmjs.com (`@microsoft`) | ESRP Release |
| `nuget` | NuGet.org | DotNetCoreCLI push |
| `rust` | crates.io | ESRP Release |
| `go` | proxy.golang.org | Git tag |
| `all` | All of the above | — |

Use `dryRun=true` for build-only validation without publishing.

---

## Contact

| Topic | Contact |
|-------|---------|
| Python / PyPI / Conda | python@microsoft.com |
| npm scope management | npmjs-admin@microsoft.com |
| NuGet publishing | [aka.ms/nuget](https://aka.ms/nuget) |
| ESRP Release support | esrprelpm@microsoft.com |
| Malicious package reports | malicioss@microsoft.com |
| MCR / Container onboarding | [aka.ms/mcr/onboarding](https://aka.ms/mcr/onboarding) |
| Linux packages (PMC) | [aka.ms/pmcrepo](https://aka.ms/pmcrepo) |
| General OSS questions | oss@microsoft.com |
