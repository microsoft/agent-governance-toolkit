# Publishing Guide

> [!IMPORTANT]
> **Community Preview Releases** — All packages currently published from this repository
> are community preview releases for testing and evaluation only. They are **not** official
> Microsoft-signed releases. The ESRP Release pipelines described below have been set up
> proactively and will be activated when official publishing approval is obtained.

This document describes the requirements for publishing packages from the
Agent Governance Toolkit to public registries.

## Python Packages (PyPI)

### Published Packages

| Package | PyPI Name | Directory |
|---------|-----------|-----------|
| Agent OS Kernel | `agent-os-kernel` | `packages/agent-os` |
| AgentMesh Platform | `agentmesh-platform` | `packages/agent-mesh` |
| Agent Hypervisor | `agent-hypervisor` | `packages/agent-hypervisor` |
| Agent Runtime | `agentmesh-runtime` | `packages/agent-runtime` |
| Agent SRE | `agent-sre` | `packages/agent-sre` |
| Agent Governance Toolkit | `agent-governance-toolkit` | `packages/agent-compliance` |
| Agent Lightning | `agent-lightning` | `packages/agent-lightning` |

### Publishing Method

All Python packages are published to PyPI via **ESRP Release** using an Azure
DevOps pipeline (`pipelines/pypi-publish.yml`).

> **⚠️ GitHub Actions Trusted Publishers are not used for PyPI publishing.**
> The GitHub Actions workflow (`.github/workflows/publish.yml`) builds and
> attests packages but does **not** publish them. Actual publishing goes
> through the ADO pipeline.

### Building Packages

```bash
# Install build tools
python -m pip install --upgrade pip build

# Build a specific package
cd packages/agent-os
python -m build
```

Each package produces:
- A wheel (`.whl`) — **required**
- A source distribution (`.tar.gz`) — recommended

### Package Metadata Requirements

All packages must include:
- **Author**: `Microsoft Corporation`
- **Contact email**: A team distribution list (not a personal email)
- **License**: MIT (with `License :: OSI Approved :: MIT License` classifier)
- **README**: `readme = "README.md"` in `pyproject.toml`

### Naming Conventions

- Do **not** start package names with `microsoft` or `windows` (reserved)
- If using `azure` branding, coordinate with the Azure SDK team
- All packages are published under the **microsoft** PyPI account

### Linux Wheels

For packages with native extensions targeting Linux, use `manylinux` tags
(e.g., `manylinux2014_x86_64`), **not** `linux_x86_64`.

## npm Packages

### Published Packages

All npm packages use the `@microsoft` scope.

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

### Publishing Method

All npm packages are published via **ESRP Release** using an Azure DevOps
pipeline (`pipelines/npm-publish.yml`).

> **⚠️ GitHub Actions is not used for npm publishing.**
> The GitHub Actions workflow builds and packs `.tgz` files but does **not**
> publish them. Actual publishing goes through the ADO pipeline.

### Building & Packing

```bash
cd packages/agent-mesh/sdks/typescript
npm ci
npm run build
npm pack
```

### Package Metadata Requirements

All packages must include:
- **Scope**: `@microsoft` (ESRP reserved scope)
- **Author**: `Microsoft Corporation`
- **License**: `MIT`
- **Repository**: pointing to `microsoft/agent-governance-toolkit`
- **`private`**: must **not** be set to `true`

### Naming Conventions

- Use the `@microsoft` scope for all publishable packages
- Avoid "shipping the org chart" — scope should reflect product, not team structure

## .NET Packages (NuGet)

The .NET SDK (`packages/agent-governance-dotnet`) is published to NuGet with
ESRP Authenticode and NuGet signing.

## Contact

- Python packaging questions: python@microsoft.com
- ESRP Release support: esrprelpm@microsoft.com
