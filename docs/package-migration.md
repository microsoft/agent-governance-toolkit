---
title: "Package identity and migration map"
last_reviewed: 2026-10-03
owner: agt-maintainers
---

# Package identity and migration map

AGT is proposed for AAIF hosting in `aaif/project-proposals#19`. This map records
the package identity transition from Microsoft-origin names to canonical
foundation-operable package identities.

Do not change a package manifest, release matrix, or install snippet without
updating this file.

ACS is maintained separately in
[`responsibleai/agent-control-spec`](https://github.com/responsibleai/agent-control-spec).
Its published packages are `agent-control-spec` on PyPI and crates.io,
`@responsibleai/agent-control-spec` on npm, and
`ResponsibleAI.AgentControlSpec` on NuGet. AGT's similarly named packages below
retain its host APIs and are not the canonical upstream SDKs. Registry
ownership proposals in this map do not rename upstream ACS packages.

## Status vocabulary

| Status | Meaning |
|---|---|
| Canonical | The package identity intended for foundation-owned releases. |
| Compatibility | Existing package name retained temporarily for users. |
| Deprecated | Package name should not be recommended for new users. |
| Pending transfer | Registry ownership or namespace depends on AAIF/LF account setup. |

## Python / PyPI

| Canonical package | Current or legacy name | Source path | Migration action |
|---|---|---|---|
| `agent-governance-toolkit` | same | `agent-governance-python/agent-compliance` | Keep as meta-package. |
| `agent-governance-toolkit-core` | `agent-os-kernel`, `agentmesh-platform`, `agentmesh-primitives`, `agentmesh-runtime`, `agent-hypervisor` | `agent-governance-python/agent-governance-toolkit-core` | Publish canonical package; old names become dependency-only stubs. |
| `agent-governance-toolkit-integrations` | framework-specific `agentmesh-*` / `*-agentmesh` packages | `agent-governance-python/agent-governance-toolkit-integrations` | Publish canonical integrations package; old names become dependency-only stubs or documented extras. |
| `agent-governance-toolkit-cli` | `agent-sre`, `agent-sandbox`, MCP trust/proxy packages | `agent-governance-python/agent-governance-toolkit-cli` | Publish canonical CLI package; old names become stubs where published. |
| `agent-governance-toolkit-protocols` | `agent-mcp-governance`, protocol-specific packages | `agent-governance-python/agent-governance-toolkit-protocols` | Publish canonical protocol package; old names become stubs where published. |
| `agent-control-specification` | same | `policy-engine/sdk/python` | Retain AGT's compatibility Python host SDK. |
| `agt-policies` | same | `agent-governance-python/agt-policies` | Keep canonical ACS/AGT policy package. |
| `acs-generator` | same | `policy-engine/generator` | Keep canonical generator package. |

## npm

| Canonical package | Current Microsoft-origin name | Source path | Migration action |
|---|---|---|---|
| `@aaif/agent-governance-sdk` | `@microsoft/agent-governance-sdk` | `agent-governance-typescript` | Create foundation scope package; retain Microsoft package as compatibility wrapper during migration. |
| `@aaif/agent-governance-copilot-cli` | `@microsoft/agent-governance-copilot-cli` | `agent-governance-copilot-cli` | Vendor integration package; retain Microsoft package only as compatibility wrapper. |
| `@aaif/agent-governance-claude-code` | `@microsoft/agent-governance-claude-code` | `agent-governance-claude-code` | Vendor integration package; retain Microsoft package only as compatibility wrapper. |
| `@aaif/agent-governance-opencode` | `@microsoft/agent-governance-opencode` | `agent-governance-opencode` | Vendor integration package; retain Microsoft package only as compatibility wrapper. |
| `@aaif/agent-governance-antigravity-cli` | `@microsoft/agent-governance-antigravity-cli` | `agent-governance-antigravity-cli` | Vendor integration package; retain Microsoft package only as compatibility wrapper. |
| `agent-control-specification` | same | `policy-engine/sdk/node` | Retain AGT's compatibility Node host SDK. |
| `agent-control-specification-*` | same | `policy-engine/sdk/node/npm/*` | Keep platform package names unless AAIF chooses scoped ACS packages. |

## NuGet

| Canonical package | Current Microsoft-origin name | Source path | Migration action |
|---|---|---|---|
| `AgentGovernance` | `Microsoft.AgentGovernance` | `agent-governance-dotnet/src/AgentGovernance` | Publish neutral package; keep Microsoft ID only as compatibility package if needed. |
| `AgentGovernance.Extensions.ModelContextProtocol` | `Microsoft.AgentGovernance.Extensions.ModelContextProtocol` | `agent-governance-dotnet/src/AgentGovernance.Extensions.ModelContextProtocol` | Publish neutral package; keep Microsoft ID only as compatibility package if needed. |
| `AgentGovernance.Extensions.Microsoft.Agents` | `Microsoft.AgentGovernance.Extensions.Microsoft.Agents` | `agent-governance-dotnet/src/AgentGovernance.Extensions.Microsoft.Agents` | Vendor-specific integration; publish only if AAIF accepts the package identity. |
| `AgentControlSpecification*` | same | `policy-engine/sdk/dotnet/src/*` | Retain AGT's compatibility .NET host and adapter packages. |

## Rust / crates.io

| Canonical crate | Source path | Migration action |
|---|---|---|
| `agentmesh` | `agent-governance-rust/agentmesh` | Transfer crate ownership to foundation release managers. |
| `agentmesh-mcp` | `agent-governance-rust/agentmesh-mcp` | Transfer crate ownership to foundation release managers. |
| `agent_control_specification_core` | `policy-engine/core` | Deprecated compatibility shim over the separately published `agent-control-spec` engine. |
| `agent_control_specification` | `policy-engine/sdk/rust` | Retain AGT's Rust host SDK over the upstream engine. |

## Go

| Canonical module path | Current module path | Source path | Migration action |
|---|---|---|---|
| `github.com/aaif/agent-governance-toolkit/agent-governance-golang` | `github.com/microsoft/agent-governance-toolkit/agent-governance-golang` | `agent-governance-golang` | Change only after repository transfer; document import migration clearly. |

## OCI images

| Canonical image family | Current image family | Source | Migration action |
|---|---|---|---|
| `ghcr.io/microsoft/agent-governance-toolkit/<component>` | `ghcr.io/microsoft/agentmesh/<component>` | `.github/workflows/publish-containers.yml` | Publish canonical images under foundation owner; keep old paths only as temporary compatibility aliases if needed. |

Components:

- `trust-engine`
- `policy-server`
- `audit-collector`
- `api-gateway`
- `registry`
- `relay`
- `governance-sidecar`

## Validation

After package identity changes, run:

```bash
rg "@microsoft/|Microsoft.AgentGovernance|ghcr.io/microsoft|microsoft.github.io" README.md docs
rg "agent-os-kernel|agentmesh-platform|agentmesh-runtime|agentmesh-marketplace|agentmesh-lightning" README.md docs
rg "agent-governance-go|agent-governance-golang" README.md docs
```
