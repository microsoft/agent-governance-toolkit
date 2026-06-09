# Packages

AGT is a multi-language monorepo with Python packages, language SDKs, developer
tool integrations, ACS packages, and container images. The authoritative package
identity and migration table is [`../package-migration.md`](../package-migration.md).

AGT is proposed for AAIF hosting in `aaif/project-proposals#19`. Microsoft-origin
package names remain current compatibility names until registry ownership and
foundation package identities are finalized.

## Canonical package families

| Family | Purpose | Source |
|---|---|---|
| Python meta-package | Full AGT install and extras | `agent-governance-python/agent-compliance` |
| Python core | Policy engine, trust, audit, identity, runtime core | `agent-governance-python/agent-governance-toolkit-core` |
| Python integrations | Framework adapters | `agent-governance-python/agent-governance-toolkit-integrations` |
| Python CLI | Operator CLI, sandbox, SRE, MCP trust tooling | `agent-governance-python/agent-governance-toolkit-cli` |
| Python protocols | Protocol governance surfaces | `agent-governance-python/agent-governance-toolkit-protocols` |
| ACS | Stateless policy decision runtime and SDKs | `policy-engine/` |
| TypeScript SDK | Agent governance SDK and developer tooling packages | `agent-governance-typescript/`, `agent-governance-*cli/` |
| .NET SDK | .NET governance SDK and extensions | `agent-governance-dotnet/` |
| Rust SDK | `agentmesh`, `agentmesh-mcp`, ACS Rust crates | `agent-governance-rust/`, `policy-engine/` |
| Go SDK | Go governance SDK | `agent-governance-golang/` |
| OCI images | Runtime/service containers | `.github/workflows/publish-containers.yml` |

## Status labels

| Status | Meaning |
|---|---|
| Shipped | Released in a current package and covered by package-local validation. |
| Compatibility | Existing Microsoft-origin or legacy package identity retained temporarily. |
| Experimental | Runnable but not guaranteed stable. |
| Proposed | ADR/RFC/spec exists but implementation is not a shipped guarantee. |
| Vendor integration | Requires a vendor product, account, or platform. |

Package pages should use these labels when a capability is not part of the
canonical core release.

## Migration

Use [`../package-migration.md`](../package-migration.md) before changing package
names, install snippets, release workflow matrices, or registry metadata.
