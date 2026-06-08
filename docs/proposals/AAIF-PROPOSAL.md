# AAIF Technical Project Proposal

## Agent Governance Toolkit - Runtime Governance for Agentic AI

**Proposed by:** Microsoft (`microsoft/agent-governance-toolkit`)
**Requested stage:** AAIF Growth review
**License:** MIT
**Primary contact:** Agent Governance Toolkit Team (`agentgovtoolkit@microsoft.com`)
**Proposal state:** Submitted as `aaif/project-proposals#19`; the public issue is open, labeled `Growth`, `Paperwork-in-review`, and `contribution-agreement/unsigned`.

AGT is proposed for AAIF hosting. Do not describe the project as donated until Technical Committee approval, Governing Board approval, governance finalization, and contribution agreement execution are complete.

---

## 1. Project summary

Agent Governance Toolkit (AGT) is an open-source, multi-language runtime governance toolkit for agentic AI systems. It provides policy evaluation, identity and trust primitives, audit and observability patterns, MCP governance components, release provenance, and SDKs/integrations that help agent frameworks enforce organizational and safety policy before actions execute.

AGT is framework-neutral: Microsoft integrations remain supported, but the canonical project scope is not tied to Microsoft Agent Framework, Microsoft security intake, Azure DevOps ESRP, or Microsoft-owned release infrastructure.

## 2. Problem statement

Agent frameworks can call tools, delegate tasks, spawn sub-agents, and take externally visible actions, but many production deployments still lack a consistent runtime control plane:

- policy decisions are often embedded in agent prompts or framework callbacks instead of an auditable policy path;
- tool and MCP server access is difficult to govern consistently across frameworks;
- agent identity, delegation, trust, and audit records are fragmented;
- reliability controls such as SLOs, error budgets, circuit breakers, and replay are rarely designed for non-deterministic agent workflows;
- package and deployment artifacts need provenance that foundation maintainers can operate without vendor-specific release systems.

AGT addresses those gaps by supplying reusable governance components and release practices that can be embedded by runtimes, gateways, CLIs, SDKs, and framework adapters.

## 3. Repository scope

AGT is a whole-repository donation candidate, not a core-only extraction. The repository includes:

| Area | Path | Purpose |
|---|---|---|
| Python governance packages | `agent-governance-python/` | Agent OS, AgentMesh, compliance CLI, SRE, runtime, discovery, marketplace, integrations, and consolidated Python packages. |
| Agent Control Specification | `policy-engine/` | Policy engine, ACS SDKs, generator, schemas, specs, and conformance assets. |
| TypeScript SDK and tools | `agent-governance-typescript/`, `agent-governance-*cli/` | SDK, CLI governance integrations, and developer-tool packages. |
| .NET SDK | `agent-governance-dotnet/` | `Microsoft.AgentGovernance*` compatibility packages and .NET integration surfaces. |
| Rust SDK | `agent-governance-rust/` | `agentmesh` and `agentmesh-mcp` crates plus Rust governance APIs. |
| Go SDK | `agent-governance-golang/` | Go module for AGT integrations. |
| Docs, examples, demos | `docs/`, `examples/` | Architecture, package docs, security docs, tutorials, worked examples, and dashboards. |
| Release and security automation | `.github/workflows/` | CI, release, SBOM, provenance, docs, and security gates. |

## 4. Architecture

AGT is organized as a layered governance stack. Individual deployments can adopt one layer or use the full toolkit.

```text
Agent / Framework / MCP Client
        |
        v
Governance integration
  - SDK middleware
  - MCP proxy or server wrapper
  - CLI/tooling adapter
        |
        v
Core governance services
  - policy evaluation
  - identity and trust
  - audit and receipt generation
  - SLO, error-budget, and incident signals
        |
        v
Protected tools, services, agents, and registries
```

The current implementation includes:

- **Agent OS / policy evaluation:** deterministic action checks, policy templates, MCP governance paths, and audit patterns;
- **AgentMesh:** agent identity, trust scoring, protocol bridges, registry patterns, and MCP/A2A/IATP integration points;
- **Agent SRE:** SLOs, error budgets, cost guards, circuit breakers, progressive delivery, replay, and incident workflows;
- **Agent Runtime / sandboxing:** runtime supervision and isolation surfaces where integrated;
- **ACS:** policy schema, generator, SDKs, and conformance assets;
- **SDKs and integrations:** Python, TypeScript, .NET, Rust, Go, and framework/tool adapters.

Security claims are scoped to calls routed through AGT integration points. Direct access outside the configured governance path still requires operator controls such as gateway, network, process, container, or sandbox policy.

## 5. Package identity and release posture

The package identity source of truth is [`docs/package-migration.md`](../package-migration.md). The current repository is in a transition period: some package identities are already neutral, while others are Microsoft-origin compatibility names that must be transferred, aliased, or replaced through the AAIF/LF process.

| Ecosystem | Current status |
|---|---|
| PyPI | Canonical `agent-governance-toolkit-*`, ACS, and policy packages are in the GitHub release matrix. Some legacy `agentmesh_*` package metadata remains as compatibility and is tracked in the migration map. |
| npm | Current packages publish from `@microsoft/*` package manifests; `docs/package-migration.md` records target `@aaif/*` identities after foundation namespace setup. |
| NuGet | Current packages are `Microsoft.AgentGovernance*`; neutral package IDs are documented as target identities before registry migration. |
| crates.io | Rust crates are listed as canonical surfaces but need crates.io ownership transfer and release wiring. |
| Go | Current module path is `github.com/microsoft/agent-governance-toolkit/agent-governance-golang`; a foundation module path is deferred until repository transfer. |
| OCI | Container workflow uses owner-derived GHCR paths; `ghcr.io/microsoft/*` is compatibility-only if retained. |

Canonical releases are moving to GitHub Actions. Azure DevOps ESRP is not a canonical AGT release path. See [`docs/RELEASE.md`](../RELEASE.md) and [`docs/PUBLISHING.md`](../PUBLISHING.md).

## 6. Governance

AGT uses public repository governance documents during AAIF contribution finalization:

- [Governance](../../GOVERNANCE.md): maintainer roles, decision making, succession, conflicts, and release authority;
- [Owners](../../OWNERS.md): operational authority for core, area, release, security, and spec roles;
- [Maintainers](../../MAINTAINERS.md): current human maintainer roster;
- [CODEOWNERS](../../.github/CODEOWNERS): per-area review routing, including non-Microsoft maintainers;
- [Contributing](../../CONTRIBUTING.md): DCO sign-off, AI-assisted contribution rules, attribution, and transitional CLA guidance;
- [Security policy](../../SECURITY.md): GitHub private vulnerability reporting, threat model, severity definitions, and intended-behavior boundaries;
- [Technical charter](../../CHARTER.md): foundation-transition charter language;
- [Trademarks](../../TRADEMARKS.md): Microsoft-origin marks pending LF/AAIF transfer or rebranding.

The current maintainer roster has one project lead and five core maintainers, including three non-Microsoft maintainers. AAIF acceptance should still verify that non-Microsoft maintainers have actual repository permissions and a record of exercised review/merge authority, not only listed roles.

## 7. Adoption and community evidence

Current public adoption evidence is tracked in [`docs/ADOPTERS.md`](../ADOPTERS.md).

The production table currently includes Microsoft internal use and Dayos. Additional organizations are listed as evaluation, pilot, or research users. If AAIF requires two independent non-donor production deployments before completing Growth acceptance, the project should either collect permission to cite another production adopter or present that as an explicit Growth-plan item rather than implying the evidence is already complete.

Community signals include external contributors, framework proposals/integrations, docs and package consumers, and public issues/PRs, but the proposal should not treat proposals or pilots as equivalent to verified production deployments.

## 8. Alignment with AAIF

AGT aligns with AAIF by addressing runtime governance, security, identity, observability, and reliability for agentic systems:

1. **MCP complement:** MCP defines tool and server interaction patterns; AGT supplies policy, identity, audit, and governance controls around MCP usage.
2. **AGENTS.md complement:** AGENTS.md describes agent instructions and capabilities; AGT helps enforce runtime authorization and policy around actual tool actions.
3. **agentgateway complement:** gateways can route and mediate traffic; AGT supplies policy decisions, trust signals, and audit/provenance components that can integrate with gateway paths.
4. **Framework neutrality:** AGT supports Microsoft-origin integrations and open-source framework integrations without making any single vendor the canonical control plane.
5. **Security and reliability focus:** AGT combines policy enforcement, provenance, SBOMs, SLOs, incident signals, and conformance-oriented specs.

## 9. Specification and conformance process

AGT includes normative and implementation guidance in `docs/specs/`, `docs/adr/`, and `policy-engine/`. The public process for spec and conformance changes is documented in [`docs/specs/PROCESS.md`](../specs/PROCESS.md).

Changes that alter observable policy, trust, audit, receipt, protocol, SDK-conformance, or security behavior should include compatibility, security, and conformance impact. This is intended to make AGT useful not only as code, but as a foundation-governed specification and conformance surface.

## 10. Proposed Growth-stage roadmap

### Phase 1: Contribution finalization

- Complete AAIF TC/GB review and contribution-agreement execution.
- Finalize the asset schedule for repository, trademarks, package accounts, docs site, registry credentials, and release environments.
- Confirm LF/AAIF contribution process and replace transitional Microsoft CLA routing where required.
- Verify actual maintainer permissions and release-manager authority across organizations.

### Phase 2: Foundation-operable releases

- Run dry-run package releases and review `release-manifest.json`.
- Configure foundation-owned PyPI trusted publishers, npm namespace/token strategy, NuGet ownership, crates.io owners, GHCR namespace, and Go module migration plan.
- Keep Microsoft-origin package names only as compatibility packages or documented aliases where needed.
- Publish SBOMs, provenance, and verification guidance for each canonical release.

### Phase 3: Growth execution

- Convert additional pilot/evaluation users into permissioned production adoption evidence.
- Finish release wiring for Rust, Go, and ACS secondary npm/NuGet/crate packages that are currently pack-only or manual.
- Expand conformance tests for ACS, MCP governance, policy evaluation, and SDK behavior.
- Mature spec/change governance toward Impact-stage expectations.

## 11. References

- **Repository:** [microsoft/agent-governance-toolkit](https://github.com/microsoft/agent-governance-toolkit)
- **AAIF proposal issue:** `aaif/project-proposals#19`
- **Release process:** [`docs/RELEASE.md`](../RELEASE.md)
- **Publishing model:** [`docs/PUBLISHING.md`](../PUBLISHING.md)
- **Package migration map:** [`docs/package-migration.md`](../package-migration.md)
- **Adopters:** [`docs/ADOPTERS.md`](../ADOPTERS.md)
- **Security policy:** [`SECURITY.md`](../../SECURITY.md)
- **Spec process:** [`docs/specs/PROCESS.md`](../specs/PROCESS.md)
