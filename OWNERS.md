# Owners

This file records operational authority for Agent Governance Toolkit during the
AAIF contribution finalization period. `MAINTAINERS.md` remains the human roster;
this file maps roles to repository areas and release/security/spec authority.

AGT is proposed for AAIF hosting in `aaif/project-proposals#19`. Ownership will
move to LF/AAIF project teams after TC approval, Governing Board approval,
governance finalization, and contribution agreement execution.

## Roles

| Role | Authority |
|---|---|
| Core Maintainer | Project-wide technical direction, cross-cutting review, governance changes. |
| Area Maintainer | Review and merge authority for a specific implementation area. |
| Release Manager | Approves and operates canonical package/container releases. |
| Security Responder | Triage and coordinate private vulnerability reports. |
| Spec Maintainer | Review normative specs, ADRs, and conformance changes. |
| Emeritus | Historical maintainer; no standing merge/release authority. |

## Current owners

| Name | GitHub | Affiliation | Roles | Scope |
|---|---|---|---|---|
| Imran Siddique | `@imran-siddique` | Microsoft | Core Maintainer, Release Manager, Security Responder, Spec Maintainer | Project architecture, Python governance stack, security-sensitive changes |
| Jack Batzner | `@jackbatzner` | Microsoft | Core Maintainer, Release Manager, Area Maintainer | Python SDK, Agent OS, package migration |
| Elton Carr | `@eltoncarr-ms` | Microsoft | Core Maintainer, Release Manager, Area Maintainer, Security Responder | .NET SDK, CI/CD, release workflows |
| Kevin Knapp | `@Knapp-Kevin` | MythologIQ | Core Maintainer, Area Maintainer, Spec Maintainer | Policy engine, runtime governance, LangChain integration |
| Nishar Miya | `@miyannishar` | Dayos | Core Maintainer, Area Maintainer | Observability and adopter integrations |
| Prashan Sapkota | `@prashansapkota` | Robert Half Inc. | Core Maintainer, Area Maintainer | Cloud infrastructure and deployment examples |

## Path ownership

| Path | Required review |
|---|---|
| `.github/**` | Release Manager or Security Responder |
| `.github/workflows/publish*.yml` | Release Manager |
| `docs/specs/**`, `docs/adr/**`, `policy-engine/spec/**` | Spec Maintainer |
| `policy-engine/**` | Spec Maintainer or policy-engine Area Maintainer |
| `agent-governance-python/**` | Python/Agent OS Area Maintainer |
| `agent-governance-dotnet/**` | .NET Area Maintainer |
| `agent-governance-typescript/**`, `agent-governance-*cli/**` | SDK/tooling Area Maintainer |
| `agent-governance-rust/**` | Rust/policy Area Maintainer |
| `agent-governance-golang/**` | SDK Area Maintainer |
| `examples/**` | Relevant Area Maintainer |
| `docs/**`, `README.md` | Relevant Area Maintainer or Spec Maintainer for normative content |

## Release authority

Canonical releases require approval from at least one Release Manager. Foundation
registry credentials and release environments must be owned by the project after
transfer. Microsoft ESRP is not a release authority for canonical AGT artifacts.

## Security authority

Security Responders triage private vulnerability reports through the repository's
GitHub Security Advisory flow. Microsoft security channels are not the canonical
AGT vulnerability intake after transfer.

## Spec authority

Spec Maintainers review normative changes. Any change that alters observable
policy, trust, audit, receipt, protocol, SDK-conformance, or security behavior
must include compatibility, security, and conformance impact.
