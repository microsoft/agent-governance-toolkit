---
title: Architecture Decision Records
last_reviewed: 2026-06-11
owner: agt-maintainers
---

# Architecture Decision Records

Key architectural decisions and their rationale. Each ADR follows the standard format: Context, Decision, Consequences.

!!! note "ADR process"
    New ADRs use the [template](0000-template.md). Status values: `accepted` (implemented), `proposed` (under review), `deprecated`, `superseded`.

## Accepted

| ADR | Decision | Area |
|-----|----------|------|
| [ADR-0001](0001-use-ed25519-for-agent-identity.md) | Use Ed25519 for agent identity signatures | Identity |
| [ADR-0002](0002-use-four-execution-rings-for-runtime-privilege.md) | Four execution rings for runtime privilege separation | Runtime |
| [ADR-0003](0003-keep-iatp-handshake-within-200ms.md) | Keep IATP handshake under 200ms | Mesh |
| [ADR-0004](0004-keep-policy-evaluation-deterministic.md) | Keep policy evaluation deterministic | Policy |
| [ADR-0009](0009-rfc-9334-rats-architecture-alignment.md) | RFC 9334 (RATS) architecture alignment | Standards |
| [ADR-0012](0012-cost-governance-observability-policies.md) | Cost governance via observability policies | SRE |
| [ADR-0013](0013-fail-closed-on-policy-evaluation-errors.md) | Fail closed on policy evaluation errors | Policy |
| [ADR-0014](0014-parent-deny-rules-immutable-in-merge.md) | Parent deny rules are immutable in policy merge | Policy |
| [ADR-0015](0015-pluggable-external-policy-backends.md) | Pluggable external policy backends via protocol interface | Policy |
| [ADR-0016](0016-trust-ceiling-propagation-for-delegation.md) | Trust ceiling propagation for delegated agents | Trust |
| [ADR-0017](0017-merkle-chain-for-audit-tamper-evidence.md) | Merkle chain for audit tamper evidence | Audit |
| [ADR-0018](0018-reconstructible-decision-bom-over-prebuilt.md) | Reconstructible Decision BOM over pre-built | Audit |
| [ADR-0019](0019-otel-batchspanprocessor-pattern-for-event-sink.md) | OTel BatchSpanProcessor pattern for event sink | Events |
| [ADR-0020](0020-circuit-breaker-for-event-sink-delivery.md) | Circuit breaker for event sink delivery | Events |
| [ADR-0021](0021-cloudevents-envelope-for-mesh-audit.md) | CloudEvents envelope for mesh audit | Audit |
| [ADR-0022](0022-compliance-framework-auto-mapping.md) | Compliance framework auto-mapping | Compliance |
| [ADR-0023](0023-append-only-delta-engine-for-hypervisor-audit.md) | Append-only delta engine for hypervisor audit | Audit |
| [ADR-0024](0024-rl-training-governance-with-violation-penalties.md) | RL training governance with violation penalties | Lightning |
| [ADR-0025](0025-structural-typing-for-sink-and-source-protocols.md) | Structural typing for sink and source protocols | Architecture |

## Proposed

| ADR | Decision | Area |
|-----|----------|------|
| [ADR-0005](0005-add-liveness-attestation-to-trust-handshake.md) | Add liveness attestation to TrustHandshake | Mesh |
| [ADR-0006](0006-constitutional-constraint-layer-as-community-extension.md) | Constitutional constraint layer as community extension | Policy |
| [ADR-0007](0007-external-jwks-federation-for-cross-org-identity.md) | External JWKS federation for cross-org identity | Identity |
| [ADR-0008](0008-cross-org-policy-federation.md) | Cross-org policy federation above identity | Policy |
| [ADR-0010](0010-tee-keystore-sevsnp-attestation.md) | TEE keystore with SEV-SNP attestation | Security |
| [ADR-0011](0011-additive-policy-check-contract.md) | Additive policy check contract | Policy |
| [ADR-0026](0026-foundry-ai-gateway-functions-pdp.md) | Azure Functions PDP behind AI Gateway for Foundry prompt-based agents | Policy |
| [ADR-0027](0027-adopt-dual-stack-migration-for-mcp-2026-07-28.md) | Dual-stack migration for MCP `2026-07-28` | MCP |
| [ADR-0028](0028-agt-studio-unified-ui.md) | AGT Studio, a single unified UI for governance | UI |
| [ADR-0029](0029-policy-distribution-and-registries.md) | Policy distribution and registries with verifiable trust | Policy / Supply chain |
| [ADR-0030](0030-action-bound-approval-protocol.md) | Action-bound, fail-closed approval protocol | Policy / Audit |
| [ADR-0031](0031-optional-embedding-detection-backend.md) | Optional embedding evidence backend for prompt-injection detection | Security |
| [ADR-0032](0032-agt-emits-trace-v01-trust-records.md) | AGT emits TRACE v0.1 Trust Records per session | Audit / Standards |
