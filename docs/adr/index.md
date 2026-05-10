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

## Proposed

| ADR | Decision | Area |
|-----|----------|------|
| [ADR-0005](0005-add-liveness-attestation-to-trust-handshake.md) | Add liveness attestation to TrustHandshake | Mesh |
| [ADR-0006](0006-constitutional-constraint-layer-as-community-extension.md) | Constitutional constraint layer as community extension | Policy |
| [ADR-0007](0007-external-jwks-federation-for-cross-org-identity.md) | External JWKS federation for cross-org identity | Identity |
| [ADR-0008](0008-cross-org-policy-federation.md) | Cross-org policy federation above identity | Policy |
| [ADR-0010](0010-tee-keystore-sevsnp-attestation.md) | TEE keystore with SEV-SNP attestation | Security |
| [ADR-0011](0011-additive-policy-check-contract.md) | Additive policy check contract | Policy |
