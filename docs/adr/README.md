# Architecture Decision Records

This directory tracks durable architecture decisions for the Agent Governance
Toolkit using a lightweight MADR-style structure.

Each ADR captures:

- the context that made the decision necessary
- the decision that was taken
- the practical consequences for maintainers and contributors

## ADR Index

- [ADR 0001: Use Ed25519 for agent identity](0001-use-ed25519-for-agent-identity.md)
- [ADR 0002: Use four execution rings instead of RBAC for runtime privilege](0002-use-four-execution-rings-for-runtime-privilege.md)
- [ADR 0003: Keep the IATP trust handshake within a 200ms SLA](0003-keep-iatp-handshake-within-200ms.md)
- [ADR 0004: Keep policy evaluation deterministic and out of LLM control loops](0004-keep-policy-evaluation-deterministic.md)
- [ADR 0005: Add liveness attestation to TrustHandshake](0005-add-liveness-attestation-to-trust-handshake.md)
- [ADR 0006: Constitutional constraint layer as a community extension](0006-constitutional-constraint-layer-as-community-extension.md)
- [ADR 0007: External JWKS federation for cross-org identity](0007-external-jwks-federation-for-cross-org-identity.md)
- [ADR 0008: Cross-org policy federation](0008-cross-org-policy-federation.md)
- [ADR 0009: RFC 9334 (RATS) architecture alignment](0009-rfc-9334-rats-architecture-alignment.md)

## Template

- [ADR 0000: Template](0000-template.md)
