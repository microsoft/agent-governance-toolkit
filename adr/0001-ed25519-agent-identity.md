# ADR-0001: Ed25519 for Agent Identity

## Status

Accepted

## Context

Autonomous agents operating in multi-agent systems need verifiable identities for accountability, delegation, and audit. The identity system must support:

- Fast key generation and verification (agents are created dynamically)
- Compact signatures suitable for embedding in delegation tokens
- W3C DID compatibility for cross-system interoperability
- Deterministic key derivation from agent metadata when needed

Options considered:

1. **RSA-2048/4096**: Widely supported but slow key generation, large signatures (256-512 bytes)
2. **ECDSA (P-256)**: Good performance, NIST-approved, but non-deterministic signatures require careful nonce handling
3. **Ed25519**: Fast, compact 64-byte signatures, deterministic (no nonce issues), strong security properties

## Decision

Use Ed25519 (Curve25519) as the default signing algorithm for agent identities. Agent identities are represented as W3C DID Documents with `Ed25519VerificationKey2020` verification methods.

Key lifecycle states (active, suspended, revoked) are tracked in the identity registry. Revocation cascades to all downstream delegations.

## Consequences

- **Easier**: Fast agent provisioning, compact delegation tokens, no nonce-related vulnerabilities, straightforward W3C DID integration
- **Harder**: Organizations requiring FIPS 140-2 compliance may need an alternate verification method (Ed25519 is not in the FIPS-approved list, though it is in SP 800-186). AGT's identity module is designed to be algorithm-pluggable to accommodate this.

## References

- [RFC 8032: Edwards-Curve Digital Signature Algorithm](https://datatracker.ietf.org/doc/html/rfc8032)
- [W3C DID Core](https://www.w3.org/TR/did-core/)
- `agent-governance-python/agent-mesh/src/agentmesh/identity/`
