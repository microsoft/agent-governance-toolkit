# ADR 0001: Use Ed25519 for agent identity

- Status: accepted
- Date: 2026-03-26

## Context

AgentMesh treats identity as the first layer of trust. The repository README,
architecture docs, tutorial 02, JSON schemas, and service API docs all describe
`did:mesh:*` identities backed by Ed25519 keys, short-lived credentials,
sponsor signatures, and cross-language SDKs. The same identity primitive must
work in Python, Node.js, and .NET-facing documentation, and it must support
repeated signing and verification during registration, delegation, and trust
handshakes. A heavier RSA-based default would increase key, signature, and
document size for flows that are already optimized for compact manifests,
ephemeral credentials, and low-latency verification.

## Decision

Standardize agent identity on Ed25519 for agent DIDs, signatures, and
verification keys. Keep interoperability through JWK export, DID documents, and
SPIFFE/SVID integration instead of making RSA the default identity primitive.

## Consequences

Identity payloads stay compact, signing remains fast enough for frequent
handshake and rotation flows, and the repository can document one consistent
identity story across SDKs and protocol bridges. The tradeoff is that legacy
RSA-only PKI environments need an adapter boundary rather than first-class,
native parity in the core identity model.
