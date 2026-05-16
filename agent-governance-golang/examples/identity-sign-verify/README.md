# Identity Sign & Verify

Generates an Ed25519 agent identity, signs a payload, verifies the signature,
exports the identity as public-only JSON, and demonstrates that a
JSON-rehydrated identity can verify peer signatures but cannot sign new
data — the private key intentionally never leaves the process that
generated it.

Covers [`identity.go`](../../packages/agentmesh/identity.go):
`GenerateIdentity`, `Sign`, `Verify`, `ToJSON`, `FromJSON`.

## Run it

```bash
go run .
```

## Expected output

```text
DID:          did:agentmesh:signer-001
Capabilities: [data.read]

Message:      transfer 10 units to account 42
Signature:    <8 hex bytes>...

Verify with original identity:  true
Verify with tampered message:   false

Public JSON: {"did":"did:agentmesh:signer-001","public_key":"...","capabilities":["data.read"]}

Peer-rehydrated DID verifies signature: true
Peer-rehydrated DID cannot sign:        no private key available
```

## Where to go next

- [`audit-chain/`](../audit-chain/) — sign identities and append signed audit
  records.
- [`trust-scoring/`](../trust-scoring/) — feed verified peer interactions
  into the trust manager.
- [`../README.md`](../../README.md) — full SDK overview.
