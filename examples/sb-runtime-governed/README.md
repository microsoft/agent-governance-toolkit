# sb-runtime Governed Example

Demonstrates the architectural claim of the `sb-runtime` integration:

> **The same Cedar policy produces semantically-equivalent signed receipts regardless of the sandbox layer that wraps the agent process. Auditors verify every receipt with one public key. The `sandbox_backend` field is inside the signature scope, so an operator cannot claim a hardened sandbox at verify time if the receipt was produced under `none`.**

This is PR 3 in the three-PR sequence proposed on [#748](https://github.com/microsoft/agent-governance-toolkit/issues/748):

| # | What | Status |
|---|---|---|
| 1 | Integration doc at [`docs/integrations/sb-runtime.md`](../../docs/integrations/sb-runtime.md) | Merged ([#1202](https://github.com/microsoft/agent-governance-toolkit/pull/1202)) |
| 2 | Provider shim at [`packages/agentmesh-integrations/sb-runtime-skill/`](../../packages/agentmesh-integrations/sb-runtime-skill/) | Merged ([#1203](https://github.com/microsoft/agent-governance-toolkit/pull/1203)) |
| 3 | Worked example (this directory) | This PR |

## Quick start

```bash
pip install -e packages/agentmesh-integrations/sb-runtime-skill/
python examples/sb-runtime-governed/getting_started.py
```

Expected exit code: `0` (all 18 receipts verify, tamper test fails as designed).

## What the demo does

The demo runs the **same six actions** (three allowed, three denied) across **three sandbox-backend configurations**, using the **same Cedar policy** and the **same operator Ed25519 key**:

| Scenario | `sandbox_backend` | Ring | Who owns the sandbox layer |
|---|---|:---:|---|
| `standalone` | `sb_runtime_builtin` | 3 | sb-runtime's own Landlock + seccomp |
| `nono` | `nono` | 2 | [nono](https://github.com/always-further/nono) capability set (recommended Linux path per [#1202](https://github.com/microsoft/agent-governance-toolkit/pull/1202)) |
| `openshell` | `openshell` | 2 | OpenShell container boundary |

Each scenario produces six signed receipts in the [Veritas Acta receipt format](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/). The demo then:

1. **Cross-verifies every receipt** (18 total) against the single operator public key, with no dependency on the `sb_runtime_agentmesh` skill at verify time.
2. **Demonstrates tamper-evidence** by flipping the `sandbox_backend` field on one receipt and confirming verification fails, proving the backend choice is covered by the Ed25519 signature and not sidecar metadata.
3. **Confirms chain linkage** by showing `receipt[1].previousReceiptHash == sha256(canonical(receipt[0]))` within a scenario.
4. **Writes receipts to disk** at `examples/sb-runtime-governed/receipts/` so the output can be inspected and re-verified with external tooling.

## Expected output

```
========================================================================
   sb-runtime Governed Agent — Multi-backend Receipt Portability
========================================================================

  Operator key:  kid = UbV24JP2YJDzwYwX...
  Policy:        .../sandbox-policy.yaml
  Agent DID:     did:mesh:sb-runtime-demo-agent

------------------------------------------------------------------------
   Scenario summaries (same policy, three sandbox backends)
------------------------------------------------------------------------

  Scenario: standalone
    sandbox_backend = "sb_runtime_builtin"  ring=3
    receipts:      6  (3 allow, 3 deny)
    policy digest: sha256:095c56b995768de62...
    sample payload fields:  type=sb-runtime:decision  ring=3  sandbox_backend=sb_runtime_builtin

  Scenario: nono
    sandbox_backend = "nono"  ring=2
    receipts:      6  (3 allow, 3 deny)
    policy digest: sha256:095c56b995768de62...
    sample payload fields:  type=sb-runtime:decision  ring=2  sandbox_backend=nono

  Scenario: openshell
    sandbox_backend = "openshell"  ring=2
    receipts:      6  (3 allow, 3 deny)
    policy digest: sha256:095c56b995768de62...
    sample payload fields:  type=sb-runtime:decision  ring=2  sandbox_backend=openshell

------------------------------------------------------------------------
   Cross-verification (single public key, all 18 receipts)
------------------------------------------------------------------------

  Verified: 18 / 18  [ALL PASS]

------------------------------------------------------------------------
   Tamper-evidence demonstration
------------------------------------------------------------------------

  Tamper test: flip sandbox_backend on a receipt from the nono scenario
    Before: 'nono'  verifies = True
    After:  'sb_runtime_builtin'  verifies = False
    -> sandbox_backend is inside the signature scope, not sidecar metadata.

  Chain linkage (scenario: standalone)
    hash(receipt[0])          = 0NECPTsP6PFdM9VaNPFPX_a4cyk7GftN...
    receipt[1].previousReceiptHash = 0NECPTsP6PFdM9VaNPFPX_a4cyk7GftN...
    match = True
```

## What an auditor sees

Every scenario's receipt contains:

- `payload.decision` ∈ `{allow, deny, require_approval}`
- `payload.policy_digest` — identical across scenarios (same policy)
- `payload.ring` ∈ `{2, 3}` — runtime ring
- `payload.sandbox_backend` — which layer wrapped the process
- `payload.previousReceiptHash` — chain linkage
- `signature.alg` = `"EdDSA"`
- `signature.kid` — identical across scenarios (same operator key)
- `signature.sig` — Ed25519 signature over the JCS-canonicalized payload

Verification path for any receipt, from a fresh machine with no AGT dependency:

```bash
npx @veritasacta/verify examples/sb-runtime-governed/receipts/standalone/000.json \
    --key examples/sb-runtime-governed/receipts/operator-public.pem
```

The public key is written to disk alongside the receipts so the demo is self-contained. In production, operators publish the pubkey via an agent card extension, DID document service endpoint, or pinned JWKS URL; `@veritasacta/verify` resolves from any of those via `--jwks` or `--trust-anchor`.

## Policy

See [`policies/sandbox-policy.yaml`](./policies/sandbox-policy.yaml). Mirrors the style of `examples/openshell-governed/policies/sandbox-policy.yaml` so cross-example comparison is straightforward.

## Related

- **Integration doc:** [`docs/integrations/sb-runtime.md`](../../docs/integrations/sb-runtime.md)
- **Provider shim package:** [`packages/agentmesh-integrations/sb-runtime-skill/`](../../packages/agentmesh-integrations/sb-runtime-skill/)
- **Reference verifier:** [`@veritasacta/verify`](https://github.com/ScopeBlind/verify) (Apache-2.0, offline, zero runtime dependencies on AGT or sb-runtime)
- **Receipt format spec:** [draft-farley-acta-signed-receipts-02](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/)
- **Conformance profile:** [VeritasActa/agt-integration-profile](https://github.com/VeritasActa/agt-integration-profile)
- **Sibling example:** [`examples/openshell-governed/`](../openshell-governed/) (same policy contract, no receipts)
- **Sandbox primitive (recommended composition):** [nono](https://github.com/always-further/nono) (Always Further, Apache-2.0)
