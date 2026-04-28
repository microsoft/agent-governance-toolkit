# Tutorial 33 — Offline-Verifiable Decision Receipts

> **Package:** `mcp-receipt-governed` · **Time:** 20 minutes · **Prerequisites:** Python 3.11+

---

## What You'll Learn

- How every MCP tool call produces a signed governance receipt
- Ed25519 signatures over RFC 8785 (JCS) canonical payloads
- Hash chaining for insertion/deletion detection
- Offline CLI verification without network access
- SLSA v1.0 provenance emission for supply-chain integration

---

Every tool call an agent makes should produce a cryptographic receipt that
third parties can verify without access to the original infrastructure.  This
tutorial shows how `mcp-receipt-governed` generates, chains, and verifies
these receipts.

**What you'll learn:**

| Section | Topic |
|---------|-------|
| [Installation](#installation) | Install the adapter with Ed25519 support |
| [Quick Start](#quick-start) | Generate your first receipt chain |
| [Hash Chaining](#hash-chaining) | Understand insertion detection |
| [Offline Verification](#offline-verification) | Verify chains from the CLI |
| [SLSA Provenance](#slsa-provenance) | Emit receipts as SLSA predicates |
| [Standards Alignment](#standards-alignment) | RFC 8032, RFC 8785, SLSA |

---

## Installation

```bash
# Core adapter (no crypto — verify_receipt() returns False)
pip install -e agent-governance-python/agentmesh-integrations/mcp-receipt-governed

# With Ed25519 signing and verification (recommended)
pip install -e "agent-governance-python/agentmesh-integrations/mcp-receipt-governed[crypto]"
```

---

## Quick Start

```python
from mcp_receipt_governed import McpReceiptAdapter, verify_receipt

# 1. Define a Cedar policy and create the adapter
adapter = McpReceiptAdapter(
    cedar_policy="""
        permit(principal, action == Action::"ReadData", resource);
        forbid(principal, action == Action::"DeleteFile", resource);
    """,
    cedar_policy_id="policy:mcp-tools:v1",
    signing_key_hex="a" * 64,  # Use a secure 32-byte hex seed in production
)

# 2. Govern tool calls — each produces a signed receipt
r1 = adapter.govern_tool_call("did:mesh:agent-1", "ReadData", {"path": "/data/1.csv"})
r2 = adapter.govern_tool_call("did:mesh:agent-1", "ReadData", {"path": "/data/2.csv"})
r3 = adapter.govern_tool_call("did:mesh:agent-1", "DeleteFile", {"path": "/secret"})

# 3. Inspect the results
for r in adapter.get_receipts():
    icon = "✅" if r.cedar_decision == "allow" else "🚫"
    print(f"  {icon} {r.tool_name}: {r.cedar_decision} (receipt: {r.receipt_id[:8]}...)")

# 4. Verify a signed receipt
print(f"  Signature valid: {verify_receipt(r1)}")
```

---

## Hash Chaining

Receipts are linked via `parent_receipt_hash`.  Each receipt includes the
SHA-256 hash of the preceding receipt's canonical payload.  This means:

- **Insertion** of a fake receipt breaks the chain because the next receipt's
  `parent_receipt_hash` won't match the inserted receipt's hash.
- **Deletion** of a receipt breaks the chain because the following receipt's
  `parent_receipt_hash` points to a receipt that no longer exists.
- **Modification** of any receipt invalidates both its Ed25519 signature and
  the hash link from the next receipt.

```
┌─────────┐    ┌─────────┐    ┌─────────┐
│Receipt 1│◀───│Receipt 2│◀───│Receipt 3│
│ (root)  │    │parent=H1│    │parent=H2│
└─────────┘    └─────────┘    └─────────┘
```

The first receipt in a chain has `parent_receipt_hash = None`.

### Verifying the Chain Programmatically

```python
from mcp_receipt_governed import verify_receipt_chain

receipts = adapter.get_receipts()
errors = verify_receipt_chain(receipts)
if errors:
    for e in errors:
        print(f"  ❌ {e}")
else:
    print("  ✅ Chain is contiguous and signatures are valid")
```

---

## Offline Verification

Export receipts to JSON and verify them from the command line — no running AGT
infrastructure or network access required.

### 1. Export the Receipt Chain

```python
import json

with open("receipts.json", "w") as f:
    json.dump(adapter.store.export(), f, indent=2)
```

### 2. Run the CLI Verifier

```bash
cd agent-governance-python/agentmesh-integrations/mcp-receipt-governed
python scripts/verify_receipts.py receipts.json
```

Output:

```
╔══════════════════════════════════════════════════════╗
║  MCP Receipt Chain — Offline Verification           ║
╚══════════════════════════════════════════════════════╝

  Loaded 3 receipt(s) from receipts.json

  [0] Receipt 9f5b54c7-036…  (tool: ReadData)
      ✅  Hash chain contiguous
      ✅  Payload hash verified
      ✅  Ed25519 signature valid

  [1] Receipt f31c719a-d97…  (tool: ReadData)
      ✅  Hash chain contiguous
      ✅  Payload hash verified
      ✅  Ed25519 signature valid

  [2] Receipt 87e5cd86-780…  (tool: DeleteFile)
      ✅  Hash chain contiguous
      ✅  Payload hash verified
      ✅  Ed25519 signature valid

  🎉 Verification passed — chain is contiguous and signatures are valid.
```

If a receipt is altered, deleted, or inserted, the verifier flags the exact
position where the chain breaks.

---

## SLSA Provenance

Receipts can be emitted as SLSA v1.0 provenance predicates.  This maps the
agent tool call to the standard in-toto Statement / SLSA Provenance format,
enabling standard supply-chain verification tools (`slsa-verifier`,
`in-toto`) to consume them.

```python
import json

slsa = r1.to_slsa_provenance()
print(json.dumps(slsa, indent=2))
```

The output follows the SLSA v1.0 schema:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "pkg:agentmesh/tool/ReadData",
      "digest": { "sha256": "..." }
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://agent-governance.org/schema/mcp-tool-call/v1",
      "externalParameters": {
        "agent_did": "did:mesh:agent-1",
        "cedar_policy_id": "policy:mcp-tools:v1",
        "cedar_decision": "allow"
      }
    }
  }
}
```

---

## Standards Alignment

| Standard | Usage |
|----------|-------|
| [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032) (Ed25519) | Receipt signing and verification |
| [RFC 8785](https://datatracker.ietf.org/doc/html/rfc8785) (JCS) | Canonical JSON serialization before hashing |
| [SLSA Provenance v1](https://slsa.dev/provenance/v1) | Optional provenance predicate emission |
| [IETF draft-farley-acta](https://datatracker.ietf.org/doc/draft-farley-acta/) | Signed receipt envelope design |

---

## Next Steps

- 📜 Full demo: `python examples/mcp-receipt-governed/demo.py`
- 🔐 Agent identity: [Tutorial 02 — Trust and Identity](02-trust-and-identity.md)
- 📚 Cedar policies: [Tutorial 01 — Policy Engine](01-policy-engine.md)
- 🌐 MCP trust proxy: `agent-governance-python/agentmesh-integrations/mcp-trust-proxy/`
