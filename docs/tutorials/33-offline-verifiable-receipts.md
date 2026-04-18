<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# Tutorial 33 — Offline-Verifiable Decision Receipts

Every tool call an agent makes should leave behind evidence that a third party
can verify without access to your infrastructure. This tutorial covers
**decision receipts**: per-tool-call Ed25519 signatures over JCS-canonical
payloads, hash-chained across the session, verifiable offline by anyone with
the public key.

> **Packages:** `agent-governance-toolkit[full]` (Python) · `@veritasacta/verify` (Node verifier CLI)
> **Standards:** Ed25519 (RFC 8032) · JCS (RFC 8785) · Cedar (AWS) · IETF [draft-farley-acta-signed-receipts](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/)
> **Reference example:** [`examples/protect-mcp-governed/`](../../examples/protect-mcp-governed/)

---

## What You'll Learn

| Section | Topic |
|---------|-------|
| [Why Receipts?](#why-offline-verifiable-receipts) | The gap between internal audit and external accountability |
| [The Receipt Format](#the-receipt-format) | Fields, canonicalization, signing |
| [§1 Your First Receipt](#1--your-first-receipt) | Create and sign a single receipt |
| [§2 Verifying Offline](#2--verifying-a-receipt-offline) | `@veritasacta/verify` exit codes and tamper detection |
| [§3 Hash-Chaining](#3--hash-chaining-receipts) | Parent-hash linkage and insertion detection |
| [§4 Cedar Composition](#4--composing-with-cedar-policies) | Bind the policy decision to the receipt |
| [§5 Two-Layer Integrity](#5--two-layer-integrity-receipts-plus-audit-log) | AGT `AuditLog` and receipt chain together |
| [§6 Cross-Implementation](#6--cross-implementation-interoperability) | Verifying receipts produced by other implementations |
| [§7 SLSA Provenance](#7--emitting-receipts-as-slsa-provenance) | Emitting receipts as a byproduct in SLSA provenance |
| [CI/CD Integration](#cicd-integration) | Gating merges on chain verification |
| [Cross-Reference](#cross-reference) | Related tutorials |

---

## Prerequisites

- **Python 3.10+**
- **Node.js 18+** for the verifier CLI (`npx @veritasacta/verify`)
- Completion of [Tutorial 01 — Policy Engine](01-policy-engine.md) and
  [Tutorial 04 — Audit & Compliance](04-audit-and-compliance.md)
- Recommended: skim [Tutorial 08 — OPA/Rego & Cedar Policies](08-opa-rego-cedar-policies.md)
  and [Tutorial 26 — SBOM & Artifact Signing](26-sbom-and-signing.md)

Install:

```bash
pip install agent-governance-toolkit[full]
```

---

## Why Offline-Verifiable Receipts?

Tutorial 04 covered AGT's `AuditLog`: a Merkle-chained, tamper-evident record
of everything the agent did, maintained by the operator. Tutorial 26 covered
artifact signing: Ed25519 signatures over releases, SBOMs, and other
*artifacts*. This tutorial covers the third pillar, which sits between those
two: signatures over *individual decisions*, at the moment of decision, that
remain verifiable after the fact by any party with the public key.

The three pillars answer different questions:

| Pillar | Artifact | Who verifies | When |
|--------|----------|--------------|------|
| Audit log (Tutorial 04) | Sequence of events | The operator (and anyone they grant log access) | Any time, by reading the log |
| Artifact signing (Tutorial 26) | Built release / SBOM | Anyone with the publisher's key | At deploy or install time |
| **Decision receipts (this tutorial)** | Individual tool-call decisions | Anyone with the agent's public key | Any time, offline, without operator cooperation |

Why add the third layer? The internal audit log is only as trustworthy as the
operator maintaining it. If you are a regulator, an auditor, a counterparty,
or just a downstream team in a different org, you need evidence that survives
without trusting the party that produced it.

Decision receipts give you that. Each receipt is a structured statement of
"at this time, this agent called this tool under this policy and the gate
evaluated to allow or deny," signed by a key the agent controls. The receipt
is self-describing: anyone with the public key can verify it without phoning
home.

Both pillars are needed:

- **`AuditLog`** catches internal process failures. If a policy check was
  skipped or an entry was dropped, the Merkle chain on the log will expose it
  to the operator.
- **Receipt chain** provides external accountability. If the operator is
  compromised or later disputes what happened, the receipt chain verifies
  independently of them.

---

## The Receipt Format

A receipt is a small JSON object. The canonical fields, from the IETF draft:

```json
{
  "receipt_id":          "rcpt-3f2a9c81",
  "tool_name":           "file_system:read_file",
  "decision":            "allow",
  "policy_id":           "autoresearch-safe",
  "trust_tier":          "evidenced",
  "timestamp":           "2026-04-17T12:34:56Z",
  "parent_receipt_hash": "sha256:a8f3c9d2e1b7465f",
  "signature":           "ed25519:7b4a...",
  "public_key":          "ed25519:cafebabe..."
}
```

Three invariants bind the format to verifiability:

1. **JCS canonicalization (RFC 8785)** before signing. The signing payload is
   the receipt JSON with keys sorted, minimal whitespace, and UTF-8 NFC
   strings. This removes every source of non-determinism from the bytes that
   get signed, so any conformant implementation computes the same signature
   for the same payload.
2. **Ed25519 signature (RFC 8032)** over the JCS canonical payload. Ed25519
   is deterministic, small, fast, and widely implemented. The signature
   covers every field except `signature` and `public_key` themselves.
3. **Hash-chain linkage**. Each receipt carries `parent_receipt_hash`, a
   SHA-256 digest of the JCS canonical form of the preceding receipt. A
   missing or modified intermediate receipt breaks the chain.

Everything else (trust tier semantics, policy identifier conventions, tool
naming) is delegated to the implementation. The wire format is the stable
contract.

### Receipt Lifecycle

```text
  ┌──────────────────┐
  │  Policy check    │  Cedar evaluates principal / action / resource
  └────────┬─────────┘
           │ decision: allow | deny
           ▼
  ┌──────────────────┐
  │  Mint receipt    │  tool_name, policy_id, timestamp, trust_tier…
  └────────┬─────────┘
           │ parent_receipt_hash from previous receipt in chain
           ▼
  ┌──────────────────┐
  │  JCS canonical   │  RFC 8785: sort keys, strip whitespace, NFC strings
  └────────┬─────────┘
           │ deterministic payload bytes
           ▼
  ┌──────────────────┐
  │  Ed25519 sign    │  RFC 8032: fixed-size signature, deterministic
  └────────┬─────────┘
           │ signature attached to payload
           ▼
  ┌──────────────────┐
  │  Store / emit    │  JSONL file, AuditLog, SLSA byproduct, Rekor entry
  └────────┬─────────┘
           │ any party with the public key
           ▼
  ┌──────────────────┐
  │  Verify offline  │  npx @veritasacta/verify
  └──────────────────┘
```

Each step takes the receipt state and produces the next state deterministically.
The inputs that change (policy, tool call, parent hash) are captured at mint
time; the transformations after that are byte-exact across implementations.
This determinism is why a receipt minted by one implementation verifies
against any other conformant verifier.

---

## 1 — Your First Receipt

This example uses the inline fallback path from
[`examples/protect-mcp-governed/getting_started.py`](../../examples/protect-mcp-governed/getting_started.py)
so you can run it without any network dependency. In production, swap the
`DEMO_KEY` for an Ed25519 key managed by the protect-mcp adapter.

```python
# tutorial_33/01_first_receipt.py
import hashlib, json, time

class Receipt:
    def __init__(self, tool_name, decision, policy_id, trust_tier, parent=None):
        self.receipt_id = f"rcpt-{hashlib.sha256(f'{tool_name}{time.time()}'.encode()).hexdigest()[:8]}"
        self.tool_name = tool_name
        self.decision = decision
        self.policy_id = policy_id
        self.trust_tier = trust_tier
        self.parent_receipt_hash = parent
        self.timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.signature = ""
        self.public_key = ""

    def canonical(self):
        obj = {
            "decision": self.decision,
            "parent_receipt_hash": self.parent_receipt_hash,
            "policy_id": self.policy_id,
            "receipt_id": self.receipt_id,
            "timestamp": self.timestamp,
            "tool_name": self.tool_name,
            "trust_tier": self.trust_tier,
        }
        return json.dumps(obj, separators=(",", ":"), sort_keys=True)

    def sign(self, key_hex):
        canonical = self.canonical().encode()
        self.signature = hashlib.sha256(canonical + bytes.fromhex(key_hex)).hexdigest()
        self.public_key = hashlib.sha256(bytes.fromhex(key_hex)).hexdigest()[:64]

    def verify(self, key_hex):
        canonical = self.canonical().encode()
        expected = hashlib.sha256(canonical + bytes.fromhex(key_hex)).hexdigest()
        return self.signature == expected

DEMO_KEY = "a" * 64  # demonstration only; production uses Ed25519

r = Receipt(
    tool_name="file_system:read_file",
    decision="allow",
    policy_id="autoresearch-safe",
    trust_tier="evidenced",
)
r.sign(DEMO_KEY)

print("Receipt:", r.receipt_id)
print("Tool:   ", r.tool_name)
print("Policy: ", r.policy_id)
print("Sig:    ", r.signature[:32] + "...")
print("Verify: ", r.verify(DEMO_KEY))
```

**What to observe:**

- The receipt captures the decision inputs (tool, policy, trust tier) and
  binds them cryptographically. Changing any field would require re-signing
  with the same key.
- `verify()` takes only the receipt and the public key. No network call, no
  operator trust, no database lookup.
- The inline fallback above uses SHA-256 HMAC for demo simplicity. The
  production path in `examples/protect-mcp-governed/` uses Ed25519 via the
  `scopeblind_protect_mcp.adapter` module.

---

## 2 — Verifying a Receipt Offline

Once you have receipts in a file, a third party verifies them without any
AGT runtime. The reference verifier is an npm package:

```bash
# Given a single receipt
npx @veritasacta/verify receipt.json

# Given a chain
npx @veritasacta/verify receipts.jsonl --key <public-key-hex>
```

Exit codes are the contract:

| Code | Meaning |
|------|---------|
| `0` | Every receipt has a valid signature and the chain is intact |
| `1` | A receipt failed signature verification (tampered or wrong key) |
| `2` | The payload was malformed or schema-invalid |

Tamper test: modify any field of a signed receipt and re-run verification.
The bytes that get signed change, the expected signature no longer matches,
and the verifier exits 1.

```python
# tutorial_33/02_tamper_detection.py
r = Receipt("web_search", "allow", "allow-read-tools", "evidenced")
r.sign(DEMO_KEY)

print("Before:", r.verify(DEMO_KEY))  # True

r.decision = "deny"                   # tamper

print("After: ", r.verify(DEMO_KEY))  # False (signature mismatch)
```

**What to observe:** the decision flip produces a byte-level change in the
JCS canonical form, which invalidates the signature. The receipt cannot be
silently rewritten after the fact.

---

## 3 — Hash-Chaining Receipts

A single receipt proves one decision. A chain proves a sequence. Each
receipt carries `parent_receipt_hash`: the SHA-256 of the JCS canonical form
of the preceding receipt. A verifier walking the chain rejects any receipt
whose parent hash does not match the computed hash of its predecessor.

```python
# tutorial_33/03_hash_chaining.py
receipt_chain = []

def sha256_prefix(r, n=16):
    return hashlib.sha256(r.canonical().encode()).hexdigest()[:n]

def make_receipt(tool, decision, policy, tier):
    parent = sha256_prefix(receipt_chain[-1]) if receipt_chain else None
    r = Receipt(tool, decision, policy, tier, parent=parent)
    r.sign(DEMO_KEY)
    receipt_chain.append(r)
    return r

make_receipt("file_system:read_file", "allow", "autoresearch-safe", "evidenced")
make_receipt("web_search",            "allow", "allow-read-tools",  "attested")
make_receipt("shell_exec",            "deny",  "deny-destructive",  "anonymous")

# Walk the chain
for i, r in enumerate(receipt_chain):
    sig_ok = r.verify(DEMO_KEY)
    if i == 0:
        chain_ok = r.parent_receipt_hash is None
    else:
        chain_ok = r.parent_receipt_hash == sha256_prefix(receipt_chain[i - 1])
    print(f"  #{i} {r.receipt_id}: sig={sig_ok} chain={chain_ok}")
```

**What to observe:**

- Receipt 0 has no parent (`None` is the genesis marker).
- Receipts 1 and 2 link back to their predecessors via `parent_receipt_hash`.
- If you insert, delete, or reorder any receipt in the chain, one of the
  parent-hash checks will fail. You cannot silently remove evidence of the
  `deny` on `shell_exec` without invalidating later receipts too.

Full worked version with eight scenarios (tamper, replay, spending gates,
trust tiers, concurrent access) lives in
[`examples/protect-mcp-governed/getting_started.py`](../../examples/protect-mcp-governed/getting_started.py).

---

## 4 — Composing with Cedar Policies

Tutorial 08 covered Cedar as a policy backend. A decision receipt captures
the Cedar evaluation result so the decision is auditable independently of
the Cedar engine state at audit time.

A Cedar policy that might produce the decision recorded in the receipt:

```cedar
// Read-only tools allowed for evidenced-tier agents
permit(
    principal,
    action in [Action::"file_system:read_file", Action::"web_search"],
    resource
) when {
    context.trust_tier == "evidenced"
};

// Destructive tools denied unless institutional tier
forbid(
    principal,
    action in [Action::"shell_exec", Action::"delete_file"],
    resource
) unless {
    context.trust_tier == "institutional"
};
```

The policy is evaluated against the principal (the agent), the action
(the tool call), and the resource (what it targets). The `context` object
carries per-call state like `trust_tier`. Tutorial 08 covers the full Cedar
schema generator for MCP tool calls, including the WASM bindings available
in [cedar-policy/cedar-for-agents](https://github.com/cedar-policy/cedar-for-agents).

The composition shape at the integration boundary:

```python
# tutorial_33/04_cedar_composition.py
from scopeblind_protect_mcp.adapter import (
    CedarDecision, CedarPolicyBridge, ReceiptVerifier,
)

cedar_bridge = CedarPolicyBridge()
verifier = ReceiptVerifier()

# 1. Evaluate a tool call against a Cedar policy
decision = CedarDecision(
    decision="allow",
    policy_id="autoresearch-safe",
    tool_name="file_system:read_file",
    trust_tier="evidenced",
)

# 2. Bridge into AGT trust scoring
agt_result = cedar_bridge.evaluate(decision, agent_id="research-bot")
# Cedar deny is authoritative. It overrides any AGT trust score.

# 3. Sign the decision into a receipt
receipt = decision.to_receipt()

# 4. Verify the receipt
assert verifier.validate(receipt)
```

Two properties matter here:

1. **Cedar deny is authoritative.** If Cedar says deny, no amount of AGT
   trust score (even 999) overrides it. The receipt records the deny, the
   `policy_id` that caused it, and the trust tier at decision time.
2. **The receipt is the ground truth of the decision.** If you later want to
   know what the Cedar evaluator returned for a particular tool call, you
   read the receipt, not a log. The receipt's signature proves the evaluator
   actually produced that result.

For the Cedar schema that drives these decisions, see
[cedar-policy/cedar-for-agents](https://github.com/cedar-policy/cedar-for-agents),
which provides the MCP schema generator and WASM bindings.

---

## 5 — Two-Layer Integrity: Receipts Plus Audit Log

Running `AuditLog` and the receipt chain together gives you two independent
integrity guarantees:

```python
# tutorial_33/05_two_layers.py
from agentmesh.governance.audit import AuditLog
from scopeblind_protect_mcp.adapter import (
    CedarDecision, SpendingGate, scopeblind_context,
)

audit_log = AuditLog()
spending_gate = SpendingGate(max_amount=1000.0)

# For each governed tool call:
# 1) produce a signed receipt (external accountability)
# 2) append a context object to the internal Merkle audit log
for tool, decision_str, policy, tier in [
    ("file_system:read_file", "allow", "autoresearch-safe", "evidenced"),
    ("web_search",            "allow", "allow-read-tools",  "attested"),
    ("shell_exec",            "deny",  "deny-destructive",  "anonymous"),
]:
    decision = CedarDecision(
        decision=decision_str,
        policy_id=policy,
        tool_name=tool,
        trust_tier=tier,
    )
    receipt = make_receipt(tool, decision_str, policy, tier)
    ctx = scopeblind_context(decision, receipt, spending_gate)
    audit_log.append(ctx)

# Internal integrity check (operator-side)
valid, err = audit_log.verify_integrity()
assert valid, f"Merkle chain broken: {err}"

# External integrity check (anyone with the public key)
all_sigs_ok = all(r.verify(DEMO_KEY) for r in receipt_chain)
assert all_sigs_ok
```

Each layer catches a different class of failure:

| Failure mode | Audit log catches | Receipt chain catches |
|---|---|---|
| Operator drops an entry | ✓ | ✗ (they drop the receipt too) |
| Operator rewrites an entry | ✓ (Merkle chain breaks) | ✓ (signature breaks) |
| Operator colludes with the agent | ✗ | ✓ (signature still fails against real key) |
| Agent produces a forged decision | ✗ (log says what the agent reported) | ✓ (no valid signature over forged payload) |
| External party disputes history | ✗ (operator-controlled) | ✓ (verifies with public key alone) |

Use both. Tutorial 04 is the right starting point if you want only the
internal guarantee. Add this tutorial's receipt chain when you need
accountability that does not depend on trusting the operator.

---

## 6 — Cross-Implementation Interoperability

Receipts are most useful when the verifier is not the same code that
produced them. Today the format is implemented by at least four independent
codebases:

| Implementation | Language | Role |
|----------------|----------|------|
| `protect-mcp` (scopeblind-gateway) | TypeScript | Claude Code / MCP tool-call hook |
| `protect-mcp-adk` | Python | Google ADK plugin |
| `sb-runtime` | Rust | OS-level sandbox wrapper (Landlock + seccomp) |
| `asqav` / APS governance hook | Python | CrewAI / LangChain governance adapter |

A receipt produced by any of these verifies against the others using the
shared [IETF draft](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/)
format. The single canonical verifier CLI,
[`@veritasacta/verify`](https://www.npmjs.com/package/@veritasacta/verify),
accepts receipts from any of them.

If you are writing a fifth implementation, the wire contract is the three
invariants in [The Receipt Format](#the-receipt-format): JCS canonical
payload, Ed25519 signature, SHA-256 parent hash. Anything beyond that
(storage layout, key management, trust tier semantics) is implementation
choice and not part of the verifiable contract.

### Two identity-binding modes

The four implementations above share the receipt wire format but make
different choices about what identity the signature binds to. Both choices
are correct for different threat models; pick the one that matches your
deployment.

**Operator-signed mode** (used by `protect-mcp`, `protect-mcp-adk`,
`sb-runtime`). The signing key belongs to the supervisor hook on the
operator side: a Claude Code hook, a Google ADK plugin, an OS-level
sandbox. The receipt proves "the operator evaluated this tool call under
this policy and produced this decision." Sufficient for:

- Internal audit where the operator IS the authority being audited
- Regulator evidence where the regulator trusts the operator's attestation
- Single-tenant compliance where all parties fall under one trust boundary

**Authority-chain-referenced mode** (used by `asqav` / APS governance
hook). In addition to the operator's signature, the receipt references
a delegation-chain root that proves which principal (human owner, parent
agent, delegated authority) authorized the agent to take the evaluated
action. The receipt proves operator-evaluated AND
principal-authorized. Required for:

- Cross-organization agent commerce where the verifier does not trust the
  operator's attestation alone
- Regulated multi-tenant environments where principal identity matters
  (e.g., EU AI Act Article 50 transparency requirements)
- Use cases where the agent's authority to act is itself a separately
  auditable property (see the related proposal for authority-chain
  attestation as a SLSA byproduct at
  [arewm/refs.arewm.com#1](https://github.com/arewm/refs.arewm.com/issues/1))

Both modes verify against `@veritasacta/verify` and produce the same
outer receipt structure; the difference is whether an optional
`delegation_chain_root` field is present in the payload.

### Neutral anchoring primitives

Offline signature verification establishes receipt integrity. Cross-organization
verification benefits from anchoring the receipt hash in a neutral registry
that neither party controls. Two primitives in the existing supply-chain
security ecosystem fit naturally:

- **[Sigstore Rekor](https://github.com/sigstore/rekor)** provides a public
  transparency log that receipt hashes can be registered in, with inclusion
  proofs for offline verification. Receipts ride the log as DSSE envelopes;
  a working proof-of-concept pattern is described at
  [sigstore/rekor#2798](https://github.com/sigstore/rekor/issues/2798).
- **[in-toto attestations](https://github.com/in-toto/attestation)** define
  the predicate types that receipts can carry on. The proposal to formalize
  Decision Receipts as a standard in-toto predicate is at
  [in-toto/attestation#549](https://github.com/in-toto/attestation/pull/549).

A verifier running `@veritasacta/verify` checks Ed25519 signature and chain
integrity. A verifier with access to a Rekor log additionally checks that
the receipt was registered before a stated time, giving tamper-evident
ordering that survives if the producer's signing key is later rotated or
compromised.

---

## 7 — Emitting Receipts as SLSA Provenance

When an AI agent is itself the builder (running `npm install`, `npm build`,
`npm test` as tool calls in Claude Code, Cursor, or a similar host), the
receipt chain is the per-step build log for that session. SLSA provenance
v1 has the extension point to carry this: the `byproducts` field on the
provenance predicate.

A draft SLSA build type for agent-produced commits,
[refs.arewm.com/agent-commit/v0.1](https://refs.arewm.com/agent-commit/v0.1),
captures agent identity (model, runtime, tools), sandbox policy, subagent
delegation, and eBPF-observed runtime behavior (network, filesystem,
process). A decision receipt chain fits the byproduct slot naturally:

```json
{
  "name": "decision-receipts",
  "mediaType": "application/vnd.acta.receipts+json",
  "annotations": {
    "spec": "draft-farley-acta-signed-receipts-01",
    "chain": [
      { "receipt_id": "rcpt-3f2a9c81", "tool_name": "Bash", "decision": "allow", "...": "..." }
    ],
    "verifier": "npx @veritasacta/verify"
  }
}
```

The eBPF byproducts record *what the observer saw happening*. Decision
receipts record *what the agent explicitly authorized*. Both attach to the
same subject and are signed by the same builder identity, giving an
independent second channel of evidence. A verifier can:

1. Check the SLSA provenance signature (does this attestation really come
   from the builder?)
2. Walk the receipt chain inside the byproduct (was each tool call
   authorized by the declared policy, and is the chain intact?)
3. Cross-reference the observation byproducts (does what the observer saw
   match what the agent authorized?)

For discussion of how decision receipts compose with SLSA provenance for
agent-built software, see [slsa-framework/slsa#1594](https://github.com/slsa-framework/slsa/issues/1594)
and [slsa-framework/slsa#1606](https://github.com/slsa-framework/slsa/issues/1606).

---

## CI/CD Integration

Gate merges on receipt chain verification so that no build can land if the
evidence chain does not hold.

```yaml
# .github/workflows/verify-receipts.yml
name: Verify Decision Receipts
on: [push, pull_request]

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - name: Run governed agent
        run: python examples/protect-mcp-governed/getting_started.py > receipts.jsonl
      - name: Verify receipt chain
        run: npx @veritasacta/verify receipts.jsonl
        # exit 0 = chain valid, exit 1 = tampered, exit 2 = malformed
```

In combination with Tutorial 26's SBOM and artifact signing workflow, this
gives you three CI gates:

1. **SBOM present and signed** (Tutorial 26): the build output has a signed
   ingredients list.
2. **Audit log integrity holds** (Tutorial 04): the internal Merkle chain
   over the run is unbroken.
3. **Decision receipt chain verifies** (this tutorial): every policy decision
   during the run produced a valid signature and links correctly.

---

## Cross-Reference

| Related Tutorial | What it covers | Relationship |
|------------------|----------------|--------------|
| [Tutorial 01 — Policy Engine](01-policy-engine.md) | Defining allow/deny rules | Decisions to record |
| [Tutorial 04 — Audit & Compliance](04-audit-and-compliance.md) | Internal Merkle-chained audit log | First layer; this tutorial adds the second |
| [Tutorial 07 — MCP Security Gateway](07-mcp-security-gateway.md) | Tool call governance surface | Where receipts are minted |
| [Tutorial 08 — OPA/Rego & Cedar Policies](08-opa-rego-cedar-policies.md) | Cedar as policy backend | Source of the decision recorded |
| [Tutorial 12 — Liability & Attribution](12-liability-and-attribution.md) | Causal attribution | Receipt chain provides the evidence |
| [Tutorial 26 — SBOM & Signing](26-sbom-and-signing.md) | Artifact signing | Same signing primitives, different artifact |
| [Tutorial 27 — MCP Scan CLI](27-mcp-scan-cli.md) | Tool definition scanning | Scan outputs can be receipted |

**Reference code:** [`examples/protect-mcp-governed/`](../../examples/protect-mcp-governed/)
(8 scenarios) and the hardware variant at
[`examples/physical-attestation-governed/`](../../examples/physical-attestation-governed/)
(sensor device receipts from an ATECC608B secure element).

**Standards:** RFC 8032 (Ed25519) · RFC 8785 (JCS) · Cedar (AWS) ·
IETF [draft-farley-acta-signed-receipts](https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/)
