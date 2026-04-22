# Proposal: Independently Verifiable Compliance Receipts

**Author:** Arian Gogani (@arian-gogani)
**Date:** 2026-04-21
**Status:** Draft
**Related issues:** #1249, #787, #1196

## Problem

AGT's audit logger writes append-only hash chains. This gives you ordering guarantees, which is good. But the evidence lives on infrastructure the operator controls. If an auditor wants to verify compliance, they have to trust that nobody modified the chain after the fact.

For EU AI Act Art. 12 (enforceable August 2, 2026) and SOC 2 audit scenarios, the question isn't "did you check?" It's "can you prove you checked, and can I verify that proof without trusting you?"

The missing piece: compliance evidence that a third party can verify independently, without access to the operator's infrastructure.

## Proposed solution

When agent-compliance runs verification, it emits a signed receipt alongside the compliance grade. The receipt carries enough information for an external verifier to confirm what happened without needing to trust the operator.

### Receipt fields

A receipt contains: receiptId (SHA-256 hash), agentDid, timestamp, covenantHash (hash of policy in effect), action details with inputHash, decision (permit/deny), authorizationHash + authorizationSignature (pre-execution), resultHash + resultSignature (post-execution), previousReceiptHash (chain link), and signerKeyId.

### What each field does

covenantHash: Hash of the policy document in effect. An auditor checks this against the declared policy.

authorizationHash + authorizationSignature: Signed before execution. Proves the policy was evaluated before anything ran. Pre-execution commitment.

resultHash + resultSignature: Signed after execution. Binds the actual outcome. Post-execution proof.

Both signatures use the same Ed25519 key (signerKeyId), so a verifier confirms they came from the same agent process.

previousReceiptHash: Links to the previous receipt. Change any receipt and every receipt after it breaks.

decision: permit or deny. If deny, the action never executed and the receipt proves the block happened.

## Verification model

A verifier checks three things:
1. Signature validity. Ed25519 signatures valid against the declared signer key.
2. Chain integrity. Each previousReceiptHash matches the hash of the receipt before it.
3. Policy binding. Each covenantHash matches the expected policy.

No access to the operator's infrastructure needed. Signatures and hashes are self-contained.

## How this maps to AGT

agent-compliance produces compliance grades. The receipt emits alongside the grade. The grade says compliant. The receipt proves it.

agent-mesh uses Ed25519 DIDs. The receipt uses the same key material. No new crypto needed.

Signet attestations (#1196) use a similar shape. Converging gives AGT one evidence format.

Physical AI receipts (#787) can use the same bilateral structure.

## Canonicalization

SHA-256 of RFC 8785 JCS canonical form. Sorted keys, no whitespace, UTF-8.

Cross-verified between Nobulex (TypeScript) and AgentLedger (Python). Three test vectors produce byte-identical digests.

## Integration path

When agt verify runs, it optionally emits a receipt wrapping the compliance grade in a signed envelope.

Operators who don't need verifiability keep using AGT as-is. Regulated environments turn on receipts and hand them to auditors.

## Cross-framework status

This format is discussed in LangChain RFC #35691, AutoGen #7609, CrewAI #5541, NousResearch #487, OpenLineage PR #4480 (Linux Foundation spec), and an interop test with 4 implementations.

## Next steps

Happy to iterate. If the direction looks right, I can follow up with a concrete implementation PR against agent-compliance.
