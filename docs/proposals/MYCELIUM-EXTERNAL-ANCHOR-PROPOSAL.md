# Proposal: EvidenceAnchor — Pluggable External Anchoring for agt-evidence.json

**Author:** @giskard09 (Rama / Mycelium)
**Date:** 2026-05-13
**Status:** Draft
**Related issues:** #2208
**Related proposals:** [verifiable-compliance-receipts.md](verifiable-compliance-receipts.md)

---

## Problem

`agt verify --evidence` closes the internal loop. An auditor who cannot trust the runtime that produced `agt-evidence.json` has no independent way to confirm the artifact was not rewritten after the fact.

Hash-chaining (including the receipt design in [verifiable-compliance-receipts.md](verifiable-compliance-receipts.md)) proves internal ordering. It does not prove the chain was not reconstructed wholesale after a compliance event. For long-retention regulated environments (EU AI Act Art. 12 enforceable 2026-08-02, FCA SYSC 9.1, SOC 2 CC7.x, ISO 27001 A.12.4, Basel III BCBS 239), the standard is: a third party can verify the evidence existed at a specific time, without trusting the operator's infrastructure.

External anchoring closes this gap. The hash of an evidence artifact is written to an append-only surface outside the operator's control. After that point, the artifact cannot be modified without the anchor detecting it.

---

## Non-goals and threat model

**What anchoring proves:** the evidence artifact existed, unmodified, at anchor time. An external verifier can confirm this without access to AGT runtime state or operator infrastructure.

**What anchoring does not prove:** the evidence was truthful at write time. The producing system is trusted up to the anchor point. AGT should not oversell this to users — it is a tamper-evidence guarantee, not a correctness guarantee.

**Non-goals:**
- Anchoring does not replace receipt signing (see verifiable-compliance-receipts.md)
- AGT core does not mandate any specific anchor backend
- This proposal does not add a runtime dependency on any chain, ledger, or third-party service

---

## Design

### EvidenceAnchor interface

AGT core owns the interface, the hashing, and `action_ref` derivation. Backends are separate plugins.

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

@dataclass
class AnchorReceipt:
    backend: str           # e.g. "mycelium", "rekor", "s3-worm"
    anchor_id: str         # backend-specific identifier (tx hash, log index, object key)
    anchored_at: str       # ISO 8601 timestamp
    evidence_hash: str     # SHA-256 hex of the anchored artifact
    metadata: dict[str, Any]  # backend-specific proof data

class EvidenceAnchor(ABC):
    @abstractmethod
    def anchor(self, evidence_hash: str, metadata: dict[str, Any]) -> AnchorReceipt:
        """Write evidence_hash to the external surface. Returns a receipt."""
        ...

    @abstractmethod
    def verify(self, evidence_hash: str, receipt: AnchorReceipt) -> bool:
        """Confirm evidence_hash is recorded at the position in receipt."""
        ...
```

### Canonical action_ref derivation

To ensure two independent implementations produce byte-identical hashes:

```
action_ref = SHA-256(agent_id || action_type || scope || timestamp_ms)
```

**Encoding rules (all required):**
- Fields concatenated with `||` as UTF-8 bytes with no separator
- `agent_id`: UTF-8 string, no normalization (caller responsible for stability)
- `action_type`: UTF-8 string, lowercase, e.g. `stripe:charge`, `file:write`
- `scope`: UTF-8 string, lowercase
- `timestamp_ms`: int64 encoded as 8-byte big-endian, before execution

This derivation is compatible with [azender1/SafeAgent RFC_EXECUTION_GUARD.md](https://github.com/azender1/SafeAgent/blob/main/RFC_EXECUTION_GUARD.md) and the joint interface spec at [giskard09/argentum-core#7](https://github.com/giskard09/argentum-core/issues/7).

### Schema changes to agt-evidence.json

Additive only. New optional field:

```json
{
  "action_ref": "sha256:...",
  "anchors": [
    {
      "backend": "mycelium",
      "anchor_id": "0xabc123...",
      "anchored_at": "2026-05-13T10:00:00Z",
      "evidence_hash": "sha256:...",
      "metadata": {}
    }
  ]
}
```

If `anchors` is absent or empty, verification behaves as today. No breaking changes.

### CLI changes

```
agt verify --evidence evidence.json --anchor <backend>
```

- Loads the named backend plugin
- Reads `anchors[backend]` from the evidence file
- Calls `backend.verify(evidence_hash, receipt)`
- Exits 0 if verified, 1 if not, 2 if anchor record not found

Runnable by an auditor with only the evidence file and public anchor metadata — no AGT runtime state, no network access to operator infrastructure.

---

## Reference implementations

**Priority 1 — filesystem/WORM (simplest, broadest trust):**
S3 Object Lock or Azure immutable blob. `anchor_id` is the object key + version ID. `verify` reads the object and compares the hash.

**Priority 2 — Sigstore Rekor (most broadly trusted public option):**
RFC 6962-style Merkle log. `anchor_id` is the log index. `verify` calls the Rekor API with the inclusion proof.

**Priority 3 — Mycelium Trails (on-chain, cross-system):**
Reads `action_ref` from the evidence file, posts to Base/Arbitrum, returns tx hash as `anchor_id`. Designed to work with the SafeAgent × DashClaw × Mycelium Trails joint interface spec. Suitable for regulated environments requiring immutable, cross-operator audit trails.

---

## Compliance mapping

| Control | How anchoring satisfies it |
|---------|---------------------------|
| EU AI Act Art. 12 (2026-08-02) | Evidence of AI system operation preserved in tamper-evident form verifiable by national competent authority |
| SOC 2 CC7.x | Detection of unauthorized changes to system components (evidence artifacts) |
| ISO 27001 A.12.4 | Event logging protected against tampering |
| FCA SYSC 9.1 | Records sufficient for FCA to monitor compliance with its requirements |
| Basel III BCBS 239 | Data lineage auditable by regulators independent of reporting firm |

---

## Implementation path

1. `EvidenceAnchor` ABC + `AnchorReceipt` dataclass in `agt-evidence` package
2. `action_ref` derivation as a standalone utility (no anchor dependency)
3. Schema: `anchors: []` array added as optional to `agt-evidence.json`
4. CLI: `agt verify --anchor` flag with plugin loader
5. Reference backend: filesystem/WORM
6. Reference backend: Sigstore Rekor
7. Plugin PR: Mycelium Trails (after core interface is merged)

Steps 1–4 are AGT-internal. Steps 5–7 are separate PRs, including from external contributors.

---

## Open questions

- Should `action_ref` derivation live in a shared `agt-core` utility or in `agt-evidence`?
- Plugin discovery mechanism: entry points, explicit registration, or config file?
- Should `anchors` support multiple backends per evidence file (already in the schema above) or limit to one?
