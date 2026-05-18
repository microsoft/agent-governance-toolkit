# Mycelium Trails — AGT EvidenceAnchor community plugin

Implements the [`EvidenceAnchor`](../../docs/proposals/MYCELIUM-EXTERNAL-ANCHOR-PROPOSAL.md) SPI
backed by [Mycelium Trails](https://argentum.rgiskard.xyz) on Arbitrum.

Evidence hashes are written as append-only trail records. Once anchored, a record cannot be
modified or deleted — the tamper-evidence guarantee holds without trusting the operator's
infrastructure.

## Install

```bash
pip install requests
```

No other dependencies required.

## Usage

```python
from mycelium_trails import MyceliumAnchor

anchor = MyceliumAnchor(agent_id="my-agent")

# Write evidence to Mycelium Trails
receipt = anchor.anchor(
    evidence_hash="sha256:abc123...",
    metadata={
        "action_type": "code.execute",   # optional, default: "agt:evidence_anchor"
        "scope": "ci-pipeline",          # optional, default: "agt-evidence"
    },
)
print(receipt.anchor_id)    # trail_id on Mycelium
print(receipt.anchored_at)  # RFC 3339 UTC timestamp

# Verify independently — no AGT runtime needed
result = anchor.verify("sha256:abc123...", receipt)
# result.status == AnchorVerifyStatus.VERIFIED
# result.inclusion_proof.proof_data["tx_hash"] — Arbitrum transaction
# result.inclusion_proof.proof_data["explorer_url"] — Arbiscan link
```

## Registration with AGT

```python
from mycelium_trails import MyceliumAnchor

# Explicit registration as required by AGT
agt_registry.register("mycelium", MyceliumAnchor())
```

## action_ref derivation

Each anchored record includes an `action_ref` — a deterministic content-addressed identifier
computable by any party holding the four preimage fields:

```
action_ref = SHA-256(JCS({ agent_id, action_type, scope, timestamp }))
```

Specification: [`docs/spec/action-ref.md`](https://github.com/giskard09/argentum-core/blob/main/docs/spec/action-ref.md)

The same derivation is implemented independently by
[SafeAgent](https://github.com/azender1/SafeAgent),
[NEXUS](https://nexus-agent-xa12.onrender.com/receipt),
and [CrewAI idempotency key](https://github.com/crewAIInc/crewAI/pull/5822) — convergent
implementations against a shared spec.

## Failure semantics

`anchor()` raises `RuntimeError` on network failure. The AGT runtime applies mode semantics
(`enforce` / `queue` / `best_effort`) based on the registered policy. The plugin does not
swallow errors.

## Tests

```bash
pytest community-plugins/mycelium_trails/tests/ -v
```

19 tests covering: `action_ref` derivation (known vectors, determinism, JCS key order),
`anchor()` happy path + metadata forwarding + network failure, `verify()` happy path +
hash mismatch + 404 + network error + fallback without action_ref + Arbiscan URL.

## Public endpoint

`https://argentum.rgiskard.xyz` — live on Arbitrum.

`GET /status` returns service health. `GET /trails/verify?payment_hash=<hash>` verifies
any anchored record independently.
