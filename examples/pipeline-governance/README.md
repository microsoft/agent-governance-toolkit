# Pipeline Governance — Example

Demonstrates governance of multi-node distributed LLM inference with Cedar policy evaluation, signed governance receipts, and cross-shard trust propagation.

## What This Shows

Every distributed pipeline step is:
1. **Policy-checked** against a Cedar policy (rank permissions, resource limits, model allowlist)
2. **Receipted** with a governance receipt linking the decision to the action
3. **Signed** with Ed25519 for non-repudiation
4. **Hash-chained** so verifiers can detect insertion or deletion of steps without replaying the full session

This pattern applies to any system where multiple compute nodes collaborate on a single inference request and need auditable proof that each step complied with governance policy.

## Governance Rules

The Cedar policy at `policies/pipeline-governance.cedar` enforces:

| Rule | Type | Description |
|------|------|-------------|
| Rank authorization | permit | Only `r0` and `r1` can load shards |
| Model allowlist | permit | Only approved models (`gemma-3-12b-qat4`, `qwen3-4b-bf16`) can run inference |
| Receipt-gated transfer | permit | Cross-shard data transfer requires a valid receipt from the prior step |
| Memory budget | forbid | Shards exceeding the node's memory budget are denied |
| Audit trail | permit | All steps are logged to an audit trail |

## Setup

```bash
# From the repository root
pip install -r examples/pipeline-governance/requirements.txt
```

## Run

```bash
python examples/pipeline-governance/demo.py
```

## Expected Output

```
🛡️  Pipeline Governance — Demo

Cedar policy: policies/pipeline-governance.cedar
Signing: Ed25519

────────────────────────────────────────────────────────────────────────────────

📋 Scenario 1: Legitimate two-node pipeline inference

Step   Action                   Principal      Decision   Signed   Chain OK
────────────────────────────────────────────────────────────────────────────────
  ✅ 0    LoadShard                r0             allow      yes      True
  ✅ 1    LoadShard                r1             allow      yes      True
  ✅ 2    RunInference             r0             allow      yes      True
  ✅ 3    CrossShardTransfer       r0             allow      yes      True
  ✅ 4    RunInference             r1             allow      yes      True
  ✅ 5    WriteAudit               r0             allow      yes      True

📋 Scenario 2: Policy violations (should be denied)

Step   Action                   Principal      Decision   Reason
────────────────────────────────────────────────────────────────────────────────
  🚫 6    LoadShard                r0             deny       shard_size exceeds memory_budget
  🚫 7    LoadShard                r2             deny       no matching permit rule
  🚫 8    RunInference             r0             deny       model 'llama-4-maverick' not in approved list
  🚫 9    CrossShardTransfer       r0             deny       missing valid receipt
  🚫 10   LoadShard                r1             deny       shard_size exceeds memory_budget

📊 Audit Summary:
   Total steps:     11
   Allowed:         6
   Denied:          5
   Chain valid:     True
```

## Architecture

```
┌─────────────┐     ┌─────────────┐
│   Rank 0    │     │   Rank 1    │
│  (shard 0)  │────▶│  (shard 1)  │
│             │     │             │
│  LoadShard  │     │  LoadShard  │
│  RunInfer   │     │  RunInfer   │
│  Transfer───┼────▶│             │
└──────┬──────┘     └──────┬──────┘
       │                   │
       ▼                   ▼
┌──────────────────────────────────┐
│       Governance Layer           │
│  ┌────────────────────────────┐  │
│  │   Cedar Policy Evaluator   │  │
│  └──────────┬─────────────────┘  │
│             │                     │
│  ┌──────────▼─────────────────┐  │
│  │   Governance Receipt       │  │
│  │   (Ed25519 + hash chain)   │  │
│  └────────────────────────────┘  │
└──────────────────────────────────┘
```

## Key Concepts

### Rank Authorization
Each compute node (rank) must be explicitly permitted to load shards. Unauthorized ranks (e.g., `r2`) are denied by default.

### Memory Budget Enforcement
Before loading a shard, the Cedar policy checks `shard_size_mb > memory_budget_mb`. This prevents out-of-memory crashes in resource-constrained environments.

### Model Allowlisting
Only approved models can run inference. This prevents unauthorized model usage in production pipelines.

### Receipt-Gated Cross-Shard Transfer
Data can only flow between shards if the sending shard has a valid governance receipt. This creates a chain of trust across the pipeline.

### Hash-Chained Audit Trail
Each receipt includes the hash of the previous receipt (`parent_receipt_hash`). Verifiers can detect if any step was inserted, deleted, or tampered with by checking the chain.

## Files

- `demo.py` — End-to-end pipeline governance demo (self-contained, no GPU required)
- `policies/pipeline-governance.cedar` — Cedar policy for distributed inference governance
- `requirements.txt` — `cryptography` for Ed25519 signing

## Extending This Example

- Add more ranks for multi-node inference (>2 nodes)
- Add Cedar conditions for network topology (e.g., only allow transfers between adjacent ranks)
- Integrate with real inference frameworks (MLX, vLLM, TGI) by replacing `mock_inference_step()`
- Add receipt persistence to a database or blockchain for long-term audit

## Prior Art

- Distributed inference on Apple Silicon via [Hippo Pipeline](https://github.com/lawcontinue/hippo-pipeline) — real-world pipeline parallelism with MLX
- [reasoning-attestation-governed](../reasoning-attestation-governed/) — SAE feature attestation with signed envelopes
- [mcp-receipt-governed](../mcp-receipt-governed/) — MCP tool-call receipt signing

## Limitations

This example is designed for **learning and prototyping** purposes. Key limitations to be aware of:

- **Simplified Cedar evaluator** — The inline `CedarPolicyEvaluator` covers only the subset of Cedar used in this demo. For production, use the [official Cedar engine](https://www.cedarpolicy.com/).
- **Single-key signing** — All receipts are signed with one Ed25519 key. Production systems should use proper key management (HSM, KMS, or hardware-backed keys).
- **No replay protection** — Governance receipts do not include nonces or short-lived validity windows. Add these for production replay-attack prevention.
- **Not thread-safe** — `PipelineGovernanceAdapter` maintains in-memory state (`_last_receipt_hash`, `_step_index`). Wrap with locks or use per-request instances for concurrent use.
- **Mock inference** — The pipeline steps are mocked. Integrate with real inference frameworks (MLX, vLLM, TGI) by replacing `mock_inference_step()`.


## License

This example is licensed under the MIT License.
