# DecisionAssure Impact: Counterfactual Governance Replay and Change‑Impact Analysis

**Status:** Ready for review  
**Date:** 2026‑09‑03  
**Author:** @a1k7  

---

## Context

AGT provides runtime governance enforcement (`MerkleAuditChain`, `AuditEntry`, `NativeAdapterRuntime`), **continuity verification** (`decisionassure_continuity`), and now portable evidence via **TRACE v0.1** (ADR 0032). These capabilities answer:

- *Was this decision admissible at the time of execution?*
- *Can I verify it offline?*

However, a critical question remains unanswered:

> *“What happens to all the agents already deployed if I change a policy, authority, model, or tool tomorrow?”*

When a policy is tightened, a delegation expires, a model is updated, or a tool capability expands, previously allowed actions may become **inadmissible** – but nobody knows which decisions will break **until after the change is deployed**. This is the **policy‑change propagation gap** identified in AGT’s ADRs and limitations.

**Existing AGT components that contribute raw material for a solution:**
- The Merkle‑chained audit log captures every decision trace.
- `decisionassure_continuity` verifies that a single decision remains admissible against a *fixed* snapshot.
- TRACE records provide a portable, signed snapshot of the governance state at execution time.

What is missing is a **batch counterfactual engine** that replays historical traces against a *proposed* future governance state and quantifies the difference.

---

## Decision

We introduce **DecisionAssure Impact** – a standalone module that performs **counterfactual governance replay** across historical decision traces.

### Core Capabilities

1. **Trace Ingestion** – Reads JSONL traces (compatible with AGT’s audit log format, including transaction amounts, evidence age, tool permissions, model version).
2. **Governance State Definition** – Models policy (YAML), authority (delegations with validity), capability (tool permissions), evidence freshness, and model approval.
3. **Counterfactual Replay** – For each decision, evaluates admissibility under *both* the current and proposed governance states, using the exact historical timestamp and context.
4. **Governance Diff** – Identifies every decision that changes from `ADMISSIBLE` to `INADMISSIBLE` (or vice versa).
5. **Blast Radius** – Aggregates affected agents, tools, policy versions, and decision types.
6. **Business Exposure** – Sums transaction amounts from affected decisions.
7. **Severity & Recommendation** – Combines exposure, impact rate, action criticality, and direction of change to output `ALLOW`, `REVIEW`, or `BLOCK`.

### Integration with AGT’s Existing Architecture

DecisionAssure Impact is designed to **complement** rather than replace existing AGT modules:

- It consumes the same audit trail that AGT already records.
- It reuses the continuity verification logic (admissibility checks) but applies it to *batches* of historical decisions.
- It can be invoked as a **CI gate** (pre‑merge) or as a **pre‑deployment validation** step.
- It does **not** modify any core AGT components (no changes to `agentmesh`, `agent_os`, or existing governance interfaces).

### CLI Interface

The module provides a CLI command `decisionassure` with two subcommands:

```bash
# Analyse the impact of a proposed policy change
decisionassure impact \
    --traces <traces.jsonl> \
    --policy-current <current.yaml> \
    --policy-proposed <proposed.yaml>

# Detect governance drift in production traces
decisionassure detect-drift \
    --traces <traces.jsonl> \
    --policy-current <current.yaml> \
    --drift-threshold <hours>


The impact command exits with code 1 if the recommendation is BLOCK, making it suitable for CI/CD pipelines.

Example Output (from synthetic bank workload)

ADMISSIBLE → INADMISSIBLE:  57
Impact rate:             18.39%
Agents affected:            43
Tools affected:              1
Estimated exposure:   ₹2,564,702
Severity:                  HIGH
Recommendation:          BLOCK

Consequences

Positive

Predictability – Governance teams can now anticipate the blast radius of any change before deployment.
Risk quantification – Exposure estimates provide a business‑aligned metric for change approval.
Compliance – DecisionAssure Impact generates auditable reports that can be used to justify change decisions.
CI/CD ready – The BLOCK exit code prevents accidental regressions.
Low coupling – The module is self‑contained and can be adopted incrementally.
Negative

Operational overhead – Running counterfactual replay on large trace volumes requires compute and storage. Performance can be optimised by sampling or incremental processing (future work).
Policy DSL – Uses YAML with simple condition expressions. Complex policies may require translation from existing AGT policy engines (Cedar, OPA). The current implementation is intentionally minimal for the MVP.
Alternatives Considered

Extending decisionassure_continuity – That module verifies a single decision against a static snapshot. It does not support batch replay or proposed‑state comparison.
Building a dashboard – A UI would be heavier and less useful for CI/CD. The CLI‑first approach aligns with AGT’s developer‑centric ethos.
Using a separate tool – Keeping the engine inside AGT ensures consistency with the audit log schema and governance abstractions.
Related Work

ADR 0032 (TRACE v0.1 Trust Records) – DecisionAssure Impact can consume TRACE‑signed traces to provide verifiable counterfactual evidence, strengthening the trust model.
decisionassure_continuity – This module is the runtime counterpart; DecisionAssure Impact is the offline, predictive counterpart.
AGT’s MerkleAuditChain – Provides the tamper‑evident trace data that feeds the replay engine.
Testing & Validation

Unit tests – pytest suite (6 tests) covering policy evaluation, diff computation, and drift detection.
Synthetic workload – Generated 100 traces (310 decisions) with a realistic bank refund scenario. Verified that tightening the refund limit from ₹50k to ₹40k correctly flags 57 decisions as INADMISSIBLE.
Manual validation – CLI commands were exercised and outputs inspected for correctness.
Future Work

Performance improvements – Parallel replay, incremental processing, and indexing for large trace datasets.
Additional dimensions – Support for model drift, tool version changes, and environment context.
Integration with AGT’s existing policy engines – Directly consume Cedar/OPA policies instead of a separate YAML DSL.
TRACE integration – Optionally consume TRACE records for offline verification of the baseline traces.
Review Notes

This PR is a restructured version of the initial prototype (previously PR #3851) following feedback from @imran‑siddique:

Package moved to agent-governance-python/agent-decisionassure/.
Examples relocated to examples/decisionassure/.
Root‑level scratch files removed.
No changes to agentmesh or agent_os.
All imports now use agent_decisionassure.
The module is ready for review and can be merged as a new experimental feature.

Signed-off‑by: @a1k7
PR: #3851 (re‑opened as a clean branch)
Related ADR: 0032 (TRACE)
Related module: decisionassure_continuity