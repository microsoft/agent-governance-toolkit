# ADR 0026: DecisionAssure Governance Learning Loop

**Status:** Draft
**Date:** 2026-06-19
**Author:** Akhilesh Warik (a1k7)
**PR:** #3113 (closed for ADR review)
**Issue:** #3116

---

## Context

The Agent Governance Toolkit currently provides:

- Policy evaluation (YAML/OPA/Cedar)
- Identity (SPIFFE/DID/mTLS)
- Audit logging (tamper‑evident)
- Replay
- MCP Security Gateway
- Trust and sandboxing

However, AGT does not currently have a dedicated mechanism for:

1. **Discovering emergent capabilities** from multi‑agent traces without pre‑defined rules.
2. **Producing verifiable witnesses** that explain why a capability existed and what minimal actions created it.
3. **Routing unknown capabilities to human review** with suggested labels and confidence scores.
4. **Evolving the governance ontology** from approved reviews.
5. **Replaying historical traces** under updated governance knowledge.
6. **Measuring governance coverage growth** over time.

This ADR proposes adding a **Governance Learning Loop** to AGT that addresses these gaps.

---

## Decision

We will add a new integration: **DecisionAssure Continuity Kernel**, which provides:

### 1. Emergent Capability Discovery

- Unsupervised clustering of agent traces using DBSCAN and TF‑IDF vectorisation.
- Discovers capability clusters (e.g., `read_credentials` + `export_data` → Credential Exfiltration).
- No pre‑defined labels required.

### 2. Capability Witness Engine

- Generates cryptographic witnesses for each discovered capability.
- Each witness contains:
  - Capability classification
  - Minimal action set
  - Confidence score
  - Severity
  - Counterfactual evidence
  - Witness hash
  - Governance recommendation (DENY / HUMAN_REVIEW / MONITOR / ADMIT)

### 3. Counterfactual Verification

- Removes each required action one at a time and confirms:
  - "If any action is removed, the capability no longer exists."
- Provides minimal witness verification and stronger causal evidence.

**Example:** If the system discovers `read_credentials` + `export_data` → Credential Exfiltration, the counterfactual test removes `read_credentials` and checks whether `export_data` alone still constitutes a capability. It does not. The capability disappears. This proves that `read_credentials` is causally necessary for the capability.

### 4. Human Review Queue

- Unknown capabilities are routed to governance analysts.
- Queue items include:
  - Suggested label
  - Similarity confidence
  - Novelty score
  - Impact score
  - Priority score

The Human Review Queue is a separate approval surface from AGT's existing `require_approval` flow (ADR-0030). The existing flow handles operational approvals during execution. The learning loop's queue handles governance‑level approvals for ontology updates. The two surfaces do not intersect.

### 5. Ontology Evolution

- Approved reviews become governance knowledge.
- Versioned ontology evolution is recorded in a ledger.
- Future traces with the same action set are auto‑classified.

### 6. Historical Replay

- After ontology evolution, the system replays historical traces.
- Answers: "What incidents would have been detected if this capability had been known earlier?"
- Outputs: previously missed incidents, newly classified traces, coverage increase.

### 7. Governance Knowledge Accumulation Index (GKAI)

- A new metric that tracks long‑term governance learning.
- Measures: base coverage, latest coverage, total knowledge gain, average gain per version.

**GKAI Formula:**
GKAI = 0.5 × (current_coverage) + 0.3 × (knowledge_gain) + 0.2 × (average_gain_per_version × 10)


The metric is clamped between 0 and 100, with higher values indicating more mature governance. It is auditable: every component is derived from observable trace data and the ontology ledger. A reviewer can independently recompute the GKAI from the same data sources and verify the result.

### Scope: Post‑Execution, Not Inline

The Governance Learning Loop processes traces **post‑execution**, not inline. It does not intercept the policy evaluation path or introduce latency into agent execution. The loop runs as an asynchronous, offline process that analyzes historical traces, discovers patterns, and evolves the ontology. The policy evaluator continues to enforce static rules inline at the speed required for agentic execution.

---

## Alternatives Considered

### Alternative 1: Manual Ontology Maintenance

**Description:** Maintain the governance ontology manually (YAML files, human‑curated).

**Why rejected:** Does not scale with agent traces. Cannot discover unknown capabilities without manual analysis. No replay or coverage measurement.

### Alternative 2: Separate Service (External to AGT)

**Description:** Build the Governance Learning Loop as a separate service outside AGT.

**Why rejected:** Would create fragmentation. AGT users would need to run an additional service. No native integration with AGT's policy engine, identity, or audit logs.

### Alternative 3: Extend Existing AGT Features

**Description:** Add capability discovery and ontology evolution to existing AGT modules (e.g., MCP, Agent OS).

**Why rejected:** Scope is too large for a single module. The Governance Learning Loop has a distinct lifecycle (discovery → review → evolution → replay → measurement) that is best kept as a separate, cohesive integration.

---

## Consequences

### Positive

- AGT gains a self‑improving governance capability.
- Unknown multi‑agent capabilities can be discovered without manual rules.
- Governance coverage becomes measurable and auditable.
- Historical traces can be replayed under updated governance knowledge.
- TRACE‑compatible capability witnesses provide portable governance evidence.

### Negative

- Adds a new integration (decisionassure-continuity) and its dependencies (`scikit‑learn`, `numpy`, `click`).
- Requires human reviewers to approve unknown capabilities (operational overhead).
- Synthetic traces used for validation – real‑world validation is ongoing.

### Neutral

- The system is optional – AGT users can choose to enable it.
- The integration is MIT licensed and maintained by the contributor.

---

## Security Considerations

### Threat Model for Self‑Improving Governance

The Governance Learning Loop introduces a self‑improving component to AGT. The primary threats are:

1. **Adversarial Trace Injection**: An attacker submits traces designed to poison the ontology.
   - Mitigation: Confidence thresholds (default 50%) reject low‑confidence discoveries. Human review gates all ontology changes. All traces are recorded immutably.

2. **Ontology Drift**: The ontology evolves in a direction that reduces governance coverage.
   - Mitigation: Ontology changes are versioned. Historical replay compares coverage before and after each change. Regressions are detected and can be rolled back.

3. **Replay Attacks**: The same capability is re‑submitted repeatedly.
   - Mitigation: Duplicate detection using witness hash deduplication. The system tracks `first_seen` and `occurrence_count` to avoid redundant reviews.

4. **Denial of Service through High‑Volume Submissions**: An attacker floods the system with traces.
   - Mitigation: Discovery requires a minimum occurrence count before a candidate is generated. This reduces noise in the queue.

### Blast‑Radius Bounds

If the learning loop converges on a bad policy:

- **Impact is bounded**: Only capabilities that have been human‑approved affect governance decisions.
- **Replay provides validation**: Every ontology change is replayed against historical traces. If coverage decreases, the change can be reverted.
- **Fail‑closed default**: If the learning loop is unavailable, AGT falls back to its existing static governance. The learning loop is advisory, not mandatory.

## Interaction with Immutable Audit Trail

The Governance Learning Loop does not modify AGT's existing audit logs. It creates new, append‑only records:

- **Trace records**: Immutable records of every uploaded trace.
- **Witness records**: Cryptographic proofs of discovered capabilities.
- **Ledger entries**: Versioned ontology changes with reviewer signatures.

These records can be independently verified and audited alongside AGT's existing audit trail.

### Audit Trail Guarantee

The Governance Learning Loop provides a **detection guarantee**: it records what happened and provides replayable evidence that a capability emerged. It does not provide a **construction guarantee**: it does not claim that capabilities are unreachable by construction.

The "couldn't have happened" guarantee is provided by AGT's existing structural controls (policy enforcement, identity verification, sandboxing, fail‑closed semantics). These two guarantees are orthogonal. The audit trail captures the first, references the second, and does not attempt the third.

---

## Status

**Draft** – awaiting maintainer review.

**Next Steps:**
1. Maintainers review and approve ADR.
2. Reopen implementation PR referencing the ADR.
3. Integration is merged into AGT under `extensions/decisionassure-continuity`.

---

## References

- PR #3113 (closed for ADR review)
- [DecisionAssure Continuity Kernel](https://github.com/a1k7/integrations/tree/main/decisionassure_continuity)
- [TRACE Specification v0.1](https://github.com/agentrust-io/trace)

---

### Assurance Classes and Reviewability

The following table clarifies which governance guarantee each layer provides and how a reviewer can verify it:

| Guarantee Class | Reviewer Checks By | Provided by this ADR? |
|-----------------|-------------------|----------------------|
| **Detection / what happened** | Replaying the trace and verifying the witness | ✅ Yes – this is the Governance Learning Loop |
| **Enforced at the gate** | Checking the policy/sandbox/fail-closed control event or log | ✅ Existing AGT structural controls (referenced, not modified) |
| **Unreachable by construction** | Inspecting the constructed reachable surface without replaying the run | ❌ No – out of scope for this ADR (a different assurance class) |

This keeps the boundary clear:

- The Governance Learning Loop **strengthens detection and evidence** of emergent capabilities.
- It does **not** claim construction-level non-reachability.
- The audit trail captures the first layer, references the second, and does not attempt the third.
- This aligns with the maintainer review question: *"How does the learning loop interact with the immutable audit trail guarantees?"* — the table makes explicit which guarantee each layer provides and how a reviewer checks it, without mixing the three assurance mechanisms.