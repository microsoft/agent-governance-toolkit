# ADR 003: Continuity Verification in ExecutionSandbox

## Status
Accepted

## Context
The `ExecutionSandbox` provides an in‑process soft sandbox for running untrusted agent code. It blocks dangerous imports, shadows `sys.modules`, and restricts builtins. However, it does not verify that the **authority context** (policy, delegation, observer identity) remains unchanged during sandbox execution. An agent could legitimately start with one policy version but, due to external changes (e.g., a policy update, delegated scope mutation, or identity drift), continue executing under a different authorisation context without any audit or rejection.

This creates a governance gap: the sandbox may be technically secure but the agent’s actions may no longer be authorised under the original approval. Compliance regimes (EU AI Act Art. 12, NIST AI RMF) require tamper‑evident audit trails and proof of continuity.

## Decision
We will add an **optional continuity verification module** to `ExecutionSandbox` with the following characteristics:
- **Pre‑execution hook**: captures SHA‑256 hashes of:
  - `observer_identity_hash` (agent_id, session_id, memory_state)
  - `reference_frame_hash` (policy_version, delegation_chain, evidence_state)
- **Post‑execution hook**: recomputes both hashes and compares.
- **Drift detection**: if either hash changes, the module produces a JSON trace (with diff) and, depending on the `enforcement_mode`, either **raises a `SecurityError`** (fail‑closed) or **only logs** (audit mode).
- **Configurable enforcement**: `enforcement_mode` in `SandboxConfig` – `"enforce"` (default) raises exception on drift; `"audit"` logs but does not block.
- **Opt‑in**: disabled by default (`enable_continuity=False`) to avoid any performance impact for existing users.

### Threat Model
The continuity verification operates inside the same process as the sandbox. It is **not** a cryptographic proof against a remote attacker – it is a defence‑in‑depth mechanism to detect accidental or malicious drift of the authority context that would otherwise go unnoticed. The sandbox’s own isolation (import hooks, restricted globals) remains the primary security boundary.

**Failure modes addressed:**
- A policy is updated while an agent is executing – the agent would continue under the old policy unless re‑authorised.
- A delegation chain is modified – an agent may gain or lose permissions without re‑evaluation.
- An agent’s memory state (e.g., goals, step count) changes in a way that voids the original approval.
- An observer identity (agent_id, session_id) is swapped – a different agent could resume a session.

**Why fail‑closed is the default:**  
Silently continuing under a drifted authority is a compliance violation and can lead to unauthorised actions. Raising `SecurityError` ensures that the system cannot proceed until the drift is resolved (e.g., re‑authorisation). This matches the sandbox’s existing fail‑closed behaviour for blocked imports and restricted builtins.

**Audit mode** allows operators to observe drift without disruption during initial rollout, then switch to `enforce` after validation.

## Consequences
- **Positive**:
  - Adds a deterministic, replayable audit trail for authority continuity.
  - Closes a governance gap without breaking existing sandbox behaviour (opt‑in).
  - Provides a clear migration path (audit mode → enforce).
- **Negative**:
  - Adds a small CPU overhead (SHA‑256 hashing) when enabled.
  - The `continuity_context` must be supplied by the caller; there is no automatic discovery of the agent’s authority context.
  - The module does not prevent in‑memory tampering – it only detects changes between pre‑ and post‑execution.

## Alternatives considered
1. **Audit‑only without enforcement** – Does not provide a deterministic block; operator may ignore logs.
2. **External service as mandatory dependency** – Creates lock‑in and extra complexity.
3. **Probabilistic anomaly detection** – Would introduce false positives and weaken auditability.

## References
- RFC #2873
- NIST AI RMF GOVERN and MEASURE functions
- EU AI Act Article 12 (tamper‑evident logging)