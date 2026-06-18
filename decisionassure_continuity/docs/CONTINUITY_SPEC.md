
---

## `decisionassure_continuity/docs/CONTINUITY_SPEC.md`

```markdown
# Constitutional Continuity Verification – Specification

## 1. Purpose

This specification defines the Constitutional Continuity Verification (CCV) protocol for proving that an AI agent remained the same agent across a sequence of actions, delegations, and context changes.

## 2. Core Concepts

- **Witness**: A cryptographically‑hashed record of agent state at a single step.
- **Witness Chain**: A blockchain‑style sequence of witnesses where each witness points to the previous one.
- **Continuity**: The property that the agent's identity, constitution, and reference frame have not changed without re‑authorisation.
- **Drift**: A change in any of the core fields (observer hash, reference frame, constitution) between steps.

## 3. Witness Format

Each witness must contain:

| Field | Type | Description |
|-------|------|-------------|
| index | integer | Step number |
| previous_witness_hash | string | SHA‑256 hash of the previous witness |
| agent_id | string | Agent identifier |
| session_id | string | Session identifier |
| constitution_hash | string | Hash of the agent's constitution (policy, rules) |
| observer_hash | string | Hash of the agent's identity context (memory, state) |
| reference_frame_hash | string | Hash of the external reference frame (delegation, evidence) |
| action_hash | string | Hash of the action performed |
| timestamp | datetime | Time of witness creation |
| witness_hash | string | SHA‑256 hash of this witness |

## 4. Verification Algorithm

1. Rebuild the witness chain from the input list.
2. Verify chain integrity (each witness's `witness_hash` matches its computed hash, and `previous_witness_hash` matches the previous witness's hash).
3. Establish baseline (first witness or provided baseline).
4. For each witness, compare `observer_hash`, `reference_frame_hash`, and `constitution_hash` to the baseline.
5. Compute drift scores: proportion of changes per field.
6. Compute continuity score: `1 - (observer_drift*0.4 + ref_drift*0.3 + constitution_drift*0.3)`.
7. Determine verification status:
   - `PASS` if score >= 0.8 and identity & constitution preserved.
   - `PARTIAL` if score >= 0.5.
   - `FAIL` otherwise.

## 5. Security Considerations

- Witness hashes are computed using SHA‑256 (collision‑resistant).
- The chain can be signed with Ed25519 for tamper‑evidence.
- Each witness includes a timestamp for temporal ordering.