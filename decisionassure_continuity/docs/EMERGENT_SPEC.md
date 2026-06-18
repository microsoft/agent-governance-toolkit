# Emergent Capability Detection – Specification

## 1. Purpose

Detect when a combination of agents creates a forbidden capability that no single agent possesses.

## 2. Input

- List of agent actions, each with:
  - `agent_id`
  - `action_type`
  - `tool`
  - `target` (optional)
  - `params` (optional)

## 3. Rule Set

Each rule defines:
- `id`
- `name`
- `description`
- `severity`
- `required_actions` – set of action types that must be present collectively

## 4. Output

- `capability_detected`: boolean
- `capability`: object with name, severity, etc.
- `contributing_agents`: list of agents involved
- `actions_involved`: list of actions that triggered the detection
- `confidence`: fraction of required actions present

## 5. Usage

```bash
continuity emergent '[{"agent_id":"alice","action_type":"read_database"},...]'

## 6. Capability Lineage

For each detected emergent capability, the system produces a lineage object that records:
- The capability ID and name.
- Each contributing agent with its specific role (discovery, aggregation, export, escalation, etc.).
- The action that triggered the contribution.
- A lineage hash (SHA‑256) that can be used to verify the lineage hasn't been tampered with.

This allows an auditor to answer: *How did this capability emerge?* not just *Did it emerge?*

## 7. Capability Witness

A Capability Witness is a cryptographic proof that a specific set of agent actions collectively form an emergent capability. It includes:

- The capability ID and name.
- A list of required actions (agent + action type).
- A SHA‑256 hash of the canonical representation of the required actions.
- A counterfactual analysis: if you remove any contributing agent, does the capability still exist?

This enables independent verification: an auditor can recompute the hash from the actions and compare it to the witness hash, ensuring the witness was derived from the exact set of actions.

## 8. Capability Discovery

The system can discover new emergent capabilities from a corpus of traces without prior knowledge of the capability patterns.

### Methodology

1. Convert each trace into an action signature.
2. Apply TF‑IDF vectorization to represent traces as feature vectors.
3. Cluster traces using DBSCAN.
4. For each cluster, extract the common action pattern.
5. Generate a Capability Witness for each discovered pattern.

### Output

- Capability ID (generated)
- Capability Name (auto‑generated)
- Required Actions (the minimal set of actions that define the capability)
- Confidence (fraction of traces in the corpus that contain the pattern)
- Occurrence Count
- Capability Witness (with hash)
- Trace Indices (for reproducibility)