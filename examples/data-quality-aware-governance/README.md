# Example: Data Quality-Aware Agent Governance

## The Problem

Most agent governance frameworks answer one question:

> Is this agent **authorized** to perform this action?

In data-heavy workflows, there is a second question that matters equally:

> Is the **data** this agent is about to use actually trustworthy right now?

An agent can be fully authorized to query a dataset. But if that dataset
failed freshness checks, validation tests, or ownership requirements
earlier that day, authorization alone is not enough.

## The Pattern

This example demonstrates a **two-layer governance check**:

```
Request
  │
  ├─ Layer 1: AGT Policy Engine
  │   └─ Is this agent authorized for this action?
  │       ├─ NO  → Block (policy violation)
  │       └─ YES → proceed to Layer 2
  │
  └─ Layer 2: Data Quality Registry
      └─ Is the target dataset trustworthy right now?
          ├─ NO  → Block (data quality violation)
          └─ YES → Allow + write to unified audit log
```

The request is blocked if **either** layer fails.

## Concrete Case This Catches

```
Agent:   analyst-agent-01
Action:  database_query
Dataset: user_events

AGT policy evaluation:  ALLOWED (agent is authorized)
Data quality check:     BLOCKED

Reason:
  - Dataset stale by 14h (threshold: 6h)
  - Quality score: 0.72 (below 0.85 minimum)
  - Failed tests: not_null_user_id, accepted_values_event_type
```

Without Layer 2, the agent queries broken data with a clean audit trail.

## CTEF Alignment

The data quality snapshot that Layer 2 evaluates is the same object
that travels as a `data-quality` scheme in the CTEF v0.3.2
`source_version` registry (a2aproject/A2A#1786):

```json
{
  "scheme": "data-quality",
  "value": "<sha256_of_jcs_canonical_snapshot>"
}
```

Where the snapshot contains:
- `freshness_at` — last successful validation timestamp
- `validation_status` — pass | warn | fail
- `dataset_owner_did` — DID of the dataset owner

This means:
- AGT evaluates the **typed fields** at policy decision time
- CTEF carries the **integrity hash** across agent boundaries

Same snapshot. Two representations. Different jobs.

## Files

| File | Purpose |
|------|---------|
| `example.py` | Working Python using real AGT objects |
| `policy.yaml` | YAML policy defining agents and data quality thresholds |
| `README.md` | This file |

## Prerequisites

```bash
# From repo root
cd agent-governance-python/agent-os
pip install -e .
```

## Running the Example

```bash
cd examples/data-quality-aware-governance
python example.py
```

## Expected Output

```
============================================================
Data Quality-Aware Agent Governance — Example
============================================================

--- Scenario 1: Authorized agent, stale/failing dataset ---
Agent 'analyst-agent-01' requesting 'database_query' on dataset 'user_events'
  [AGT_POLICY] ✓ ALLOWED — Agent authorized for action
  [DATA_QUALITY] ✗ BLOCKED — Dataset stale by 14.0h (threshold: 6.0h)
  Final decision: BLOCKED (data_quality)

--- Scenario 2: Authorized agent, fresh/passing dataset ---
Agent 'analyst-agent-01' requesting 'database_query' on dataset 'revenue_metrics'
  [AGT_POLICY] ✓ ALLOWED — Agent authorized for action
  [DATA_QUALITY] ✓ ALLOWED — Fresh, score 0.97, all tests passing
  Final decision: ALLOWED (unified)

--- Scenario 3: Unauthorized agent (blocked at AGT layer) ---
Agent 'report-agent-02' requesting 'database_query' on dataset 'revenue_metrics'
  [AGT_POLICY] ✗ BLOCKED — Role report-agent-02 cannot use tool database_query
  Final decision: BLOCKED (agt_policy)
```

## The Data Quality Registry

The registry in this example is simulated. It mirrors the kind of metadata
a dbt-based governance platform exposes at runtime:

- Freshness threshold and last validation timestamp
- Quality score (composite of test pass rates)
- Failed test names
- Dataset owner DID

In production, replace `DataQualityRegistry` with a client that pulls
from real dbt artifacts, Great Expectations results, or a metadata
catalog like Atlan or DataHub.

## Related

- AGT Discussion: [#1795](https://github.com/microsoft/agent-governance-toolkit/discussions/1795)
- AGT Discussion: [#814](https://github.com/microsoft/agent-governance-toolkit/discussions/814)
- CTEF v0.3.2 data-quality scheme: [a2aproject/A2A#1786](https://github.com/a2aproject/A2A/issues/1786)
- Prototype: [SomeshZanwar/data-quality-aware-agent-governance](https://github.com/SomeshZanwar/data-quality-aware-agent-governance)
