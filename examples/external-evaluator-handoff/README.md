# External Evaluator Handoff

> Status: experimental, community-driven example

This example converts one or more AGT Decision BOMs into a deterministic,
strict-JSON request for a downstream evaluator. It demonstrates an
interface-first boundary: AGT remains the runtime governance and observation
source, while an external system may perform post-execution fitness,
adaptation, stability, or other longitudinal evaluation.

The example is deliberately offline. It does not call an external service,
change an AGT policy decision, authorize an action, mutate an audit record, or
turn an evaluation result into a governance decision.

## Why this boundary exists

Runtime governance and post-execution evaluation answer different questions:

- AGT answers whether an action was allowed, which policy applied, and what
  governance signals were observed.
- A downstream evaluator may compare multiple observed decisions over time and
  produce a reviewable assessment.
- That assessment is input to a separate review process. It is not permission
  and does not override AGT.

The handoff builds on AGT's existing
[`DecisionBOM`](../../agent-governance-python/agent-mesh/src/agentmesh/governance/decision_bom.py)
instead of introducing a second audit or policy model.

## Prerequisites

- Python 3.11+
- No API keys or network service required at runtime

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r examples/external-evaluator-handoff/requirements.txt
```

## Run

From the repository root:

```bash
python examples/external-evaluator-handoff/external_evaluator_handoff.py
```

The script prints one synthetic request. Its shape contains:

- a content-derived `request_id`;
- source Decision BOM observations;
- only explicitly allowlisted extra fields;
- fixed read-only and zero-authority declarations.

Example boundary:

```json
{
  "authority_boundary": {
    "evaluation_result_is_governance_decision": false,
    "execution_authorized": false,
    "policy_decision_overridden": false,
    "read_only": true,
    "source_records_mutated": false
  }
}
```

## Test

```bash
PYTHONPATH=agent-governance-python/agent-mesh/src \
  pytest -q examples/external-evaluator-handoff/test_external_evaluator_handoff.py
```

The tests cover deterministic output, exact field allowlisting, source
immutability, timezone rejection, empty-input rejection, strict JSON values,
and the permanent authority boundary.

## Data and security notes

- Decision BOM fields can contain policy, context, or trace data. The exporter
  therefore includes no optional fields unless their exact names are
  allowlisted by the caller.
- Allowlisted values are normalized into detached strict-JSON copies. Mutating
  a constructed request therefore does not mutate the source Decision BOM.
- The sample uses synthetic identifiers and values. Review tenant, privacy,
  retention, and cross-border requirements before exporting real records.
- `source_completeness` describes Decision BOM reconstruction coverage. It does
  not prove that an event was correct, authorized, or complete in the real
  world.
- A content hash identifies the canonical payload bytes before `request_id` is
  added, so the identifier itself is excluded from its hash input. The hash is
  not a signature, attestation, or proof of truth.

## Prior art and interoperability intent

The interface boundary was informed by SAEE's Evolution Intelligence Layer:
`https://github.com/joy7758/SAEE`. No SAEE source code, engine implementation,
or runtime dependency is included. The request is framework-neutral so other
external evaluators can consume the same observation boundary.
