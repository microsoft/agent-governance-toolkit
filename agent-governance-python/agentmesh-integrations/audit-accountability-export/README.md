# Audit Accountability Export

This integration is a small example adapter for mapping real AgentMesh
`AuditEntry` / `AuditService` output into a smallest-stable external
accountability export shape.

It follows the interoperability discussion in
[issue #1314](https://github.com/microsoft/agent-governance-toolkit/issues/1314)
and the docs-only note merged in
[PR #1319](https://github.com/microsoft/agent-governance-toolkit/pull/1319).

## Purpose

The adapter treats AGT audit output as upstream runtime-governance evidence and
emits a compact downstream accountability shape with:

- actor reference
- subject reference
- operation
- policy digest
- decision
- occurrence timestamp
- input and output references
- evidence references

The EEOAP mapping function is an external mapping example. It does not import an
external validator and does not imply official AGT runtime support for EEOAP.

## Non-goals

- no AGT runtime changes
- no `AuditEntry` / `AuditService` contract changes
- no replacement of `agt verify --evidence`
- no new AGT-native evidence format
- no required dependency on EEOAP or external validators
- no production compliance claim

## Pipeline

```text
AuditService output
-> AuditEntry
-> external accountability export shape
-> EEOAP mapping example
```

## Example

```python
from agentmesh.services.audit import AuditService
from audit_accountability_export import (
    accountability_export_to_eeoap_statement,
    audit_entry_to_accountability_export,
)

audit = AuditService()
entry = audit.log_policy_decision(
    "did:mesh:research-agent",
    "metadata.enrich",
    decision="allow",
    policy_name="approved-metadata-policy",
    data={
        "subject_ref": "urn:demo:client-note-001",
        "input_refs": ["urn:demo:client-note-001"],
        "output_refs": ["urn:demo:client-note-001-derived"],
    },
)

export = audit_entry_to_accountability_export(entry)
statement = accountability_export_to_eeoap_statement(export)
```

## Export shape

```json
{
  "export_type": "agt.audit_entry.external_accountability_export",
  "export_version": "0.1",
  "actor_ref": "...",
  "subject_ref": "...",
  "operation": "...",
  "policy_digest": "...",
  "decision": "...",
  "occurred_at": "...",
  "input_refs": [],
  "output_refs": [],
  "evidence_refs": []
}
```

## Sensitivity note

Exported data may include values derived from `AuditEntry.data`. Review and
redact sensitive fields before sharing externally. This example is intended to
demonstrate a smallest-stable external accountability export shape, not to
define a blanket-safe export for all audit records.

## Running locally

From the repository root:

```bash
pip install .[dev]

PYTHONPATH=agent-governance-python/agent-mesh/src:agent-governance-python/agentmesh-integrations/audit-accountability-export \
  python -m pytest agent-governance-python/agentmesh-integrations/audit-accountability-export/tests -q

PYTHONPATH=agent-governance-python/agent-mesh/src:agent-governance-python/agentmesh-integrations/audit-accountability-export \
  python agent-governance-python/agentmesh-integrations/audit-accountability-export/examples/basic_auditservice_export.py
```

The tests create real `AuditService` entries and use the returned `AuditEntry`
objects as the source. They do not rely on static synthetic fixtures.
