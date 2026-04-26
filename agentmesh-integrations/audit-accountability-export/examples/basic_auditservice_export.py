# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Basic AuditService to external accountability export example."""

from __future__ import annotations

import json

from agentmesh.services.audit import AuditService

from audit_accountability_export import (
    accountability_export_to_eeoap_statement,
    audit_entry_to_accountability_export,
)


def main() -> None:
    audit = AuditService()

    audit.log_action(
        "did:mesh:research-agent",
        "metadata.enrich",
        resource="urn:demo:client-note-001",
        data={
            "input_refs": ["urn:demo:client-note-001"],
            "output_refs": ["urn:demo:client-note-001-derived"],
        },
    )
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

    print(json.dumps({"export": export, "eeoap_mapping_example": statement}, indent=2))


if __name__ == "__main__":
    main()
