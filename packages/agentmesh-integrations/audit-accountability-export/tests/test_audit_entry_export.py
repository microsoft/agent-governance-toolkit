# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for AuditEntry external accountability export."""

from agentmesh.services.audit import AuditService

from audit_accountability_export import (
    accountability_export_to_eeoap_statement,
    audit_entry_to_accountability_export,
)


def test_log_action_export_uses_real_auditservice_output():
    service = AuditService()

    entry = service.log_action(
        "did:mesh:alice",
        "read_file",
        resource="urn:demo:file-001",
        data={
            "input_refs": ["urn:demo:file-001"],
            "output_refs": ["urn:demo:file-001#view"],
        },
        trace_id="trace-001",
    )
    export = audit_entry_to_accountability_export(entry)

    assert service.entry_count == 1
    assert entry.entry_hash
    assert export["actor_ref"] == "did:mesh:alice"
    assert export["subject_ref"] == "urn:demo:file-001"
    assert export["operation"] == "read_file"
    assert export["policy_digest"] is None
    assert export["decision"] == "success"
    assert export["occurred_at"]
    assert export["input_refs"] == ["urn:demo:file-001"]
    assert export["output_refs"] == ["urn:demo:file-001#view"]
    assert export["evidence_refs"][0]["entry_id"] == entry.entry_id
    assert export["evidence_refs"][0]["entry_hash"] == entry.entry_hash
    assert export["evidence_refs"][0]["digest"].startswith("sha256:")


def test_log_policy_decision_export_and_eeoap_mapping():
    service = AuditService()

    entry = service.log_policy_decision(
        "did:mesh:policy-agent",
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

    assert entry.event_type == "policy_decision"
    assert entry.entry_hash
    assert export["export_type"] == "agt.audit_entry.external_accountability_export"
    assert export["export_version"] == "0.1"
    assert export["actor_ref"] == "did:mesh:policy-agent"
    assert export["subject_ref"] == "urn:demo:client-note-001"
    assert export["operation"] == "metadata.enrich"
    assert export["policy_digest"].startswith("sha256:")
    assert export["decision"] == "allow"
    assert export["occurred_at"]
    assert export["input_refs"] == ["urn:demo:client-note-001"]
    assert export["output_refs"] == ["urn:demo:client-note-001-derived"]
    assert export["evidence_refs"][0]["entry_id"] == entry.entry_id

    assert statement["profile"] == "external.operation_accountability.mapping.example"
    assert statement["actor"]["id"] == export["actor_ref"]
    assert statement["subject"]["id"] == export["subject_ref"]
    assert statement["operation"]["name"] == export["operation"]
    assert statement["policy"]["digest"] == export["policy_digest"]
    assert statement["policy"]["decision"] == "allow"
    assert statement["evidence"]["artifacts"] == export["evidence_refs"]
    assert statement["validation"]["external_validator_required"] is False


def test_subject_ref_fallback_prefers_resource_then_subject_ref():
    service = AuditService()

    resource_entry = service.log_action(
        "did:mesh:alice",
        "inspect",
        resource="urn:demo:resource",
        data={"subject_ref": "urn:demo:subject"},
    )
    subject_entry = service.log_action(
        "did:mesh:alice",
        "inspect",
        data={"subject_ref": "urn:demo:subject"},
    )

    assert audit_entry_to_accountability_export(resource_entry)["subject_ref"] == "urn:demo:resource"
    assert audit_entry_to_accountability_export(subject_entry)["subject_ref"] == "urn:demo:subject"
