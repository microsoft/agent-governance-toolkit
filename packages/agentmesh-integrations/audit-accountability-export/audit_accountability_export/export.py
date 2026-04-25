# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Map AgentMesh audit entries to external accountability examples.

This module intentionally stays outside AGT runtime governance. It reads a real
``AuditEntry`` object and emits a small external export shape that downstream
accountability tooling can map further.
"""

from __future__ import annotations

from datetime import datetime
import hashlib
import json
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agentmesh.governance.audit import AuditEntry


EXPORT_TYPE = "agt.audit_entry.external_accountability_export"
EXPORT_VERSION = "0.1"
EEOAP_MAPPING_PROFILE = "external.operation_accountability.mapping.example"
EEOAP_MAPPING_VERSION = "0.1"


def canonical_sha256(value: Any) -> str:
    """Return a stable SHA-256 digest for JSON-like values."""
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        default=_json_default,
    )
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


def audit_entry_to_accountability_export(entry: AuditEntry) -> dict[str, Any]:
    """Build the smallest external accountability export from an ``AuditEntry``.

    The export is an interoperability shape, not a new AGT runtime evidence
    format. It keeps the source AGT audit entry as an evidence reference.
    """
    data = entry.data or {}
    policy_context = _policy_context(entry)

    return {
        "export_type": EXPORT_TYPE,
        "export_version": EXPORT_VERSION,
        "actor_ref": entry.agent_did,
        "subject_ref": _subject_ref(entry),
        "operation": entry.action,
        "policy_digest": canonical_sha256(policy_context) if policy_context else None,
        "decision": entry.policy_decision or entry.outcome,
        "occurred_at": _timestamp(entry.timestamp),
        "input_refs": _list_field(data.get("input_refs", [])),
        "output_refs": _list_field(data.get("output_refs", [])),
        "evidence_refs": [
            {
                "type": "agt.audit_entry",
                "entry_id": entry.entry_id,
                "event_type": entry.event_type,
                "entry_hash": entry.entry_hash,
                "digest": canonical_sha256(entry.model_dump(mode="json")),
            }
        ],
    }


def accountability_export_to_eeoap_statement(export: dict[str, Any]) -> dict[str, Any]:
    """Map an accountability export into an EEOAP-like example statement.

    This mapping does not import or invoke external validators and does not imply
    official AGT runtime support for any external profile.
    """
    return {
        "profile": EEOAP_MAPPING_PROFILE,
        "profile_version": EEOAP_MAPPING_VERSION,
        "actor": {
            "id": export.get("actor_ref"),
        },
        "subject": {
            "id": export.get("subject_ref"),
        },
        "operation": {
            "name": export.get("operation"),
            "occurred_at": export.get("occurred_at"),
        },
        "policy": {
            "digest": export.get("policy_digest"),
            "decision": export.get("decision"),
        },
        "provenance": {
            "source_export_type": export.get("export_type"),
            "source_export_version": export.get("export_version"),
        },
        "evidence": {
            "references": [
                {"role": "input", "ref": ref}
                for ref in export.get("input_refs", [])
            ]
            + [
                {"role": "output", "ref": ref}
                for ref in export.get("output_refs", [])
            ],
            "artifacts": export.get("evidence_refs", []),
        },
        "validation": {
            "status": "not_validated",
            "external_validator_required": False,
        },
    }


def _policy_context(entry: AuditEntry) -> dict[str, Any] | None:
    """Return the minimal policy context included in the external digest.

    This helper intentionally limits the digest input to a smallest-stable
    interoperability shape rather than defining a new AGT-native policy format.
    """
    data = entry.data or {}
    context = {
        key: value
        for key, value in {
            "policy_decision": entry.policy_decision,
            "matched_rule": entry.matched_rule,
            "policy_name": data.get("policy_name"),
        }.items()
        if value not in (None, "")
    }
    return context or None


def _subject_ref(entry: AuditEntry) -> str | None:
    """Resolve a subject reference using the narrowest stable fallback chain.

    Prefer the direct audit resource first, then `target_did`, then an explicit
    `subject_ref` in `AuditEntry.data` when present.
    """
    data = entry.data or {}
    return entry.resource or entry.target_did or data.get("subject_ref")


def _timestamp(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _list_field(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)
