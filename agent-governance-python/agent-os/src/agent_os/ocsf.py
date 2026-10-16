# Copyright (c) Microsoft Corporation. Licensed under the MIT License.
"""Open Cybersecurity Schema Framework (OCSF) v1.3.0 conversion and sink.

This module translates AGT governance, audit, and trace telemetry from
CloudEvents v1.0 schema into OCSF schema (Open Cybersecurity Schema Framework),
enabling direct ingestion into OCSF-native SIEM, XDR, and security data lakes
such as Amazon Security Lake, Splunk, Datadog, and IBM QRadar.

References:
    - OCSF Schema Specification: https://schema.ocsf.io/
    - ADR-0021: CloudEvents Envelope for Mesh Audit
    - AUDIT-COMPLIANCE-1.0 §20.4
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any, Sequence

from agent_os.event_sink import (
    GovernanceEvent,
    GovernanceEventKind,
    GovernanceEventSinkBase,
    SinkExportResult,
)

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

#: OCSF Schema version targeted by this converter.
OCSF_SCHEMA_VERSION = "1.3.0"

# OCSF Categories
OCSF_CATEGORY_FINDINGS = 2
OCSF_CATEGORY_IAM = 3
OCSF_CATEGORY_APPLICATION_ACTIVITY = 6

# OCSF Classes
OCSF_CLASS_SECURITY_FINDING = 2001
OCSF_CLASS_AUTHORIZE_SESSION = 3002
OCSF_CLASS_API_ACTIVITY = 6003

# OCSF Severities
OCSF_SEVERITY_UNKNOWN = 0
OCSF_SEVERITY_INFORMATIONAL = 1
OCSF_SEVERITY_LOW = 2
OCSF_SEVERITY_MEDIUM = 3
OCSF_SEVERITY_HIGH = 4
OCSF_SEVERITY_CRITICAL = 5
OCSF_SEVERITY_FATAL = 6

_SEVERITY_MAP: dict[str, tuple[int, str]] = {
    "info": (OCSF_SEVERITY_INFORMATIONAL, "Informational"),
    "informational": (OCSF_SEVERITY_INFORMATIONAL, "Informational"),
    "low": (OCSF_SEVERITY_LOW, "Low"),
    "med": (OCSF_SEVERITY_MEDIUM, "Medium"),
    "medium": (OCSF_SEVERITY_MEDIUM, "Medium"),
    "warn": (OCSF_SEVERITY_MEDIUM, "Medium"),
    "warning": (OCSF_SEVERITY_MEDIUM, "Medium"),
    "high": (OCSF_SEVERITY_HIGH, "High"),
    "critical": (OCSF_SEVERITY_CRITICAL, "Critical"),
    "fatal": (OCSF_SEVERITY_FATAL, "Fatal"),
}

# OCSF Dispositions
OCSF_DISPOSITION_ALLOWED = 1
OCSF_DISPOSITION_BLOCKED = 2
OCSF_DISPOSITION_QUARANTINED = 3
OCSF_DISPOSITION_ISOLATED = 4
OCSF_DISPOSITION_DROPPED = 5
OCSF_DISPOSITION_CUSTOM = 6
OCSF_DISPOSITION_OTHER = 99

# OCSF Statuses
OCSF_STATUS_SUCCESS = 1
OCSF_STATUS_FAILURE = 2
OCSF_STATUS_OTHER = 99


def _parse_time_ms(time_val: Any) -> tuple[int, str]:
    """Parse a datetime object or ISO8601 string into (epoch_ms, iso_str)."""
    if isinstance(time_val, datetime):
        dt = time_val if time_val.tzinfo else time_val.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000), dt.isoformat()
    if isinstance(time_val, (int, float)):
        # If timestamp is in seconds, convert to ms
        ms = int(time_val * 1000) if time_val < 1e11 else int(time_val)
        dt = datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)
        return ms, dt.isoformat()
    if isinstance(time_val, str) and time_val:
        try:
            clean = time_val.replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean)
            if not dt.tzinfo:
                dt = dt.replace(tzinfo=timezone.utc)
            return int(dt.timestamp() * 1000), time_val
        except Exception:
            pass
    now = datetime.now(timezone.utc)
    return int(now.timestamp() * 1000), now.isoformat()


def _map_disposition_and_status(
    decision: str, outcome: str
) -> tuple[int, str, int, str]:
    """Map decision/outcome to OCSF disposition and status tuples."""
    d_norm = (decision or "").strip().lower()
    o_norm = (outcome or "").strip().lower()

    if d_norm in {"allow", "allowed", "permit", "permitted"} or (
        not d_norm and o_norm in {"success", "allowed", "permitted"}
    ):
        return (
            OCSF_DISPOSITION_ALLOWED,
            "Allowed",
            OCSF_STATUS_SUCCESS,
            "Success",
        )
    if d_norm in {"deny", "denied", "block", "blocked", "rejected"} or (
        not d_norm and o_norm in {"denied", "blocked", "rejected", "failure", "error"}
    ):
        return (
            OCSF_DISPOSITION_BLOCKED,
            "Blocked",
            OCSF_STATUS_FAILURE,
            "Failure",
        )
    if d_norm in {"quarantine", "quarantined"}:
        return (
            OCSF_DISPOSITION_QUARANTINED,
            "Quarantined",
            OCSF_STATUS_FAILURE,
            "Failure",
        )

    return (
        OCSF_DISPOSITION_OTHER,
        "Other",
        OCSF_STATUS_SUCCESS if o_norm == "success" else OCSF_STATUS_OTHER,
        "Success" if o_norm == "success" else "Other",
    )


def _classify_event(
    ce_type: str,
    kind_val: str,
    decision: str,
    outcome: str,
) -> tuple[int, str, int, str, int, str, int, str]:
    """Determine the OCSF Class, Category, Activity, and Type."""
    t_norm = (ce_type or "").lower()
    k_norm = (kind_val or "").lower()
    d_norm = (decision or "").lower()
    o_norm = (outcome or "").lower()

    is_violation = (
        k_norm
        in {
            GovernanceEventKind.POLICY_VIOLATION.value,
            GovernanceEventKind.TOOL_CALL_BLOCKED.value,
            GovernanceEventKind.PROMPT_INJECTION_DETECTED.value,
            GovernanceEventKind.MCP_TOOL_POISONING.value,
            GovernanceEventKind.CONTENT_VIOLATION.value,
            GovernanceEventKind.ANOMALY_DETECTED.value,
        }
        or "violation" in t_norm
        or "blocked" in t_norm
        or "poisoning" in t_norm
        or d_norm in {"deny", "denied", "block", "blocked"}
        or o_norm in {"denied", "blocked"}
    )

    is_iam = (
        k_norm
        in {
            GovernanceEventKind.IDENTITY_VERIFIED.value,
            GovernanceEventKind.IDENTITY_REJECTED.value,
            GovernanceEventKind.ESCALATION_REQUESTED.value,
        }
        or "identity" in t_norm
        or "handshake" in t_norm
        or "agent.registered" in t_norm
        or "agent.verified" in t_norm
    )

    if is_violation:
        # Category 2: Findings -> Class 2001: Security Finding
        activity_id = 1  # Create
        activity_name = "Create"
        class_uid = OCSF_CLASS_SECURITY_FINDING
        class_name = "Security Finding"
        category_uid = OCSF_CATEGORY_FINDINGS
        category_name = "Findings"
        type_uid = class_uid * 100 + activity_id
        type_name = f"{class_name}: {activity_name}"
        return (
            class_uid,
            class_name,
            category_uid,
            category_name,
            activity_id,
            activity_name,
            type_uid,
            type_name,
        )

    if is_iam:
        # Category 3: Identity & Access Management -> Class 3002: Authorize Session
        activity_id = 1  # Authorize
        activity_name = "Authorize"
        class_uid = OCSF_CLASS_AUTHORIZE_SESSION
        class_name = "Authorize Session"
        category_uid = OCSF_CATEGORY_IAM
        category_name = "Identity & Access Management"
        type_uid = class_uid * 100 + activity_id
        type_name = f"{class_name}: {activity_name}"
        return (
            class_uid,
            class_name,
            category_uid,
            category_name,
            activity_id,
            activity_name,
            type_uid,
            type_name,
        )

    # Category 6: Application Activity -> Class 6003: API Activity
    activity_id = 99  # Other
    activity_name = "Other"
    class_uid = OCSF_CLASS_API_ACTIVITY
    class_name = "API Activity"
    category_uid = OCSF_CATEGORY_APPLICATION_ACTIVITY
    category_name = "Application Activity"
    type_uid = class_uid * 100 + activity_id
    type_name = f"{class_name}: {activity_name}"
    return (
        class_uid,
        class_name,
        category_uid,
        category_name,
        activity_id,
        activity_name,
        type_uid,
        type_name,
    )


def cloudevent_to_ocsf(
    cloudevent: dict[str, Any],
    *,
    custom_product: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Convert a CloudEvents v1.0 governance or trace envelope into an OCSF v1.3.0 event.

    Maps CloudEvents attributes and AGT governance payloads into standard OCSF
    classes (API Activity 6003, Security Finding 2001, Authorize Session 3002),
    preserving trace correlation, actor identity, policy metadata, and custom
    payloads under the `unmapped` attribute.

    Args:
        cloudevent: A CloudEvents 1.0 JSON-compliant dict.
        custom_product: Optional metadata.product override for OCSF metadata.

    Returns:
        An OCSF v1.3.0 compliant dictionary.
    """
    event_id = str(cloudevent.get("id") or "")
    ce_type = str(cloudevent.get("type") or "ai.agentos.event")
    ce_source = str(cloudevent.get("source") or "")
    ce_time = cloudevent.get("time")

    time_ms, original_time = _parse_time_ms(ce_time)

    raw_data = cloudevent.get("data")
    data: dict[str, Any] = raw_data if isinstance(raw_data, dict) else {}

    # Extract trace and session correlation from CloudEvent extensions or data
    trace_id = (
        cloudevent.get("traceid")
        or data.get("trace_id")
        or data.get("traceid")
        or None
    )
    span_id = (
        cloudevent.get("spanid")
        or data.get("span_id")
        or data.get("spanid")
        or None
    )
    parent_span_id = (
        cloudevent.get("parentspanid")
        or data.get("parent_span_id")
        or data.get("parentspanid")
        or None
    )
    session_id = (
        cloudevent.get("sessionid")
        or data.get("session_id")
        or data.get("sessionid")
        or None
    )

    action = str(data.get("action") or "")
    decision = str(data.get("decision") or data.get("policy_decision") or "")
    outcome = str(data.get("outcome") or "")
    reason = str(data.get("reason") or data.get("violation_reason") or "")
    resource = data.get("resource")
    policy_name = data.get("policy_name") or data.get("policy_id")
    agent_id = str(data.get("agent_id") or "")
    agent_did = str(data.get("agent_did") or ce_source or "")
    if not agent_id and agent_did:
        agent_id = agent_did.split("/")[-1]

    kind_val = str(data.get("kind") or "")
    if not kind_val:
        # Infer kind from ce_type if present
        parts = ce_type.split(".")
        kind_val = parts[-1] if parts else ""

    severity_str = str(data.get("severity") or "info").lower()
    severity_id, severity_name = _SEVERITY_MAP.get(
        severity_str, (OCSF_SEVERITY_UNKNOWN, "Unknown")
    )

    (
        class_uid,
        class_name,
        category_uid,
        category_name,
        activity_id,
        activity_name,
        type_uid,
        type_name,
    ) = _classify_event(ce_type, kind_val, decision, outcome)

    disp_id, disp_name, stat_id, stat_name = _map_disposition_and_status(
        decision, outcome
    )

    product_meta = custom_product or {
        "name": "Agent Governance Toolkit",
        "vendor_name": "Microsoft",
        "feature": {"name": "agent-os"},
        "version": cloudevent.get("schemaversion") or "1.0",
    }

    metadata: dict[str, Any] = {
        "version": OCSF_SCHEMA_VERSION,
        "product": product_meta,
        "profiles": ["cloud", "security_control"],
        "original_time": original_time,
        "event_code": ce_type,
    }
    if event_id:
        metadata["uid"] = event_id
    if trace_id:
        metadata["correlation_uid"] = str(trace_id)
    elif session_id:
        metadata["correlation_uid"] = str(session_id)

    actor: dict[str, Any] = {
        "type": "Agent",
        "user": {
            "name": agent_id or agent_did or "unknown",
            "uid": agent_did or agent_id or "unknown",
        },
    }
    if agent_did:
        actor["id"] = agent_did
    elif agent_id:
        actor["id"] = agent_id

    approver_did = data.get("approver_did")
    if approver_did:
        actor["invoked_by"] = {"uid": str(approver_did), "type": "Principal"}

    # Observability & Trace Context
    observability: dict[str, Any] = {}
    if trace_id:
        observability["trace_id"] = str(trace_id)
    if span_id:
        observability["span_id"] = str(span_id)
    if parent_span_id:
        observability["parent_span_id"] = str(parent_span_id)
    if session_id:
        observability["session_id"] = str(session_id)

    # Base OCSF Event Envelope
    ocsf: dict[str, Any] = {
        "class_uid": class_uid,
        "class_name": class_name,
        "category_uid": category_uid,
        "category_name": category_name,
        "activity_id": activity_id,
        "activity_name": activity_name,
        "type_uid": type_uid,
        "type_name": type_name,
        "time": time_ms,
        "timezone_offset": 0,
        "severity_id": severity_id,
        "severity": severity_name,
        "status_id": stat_id,
        "status": stat_name,
        "disposition_id": disp_id,
        "disposition": disp_name,
        "metadata": metadata,
        "actor": actor,
    }

    if reason:
        ocsf["status_detail"] = reason

    if observability:
        ocsf["observability"] = observability

    # Class-specific attributes
    if class_uid == OCSF_CLASS_SECURITY_FINDING:
        finding_info: dict[str, Any] = {
            "uid": event_id or f"finding-{time_ms}",
            "title": f"Governance Violation: {policy_name or action or kind_val}",
            "desc": reason or f"Policy violation detected for action: {action or 'unknown'}",
            "types": [kind_val] if kind_val else ["policy_violation"],
        }
        ocsf["finding_info"] = finding_info
        if policy_name:
            ocsf["policy"] = {
                "name": str(policy_name),
                "desc": reason or "",
                **({"version": str(data["policy_version"])} if "policy_version" in data else {}),
            }

    elif class_uid == OCSF_CLASS_API_ACTIVITY:
        api: dict[str, Any] = {
            "operation": action or kind_val or "execute",
            "service": {"name": "agent-os"},
        }
        if resource:
            api["request"] = {"data": resource}
        ocsf["api"] = api
        if policy_name:
            ocsf["policy"] = {
                "name": str(policy_name),
                **({"version": str(data["policy_version"])} if "policy_version" in data else {}),
            }

    elif class_uid == OCSF_CLASS_AUTHORIZE_SESSION:
        auth_session: dict[str, Any] = {}
        if session_id:
            auth_session["uid"] = str(session_id)
        if auth_session:
            ocsf["session"] = auth_session
        if resource:
            ocsf["resource"] = {"name": str(resource)}

    # Retain all unmapped custom attributes to preserve complete data fidelity
    standard_keys = {
        "action",
        "decision",
        "outcome",
        "reason",
        "violation_reason",
        "resource",
        "policy_name",
        "policy_id",
        "policy_version",
        "policy_decision",
        "agent_id",
        "agent_did",
        "approver_did",
        "kind",
        "severity",
        "trace_id",
        "traceid",
        "span_id",
        "spanid",
        "parent_span_id",
        "parentspanid",
        "session_id",
        "sessionid",
    }
    unmapped: dict[str, Any] = {
        k: v for k, v in data.items() if k not in standard_keys
    }

    # Also capture extension attributes from CloudEvent (e.g. signature or hashes)
    ce_standard_keys = {
        "specversion",
        "id",
        "type",
        "source",
        "time",
        "datacontenttype",
        "dataschema",
        "subject",
        "data",
        "schemaversion",
        "traceid",
        "spanid",
        "parentspanid",
        "sessionid",
    }
    for ce_k, ce_v in cloudevent.items():
        if ce_k not in ce_standard_keys:
            unmapped[ce_k] = ce_v

    if unmapped:
        ocsf["unmapped"] = unmapped

    return ocsf


def governance_event_to_ocsf(
    event: GovernanceEvent,
    source: str | None = None,
) -> dict[str, Any]:
    """Convert a :class:`GovernanceEvent` directly into an OCSF v1.3.0 record.

    Serializes the event to its canonical CloudEvent envelope first, then maps
    it to OCSF schema.

    Args:
        event: The GovernanceEvent instance to convert.
        source: Optional CloudEvents source URI identifying the emitter.

    Returns:
        An OCSF v1.3.0 compliant dictionary.
    """
    cloudevent = event.to_cloudevent(source=source)
    return cloudevent_to_ocsf(cloudevent)


class OCSFGovernanceSink(GovernanceEventSinkBase):
    """Sink that writes governance trace events in OCSF schema as JSON lines.

    Converts :class:`GovernanceEvent` objects (and their CloudEvents representation)
    to Open Cybersecurity Schema Framework (OCSF v1.3.0) format, the industry
    standard for SIEM, XDR, and security data lakes (e.g. AWS Security Lake,
    Splunk, Datadog).

    Outputs newline-delimited JSON (NDJSON) records.
    """

    def __init__(
        self,
        source: str = "/agent-os",
        *,
        stream: Any = None,
    ) -> None:
        """Initialize the OCSF sink.

        Args:
            source: CloudEvents ``source`` URI-reference for emitted events.
            stream: Writable text stream. Defaults to ``sys.stdout`` at emit time.
        """
        self._source = source
        self._stream = stream

    def emit(self, events: Sequence[GovernanceEvent]) -> SinkExportResult:
        """Deliver a batch of governance events formatted as OCSF NDJSON."""
        import sys

        stream = self._stream if self._stream is not None else sys.stdout
        try:
            for event in events:
                ocsf_record = governance_event_to_ocsf(event, source=self._source)
                stream.write(json.dumps(ocsf_record, sort_keys=True, default=str) + "\n")
            stream.flush()
            return SinkExportResult.SUCCESS
        except Exception:
            logger.exception("OCSFGovernanceSink failed to emit events")
            return SinkExportResult.FAILURE

