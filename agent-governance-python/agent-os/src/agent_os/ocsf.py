# Copyright (c) Microsoft Corporation. Licensed under the MIT License.
"""Open Cybersecurity Schema Framework (OCSF) v1.9.0 conversion and sink.

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
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from agent_os.event_sink import (
    GovernanceEvent,
    GovernanceEventKind,
    GovernanceEventSinkBase,
    SinkExportResult,
)

logger = logging.getLogger(__name__)

#: Default OCSF Schema version targeted by this converter.
OCSF_SCHEMA_VERSION = "1.9.0"

# Note: This converter targets OCSF 1.9.0 only and always emits 1.9.0-compliant shapes.

# OCSF Categories
OCSF_CATEGORY_FINDINGS = 2
OCSF_CATEGORY_IAM = 3
OCSF_CATEGORY_APPLICATION_ACTIVITY = 6

# OCSF Classes (OCSF v1.9.0)
OCSF_CLASS_DETECTION_FINDING = 2004  # Category 2: replaces deprecated Security Finding 2001
OCSF_CLASS_AUTHORIZE_SESSION = 3003  # Category 3: Authorize Session (Assign Privileges)
OCSF_CLASS_API_ACTIVITY = 6003  # Category 6: API Activity

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

# OCSF Dispositions (https://schema.ocsf.io/1.3.0/objects/disposition)
OCSF_DISPOSITION_ALLOWED = 1
OCSF_DISPOSITION_BLOCKED = 2
OCSF_DISPOSITION_QUARANTINED = 3
OCSF_DISPOSITION_ISOLATED = 4
OCSF_DISPOSITION_DELETED = 5
OCSF_DISPOSITION_DROPPED = 6
OCSF_DISPOSITION_CUSTOM = 7
OCSF_DISPOSITION_OTHER = 99

# OCSF Statuses
OCSF_STATUS_SUCCESS = 1
OCSF_STATUS_FAILURE = 2
OCSF_STATUS_OTHER = 99

# Map CloudEvents type segments → GovernanceEventKind values, used when
# ``kind`` is absent from the data payload (which is the default for events
# produced by GovernanceEvent.to_cloudevent()).
_CE_TYPE_SUFFIX_TO_KIND: dict[str, str] = {
    "check": GovernanceEventKind.POLICY_CHECK.value,
    "violation": GovernanceEventKind.POLICY_VIOLATION.value,
    "blocked": GovernanceEventKind.TOOL_CALL_BLOCKED.value,
    "detected": GovernanceEventKind.PROMPT_INJECTION_DETECTED.value,
    "verified": GovernanceEventKind.IDENTITY_VERIFIED.value,
    "rejected": GovernanceEventKind.IDENTITY_REJECTED.value,
    "access": GovernanceEventKind.RESOURCE_ACCESS.value,
    "requested": GovernanceEventKind.ESCALATION_REQUESTED.value,
    "created": GovernanceEventKind.CHECKPOINT_CREATED.value,
    "tool_poisoning": GovernanceEventKind.MCP_TOOL_POISONING.value,
    "content.violation": GovernanceEventKind.CONTENT_VIOLATION.value,
    "anomaly.detected": GovernanceEventKind.ANOMALY_DETECTED.value,
}

# All kind values that map to Detection Finding (class 2004)
_FINDING_KINDS: frozenset[str] = frozenset(
    {
        GovernanceEventKind.POLICY_VIOLATION.value,
        GovernanceEventKind.TOOL_CALL_BLOCKED.value,
        GovernanceEventKind.PROMPT_INJECTION_DETECTED.value,
        GovernanceEventKind.MCP_TOOL_POISONING.value,
        GovernanceEventKind.CONTENT_VIOLATION.value,
        GovernanceEventKind.ANOMALY_DETECTED.value,
    }
)

# All kind values that map to Authorize Session (class 3003)
_IAM_KINDS: frozenset[str] = frozenset(
    {
        GovernanceEventKind.IDENTITY_VERIFIED.value,
        GovernanceEventKind.IDENTITY_REJECTED.value,
        GovernanceEventKind.ESCALATION_REQUESTED.value,
    }
)


def _parse_time_ms(time_val: Any) -> tuple[int, str]:
    """Parse a datetime object or ISO8601 string into (epoch_ms, iso_str)."""
    if isinstance(time_val, datetime):
        dt = time_val if time_val.tzinfo else time_val.replace(tzinfo=UTC)
        return int(dt.timestamp() * 1000), dt.isoformat()
    if isinstance(time_val, (int, float)):
        # If timestamp is in seconds, convert to ms
        ms = int(time_val * 1000) if time_val < 1e11 else int(time_val)
        dt = datetime.fromtimestamp(ms / 1000.0, tz=UTC)
        return ms, dt.isoformat()
    if isinstance(time_val, str) and time_val:
        try:
            clean = time_val.replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean)
            if not dt.tzinfo:
                dt = dt.replace(tzinfo=UTC)
            return int(dt.timestamp() * 1000), time_val
        except Exception:
            pass
    now = datetime.now(UTC)
    return int(now.timestamp() * 1000), now.isoformat()


def _map_disposition_and_status(decision: str, outcome: str) -> tuple[int, str, int, str]:
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


def _resolve_kind(ce_type: str, kind_val: str) -> str:
    """Resolve the effective GovernanceEventKind value from the CE type or data.

    ``GovernanceEvent.to_cloudevent()`` does not write ``kind`` into the data
    payload; the kind is encoded as the CloudEvents ``type`` string instead
    (e.g. ``ai.agentos.policy.violation``).  This function recovers the kind
    by matching known type suffixes so that classification is correct for both
    raw CloudEvents and events that carry an explicit ``kind`` field.

    Args:
        ce_type: The CloudEvents ``type`` attribute value.
        kind_val: The ``kind`` field read from the event ``data`` payload
            (may be empty).

    Returns:
        The resolved kind string (a :class:`GovernanceEventKind` value or the
        raw suffix used as a fallback).
    """
    if kind_val:
        return kind_val.lower()

    # Match known multi-word suffixes first (longer match wins)
    t_lower = ce_type.lower()
    for suffix, kind in sorted(
        _CE_TYPE_SUFFIX_TO_KIND.items(), key=lambda kv: len(kv[0]), reverse=True
    ):
        if t_lower.endswith(suffix) or f".{suffix}." in t_lower:
            return kind

    # Fallback: last dot-segment (preserves previous behaviour for unknown types)
    parts = ce_type.split(".")
    return parts[-1] if parts else ""


def _classify_event(
    ce_type: str,
    kind_val: str,
    decision: str,
    outcome: str,
) -> tuple[int, str, int, str, int, str, int, str]:
    """Determine the OCSF Class, Category, Activity, and Type UID.

    OCSF v1.9.0 classes used:
    - 2004 Detection Finding  (category 2) — policy violations and security detections.
    - 3003 Authorize Session  (category 3) — identity checks and privilege escalations.
    - 6003 API Activity       (category 6) — policy checks, resource accesses, checkpoints.

    Note: Security Finding (2001) is deprecated in OCSF 1.3.0 and is not used here.
    Note: Class 3002 is Authentication in OCSF 1.3.0; agent identity/trust events
          map to 3003 (Authorize Session) because they concern privilege grants.
    """
    k_norm = _resolve_kind(ce_type, kind_val)
    t_norm = ce_type.lower()
    d_norm = (decision or "").lower()
    o_norm = (outcome or "").lower()

    # Kind-based IAM check takes priority — an explicit IAM kind (e.g.
    # IDENTITY_REJECTED with decision=deny) must remain Authorize Session even
    # when the decision field alone would trigger the finding path.
    kind_is_iam = k_norm in _IAM_KINDS
    kind_is_finding = k_norm in _FINDING_KINDS

    is_iam = (
        kind_is_iam
        or "identity" in t_norm
        or "handshake" in t_norm
        or "agent.registered" in t_norm
        or "agent.verified" in t_norm
    )

    is_finding = (not is_iam) and (
        kind_is_finding
        or "violation" in t_norm
        or "blocked" in t_norm
        or "poisoning" in t_norm
        or "injection" in t_norm
        or "anomaly" in t_norm
        # Decision/outcome signals only apply when kind is not explicitly IAM
        or d_norm in {"deny", "denied", "block", "blocked"}
        or o_norm in {"denied", "blocked"}
    )

    if is_finding:
        # Category 2: Findings - Class 2004: Detection Finding
        # Activity 1 = "Create" (a new finding record)
        activity_id = 1
        activity_name = "Create"
        class_uid = OCSF_CLASS_DETECTION_FINDING
        class_name = "Detection Finding"
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
        # Category 3: Identity & Access Management → Class 3003: Authorize Session
        # Activity 1 = "Assign Privileges" per OCSF 1.3.0
        activity_id = 1
        activity_name = "Assign Privileges"
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

    # Category 6: Application Activity → Class 6003: API Activity
    # Activity 99 = "Other"
    activity_id = 99
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
    """Convert a CloudEvents v1.0 governance or trace envelope into an OCSF v1.9.0 event.

    Maps CloudEvents attributes and AGT governance payloads into standard OCSF
    classes (API Activity 6003, Detection Finding 2004, Authorize Session 3003),
    preserving trace correlation, actor identity, policy metadata, and custom
    payloads under the ``unmapped`` attribute.

    ``kind`` is **not** expected in the CloudEvents data payload (it is not
    written there by :meth:`GovernanceEvent.to_cloudevent`).  Classification is
    driven by the ``type`` attribute instead; if an explicit ``kind`` field is
    present in ``data`` it takes precedence.

    Args:
        cloudevent: A CloudEvents 1.0 JSON-compliant dict.
        custom_product: Optional metadata.product override for OCSF metadata.

    Returns:
        An OCSF v1.9.0 compliant dictionary.
    """
    event_id = str(cloudevent.get("id") or "")
    ce_type = str(cloudevent.get("type") or "ai.agentos.event")
    ce_source = str(cloudevent.get("source") or "")
    ce_time = cloudevent.get("time")

    time_ms, original_time = _parse_time_ms(ce_time)

    raw_data = cloudevent.get("data")
    data: dict[str, Any] = raw_data if isinstance(raw_data, dict) else {}

    # Extract trace and session correlation from CloudEvent extensions or data
    trace_id = cloudevent.get("traceid") or data.get("trace_id") or data.get("traceid") or None
    span_id = cloudevent.get("spanid") or data.get("span_id") or data.get("spanid") or None
    parent_span_id = (
        cloudevent.get("parentspanid")
        or data.get("parent_span_id")
        or data.get("parentspanid")
        or None
    )
    session_id = (
        cloudevent.get("sessionid") or data.get("session_id") or data.get("sessionid") or None
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

    # ``kind`` may be present when a raw CE is constructed manually or comes
    # from an external system; to_cloudevent() does not write it to data.
    kind_val = str(data.get("kind") or "")
    # OCSF v1.9.0 is always used.
    resolved_kind = _resolve_kind(ce_type, kind_val)

    severity_str = str(data.get("severity") or "info").lower()
    severity_id, severity_name = _SEVERITY_MAP.get(severity_str, (OCSF_SEVERITY_UNKNOWN, "Unknown"))

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

    disp_id, disp_name, stat_id, stat_name = _map_disposition_and_status(decision, outcome)

    product_meta = custom_product or {
        "name": "Agent Governance Toolkit",
        "vendor_name": "Microsoft",
        "feature": {"name": "agent-os"},
        "version": cloudevent.get("schemaversion") or "1.0",
    }

    metadata: dict[str, Any] = {
        "version": OCSF_SCHEMA_VERSION,
        "product": product_meta,
        "profiles": ["security_control"],
        "original_time": original_time,
        "event_code": ce_type,
    }
    if event_id:
        metadata["uid"] = event_id
    if trace_id:
        metadata["correlation_uid"] = str(trace_id)
    elif session_id:
        metadata["correlation_uid"] = str(session_id)

    # actor: OCSF actor object - user sub-object is the standard carrier of
    # identity.  ``invoked_by`` is a plain string in OCSF (the name of the
    # process or service that triggered the actor).  Custom fields that are not
    # in the OCSF actor schema go to unmapped.
    actor: dict[str, Any] = {
        "user": {
            "name": agent_id or agent_did or "unknown",
            "uid": agent_did or agent_id or "unknown",
        },
    }
    approver_did = data.get("approver_did")
    if approver_did:
        # invoked_by is a String in OCSF actor
        actor["invoked_by"] = str(approver_did)

    # Span / trace context: kept in unmapped (OCSF has no standard observability
    # object on these classes); metadata.correlation_uid carries trace_id above.
    trace_context: dict[str, Any] = {}
    if span_id:
        trace_context["span_id"] = str(span_id)
    if parent_span_id:
        trace_context["parent_span_id"] = str(parent_span_id)
    if session_id:
        trace_context["session_id"] = str(session_id)
    if trace_id:
        trace_context["trace_id"] = str(trace_id)

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

    # Class-specific attributes
    if class_uid == OCSF_CLASS_DETECTION_FINDING:
        # Detection Finding 2004: finding_info is the required finding container.
        # In OCSF 1.3, state/state_id were used; newer validators reject them.
        finding_info: dict[str, Any] = {
            "uid": event_id or f"finding-{time_ms}",
            "title": f"Governance Detection: {policy_name or action or resolved_kind}",
            "desc": reason or f"Policy detection for action: {action or 'unknown'}",
            "types": [resolved_kind] if resolved_kind else ["policy_detection"],
        }
        ocsf["finding_info"] = finding_info
        # Detection Finding uses its own status enum; default to New.
        ocsf["status_id"], ocsf["status"] = 1, "New"
        # Do not add legacy state/state_id; the latest validator rejects them.
        if policy_name:
            ocsf["policy"] = {
                "name": str(policy_name),
                "desc": reason or "",
                **({"version": str(data["policy_version"])} if "policy_version" in data else {}),
            }

    elif class_uid == OCSF_CLASS_API_ACTIVITY:
        # API Activity 6003: requires api.operation and src_endpoint.
        # api.request.uid is the canonical request identifier.
        api: dict[str, Any] = {
            "operation": action or kind_val or "execute",
            "service": {"name": "agent-os"},
            "request": {
                "uid": event_id or "",
                **({"data": str(resource)} if resource else {}),
            },
        }
        ocsf["api"] = api
        # src_endpoint is required for API Activity validation
        ocsf["src_endpoint"] = {"name": ce_source or "agent-os"}
        if policy_name:
            ocsf["policy"] = {
                "name": str(policy_name),
                **({"version": str(data["policy_version"])} if "policy_version" in data else {}),
            }

    elif class_uid == OCSF_CLASS_AUTHORIZE_SESSION:
        # Authorize Session 3003: session object carries the session uid.
        auth_session: dict[str, Any] = {}
        if session_id:
            auth_session["uid"] = str(session_id)
        if auth_session:
            ocsf["session"] = auth_session
        # Do not set top-level resource on 3003; validators reject it.

    # Retain all unmapped custom attributes to preserve complete data fidelity.
    # Trace/span context that has no standard OCSF home on these classes is also
    # kept here so nothing is silently dropped.
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
        "latency_ms",
    }
    unmapped: dict[str, Any] = {k: v for k, v in data.items() if k not in standard_keys}

    # Also capture extension attributes from the CloudEvent envelope
    # (e.g. signature hashes added by AgentMesh or external signers).
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

    if trace_context:
        unmapped["_trace"] = trace_context

    if unmapped:
        ocsf["unmapped"] = unmapped
    # Preserve resource under unmapped for 3003 (top-level resource is invalid)
    if class_uid == OCSF_CLASS_AUTHORIZE_SESSION and resource:
        ocsf.setdefault("unmapped", {})["resource"] = {"name": str(resource)}

    # Adjustments for the latest public OCSF schema conventions.

    if class_uid == OCSF_CLASS_DETECTION_FINDING:
        # Drop attributes the latest schema flags as unknown on 2004
        ocsf.pop("actor", None)
        ocsf.pop("state", None)
        ocsf.pop("state_id", None)

    elif class_uid == OCSF_CLASS_AUTHORIZE_SESSION:
        # Latest schema expects top-level user and at least one of
        # privileges/groups/iam_roles.
        # Provide a minimal user mirror from actor.user if present.
        actor_user = (
            (ocsf.get("actor") or {}).get("user") if isinstance(ocsf.get("actor"), dict) else None
        )
        if actor_user and "user" not in ocsf:
            ocsf["user"] = actor_user
        elif "user" not in ocsf:
            ocsf["user"] = {
                "name": agent_id or agent_did or "unknown",
                "uid": agent_did or agent_id or "unknown",
            }

        # Ensure at least one constraint field is present. Prefer privileges
        # and derive a sensible name from policy/action/decision. Latest schema
        # expects privileges as an array of strings, not objects.
        if not any(k in ocsf for k in ("privileges", "groups", "iam_roles")):
            priv_name = str(
                policy_name
                or action
                or ("allow" if disp_id == OCSF_DISPOSITION_ALLOWED else "deny")
                or "access"
            )
            ocsf["privileges"] = [priv_name]

    return ocsf


def governance_event_to_ocsf(
    event: GovernanceEvent,
    source: str | None = None,
) -> dict[str, Any]:
    """Convert a :class:`GovernanceEvent` directly into an OCSF v1.9.0 record.

    Serializes the event to its canonical CloudEvent envelope first, then maps
    it to OCSF schema.

    Args:
        event: The GovernanceEvent instance to convert.
        source: Optional CloudEvents source URI identifying the emitter.

    Returns:
        An OCSF v1.9.0 compliant dictionary.
    """
    cloudevent = event.to_cloudevent(source=source)
    return cloudevent_to_ocsf(cloudevent)


class OCSFGovernanceSink(GovernanceEventSinkBase):
    """Sink that writes governance trace events in OCSF schema as JSON lines.

    Converts :class:`GovernanceEvent` objects (and their CloudEvents representation)
    to Open Cybersecurity Schema Framework (OCSF v1.9.0) format, the industry
    standard for SIEM, XDR, and security data lakes (e.g. AWS Security Lake,
    Splunk, Datadog).

    Outputs newline-delimited JSON (NDJSON) records.  A per-event try/except
    ensures that one un-serialisable record does not suppress the remaining
    valid records in the same batch.
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
        """Deliver a batch of governance events formatted as OCSF NDJSON.

        Each event is converted and written independently so that a single
        un-serialisable record does not suppress valid records in the same batch.
        """
        import sys

        stream = self._stream if self._stream is not None else sys.stdout
        overall = SinkExportResult.SUCCESS
        for event in events:
            try:
                ocsf_record = governance_event_to_ocsf(event, source=self._source)
                stream.write(json.dumps(ocsf_record, sort_keys=True) + "\n")
            except Exception:
                logger.exception(
                    "OCSFGovernanceSink: failed to emit event %s; skipping",
                    getattr(event, "event_id", "unknown"),
                )
                overall = SinkExportResult.FAILURE
        try:
            stream.flush()
        except Exception:
            logger.exception("OCSFGovernanceSink: stream flush failed")
            overall = SinkExportResult.FAILURE
        return overall
