# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""TRACE v0.2 Trust Record data model and session mapping (ADR-0032, step 1/5)."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Optional

from .audit import AuditEntry


_DENY_OUTCOMES = frozenset({"denied"})
_DENY_EVENT_TYPES = frozenset({"policy_violation", "tool_blocked"})


@dataclass
class TraceModelConfig:
    """Config-injected values for TRACE Trust Record fields."""

    model: dict
    runtime: dict
    enforcement_mode: str
    build_provenance: dict
    verifier: str
    eat_profile: str = "tag:agentrust.io,2026:trace-v0.1"


@dataclass
class TraceSession:
    """Bundle of per-session data needed to produce a TRACE Trust Record."""

    agent_did: str
    audit_entries: list[AuditEntry]
    data_class: str
    policy_bundle_hash: Optional[str] = None


@dataclass
class TrustRecord:
    """TRACE v0.2 Trust Record (ADR-0032)."""

    eat_profile: str
    iat: int
    subject: str
    model: dict
    runtime: dict
    policy: dict
    data_class: str
    build_provenance: dict
    appraisal: dict
    transparency: str
    tool_transcript: dict


def _jcs_hash(entries: list[AuditEntry]) -> str:
    """Return 'sha256:<hex>' of RFC 8785 JCS-canonical JSON of the entry list."""
    serialized = [json.loads(e.model_dump_json()) for e in entries]
    canonical = json.dumps(
        serialized, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def session_to_trust_record(session: TraceSession, config: TraceModelConfig) -> dict:
    """Map a closed AGT session to a TRACE v0.2 Trust Record payload dict."""
    entries = session.audit_entries

    iat = 0
    if entries:
        latest = max(entries, key=lambda e: e.timestamp)
        iat = int(latest.timestamp.timestamp())

    has_deny = any(
        e.outcome in _DENY_OUTCOMES or e.event_type in _DENY_EVENT_TYPES
        for e in entries
    )
    appraisal_status = "contraindicated" if has_deny else "affirming"

    call_count = sum(1 for e in entries if e.event_type == "tool_invocation")

    record = TrustRecord(
        eat_profile=config.eat_profile,
        iat=iat,
        subject=session.agent_did,
        model=config.model,
        runtime=config.runtime,
        policy={
            "bundle_hash": session.policy_bundle_hash or "",
            "enforcement_mode": config.enforcement_mode,
        },
        data_class=session.data_class,
        build_provenance=config.build_provenance,
        appraisal={"status": appraisal_status, "verifier": config.verifier},
        transparency="",
        tool_transcript={"hash": _jcs_hash(entries), "call_count": call_count},
    )

    return {
        "eat_profile": record.eat_profile,
        "iat": record.iat,
        "subject": record.subject,
        "model": record.model,
        "runtime": record.runtime,
        "policy": record.policy,
        "data_class": record.data_class,
        "build_provenance": record.build_provenance,
        "appraisal": record.appraisal,
        "transparency": record.transparency,
        "tool_transcript": record.tool_transcript,
    }
