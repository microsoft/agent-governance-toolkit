# Copyright (c) Microsoft Corporation. Licensed under the MIT License.
"""V2 validator (latest schema) compatibility tests for OCSF conversion.

These tests assert the shapes expected by the public OCSF validator as of
2026-10-19, which uses a newer schema (reports 1.9.x). They do NOT replace the
1.3.0 tests; they run in parallel to ensure both modes continue to work.
"""

from __future__ import annotations

from agent_os.event_sink import GovernanceEvent, GovernanceEventKind
from agent_os.ocsf import (
    OCSF_CLASS_API_ACTIVITY,
    OCSF_CLASS_AUTHORIZE_SESSION,
    OCSF_CLASS_DETECTION_FINDING,
    cloudevent_to_ocsf,
    governance_event_to_ocsf,
)


def test_v2_detection_finding_drops_actor_and_state():
    event = GovernanceEvent(
        agent_id="bot-1",
        action="execute_shell",
        resource="rm -rf /",
        decision="deny",
        reason="forbidden",
        policy_name="no-destructive-commands",
        kind=GovernanceEventKind.POLICY_VIOLATION,
        trace_id="trace-1",
        span_id="span-1",
        session_id="sess-1",
    )

    ocsf = governance_event_to_ocsf(event, source="/agent-os/test", schema_mode="latest")

    assert ocsf["class_uid"] == OCSF_CLASS_DETECTION_FINDING
    assert "finding_info" in ocsf
    # Latest validator rejects these on 2004
    assert "actor" not in ocsf
    assert "state" not in ocsf
    assert "state_id" not in ocsf


def test_v2_authorize_session_has_user_and_privileges():
    ce = GovernanceEvent(
        agent_id="bot-2",
        agent_did="did:mesh:bot-2",
        action="identity_check",
        decision="deny",
        reason="trust threshold not met",
        kind=GovernanceEventKind.IDENTITY_REJECTED,
        session_id="sess-2002",
    ).to_cloudevent(source="/agent-os/test")

    ocsf = cloudevent_to_ocsf(ce, schema_mode="latest")

    assert ocsf["class_uid"] == OCSF_CLASS_AUTHORIZE_SESSION
    # Latest validator requires top-level user and one of the constraint sets
    assert "user" in ocsf
    assert any(k in ocsf for k in ("privileges", "groups", "iam_roles"))


def test_v2_api_activity_still_valid_shape():
    event = GovernanceEvent(
        agent_id="bot-3",
        action="query_database",
        resource="SELECT * FROM users",
        decision="allow",
        reason="read-only policy",
        policy_name="read-only-access",
        kind=GovernanceEventKind.POLICY_CHECK,
        trace_id="trace-2",
    )

    ocsf = governance_event_to_ocsf(event, source="/agent-os/test", schema_mode="latest")

    assert ocsf["class_uid"] == OCSF_CLASS_API_ACTIVITY
    assert ocsf["api"]["request"]["uid"]
    assert ocsf["src_endpoint"]["name"]
