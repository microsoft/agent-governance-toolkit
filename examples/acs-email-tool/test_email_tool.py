# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the ACS email-tool example."""

from __future__ import annotations

from pathlib import Path

import pytest

from email_policy import EmailPolicy

ROOT = Path(__file__).parent


def _invocation(args: dict[str, str]) -> dict[str, object]:
    return {
        "input": {
            "intervention_point": "pre_tool_call",
            "policy_target": {"value": args},
        }
    }


def test_policy_allows_internal_email() -> None:
    verdict = EmailPolicy().evaluate(
        _invocation({"to": "customer@example.com", "body": "Status update"})
    )
    assert verdict == {"decision": "allow"}


def test_policy_transforms_tracking_token() -> None:
    verdict = EmailPolicy().evaluate(
        _invocation(
            {
                "to": "customer@example.com",
                "body": "Tracking token: TRACK-123",
            }
        )
    )
    assert verdict["decision"] == "transform"
    assert verdict["transform"]["value"] == "Tracking token: [REDACTED]"


def test_policy_denies_external_recipient() -> None:
    verdict = EmailPolicy().evaluate(
        _invocation({"to": "partner@example.net", "body": "Status update"})
    )
    assert verdict["decision"] == "deny"
    assert verdict["reason"] == "external_recipient_blocked"


def test_native_runtime_applies_transform_and_deny() -> None:
    pytest.importorskip("agent_control_specification")
    pytest.importorskip("agt.policies")

    from agt.policies import SnapshotBuilder
    from agt.policies.runtime import AgtRuntime

    from run import enforce_email

    runtime = AgtRuntime(
        ROOT / "manifest.yaml",
        policy_dispatcher=EmailPolicy(),
    )
    session = SnapshotBuilder(agent_id="test-agent", session_id="test-session")

    try:
        transformed, output = enforce_email(
            runtime,
            session,
            {
                "to": "customer@example.com",
                "body": "Tracking token: TRACK-123",
            },
            call_id="transform-1",
        )
        assert transformed.verdict == "transform"
        assert output is not None
        assert output["body"] == "Tracking token: [REDACTED]"

        denied, output = enforce_email(
            runtime,
            session,
            {"to": "partner@example.net", "body": "Status update"},
            call_id="deny-1",
        )
        assert denied.verdict == "deny"
        assert output is None
    finally:
        runtime.close()
