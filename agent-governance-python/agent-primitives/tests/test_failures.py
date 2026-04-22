# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from datetime import timezone

from agent_primitives import AgentFailure, FailureTrace, FailureType


def test_failure_trace_timestamp_is_timezone_aware() -> None:
    trace = FailureTrace(
        user_prompt="delete records",
        failed_action={"action": "execute_sql"},
        error_details="blocked",
    )

    assert trace.timestamp.tzinfo is timezone.utc


def test_agent_failure_timestamp_is_timezone_aware() -> None:
    failure = AgentFailure(
        agent_id="agent-123",
        failure_type=FailureType.TIMEOUT,
        error_message="timed out",
    )

    assert failure.timestamp.tzinfo is timezone.utc
