# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Run a framework-neutral email tool through the AGT ACS host path."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agent_control_specification import (
    AgentControl,
    Decision,
    HostSession,
    InterventionPointResult,
)

from email_policy import EmailPolicy

ROOT = Path(__file__).parent


def send_email(args: dict[str, str]) -> dict[str, Any]:
    """Stand-in side effect that returns the arguments it received."""
    return {"sent": True, **args}


def enforce_email(
    session: HostSession,
    args: dict[str, str],
    *,
    call_id: str,
) -> tuple[InterventionPointResult, dict[str, Any] | None]:
    """Evaluate, enforce, and conditionally execute one email tool call."""
    decision = session.pre_tool_call(
        tool_name="send_email",
        args=args,
        call_id=call_id,
    )

    if not decision.verdict.decision.permits:
        return decision, None

    enforced_args: dict[str, str] = args
    if decision.verdict.decision is Decision.TRANSFORM:
        applied_value = decision.transformed_policy_target
        if not isinstance(applied_value, dict):
            raise RuntimeError("ACS transform did not produce an argument object")
        enforced_args = applied_value

    output = send_email(enforced_args)
    session.builder.record_tool_call()
    return decision, output


def main() -> None:
    control = AgentControl.from_path(
        str(ROOT / "manifest.yaml"),
        policy_dispatcher=EmailPolicy(),
    )
    session = HostSession(
        control,
        agent_id="email-agent",
        session_id="demo-session",
    )

    cases = [
        (
            "allow",
            {"to": "customer@example.com", "body": "Your case is ready."},
        ),
        (
            "transform",
            {
                "to": "customer@example.com",
                "body": "Your case is ready. Tracking token: TRACK-123",
            },
        ),
        (
            "deny",
            {"to": "partner@example.net", "body": "Status update"},
        ),
    ]

    for index, (label, args) in enumerate(cases, start=1):
        decision, output = enforce_email(
            session,
            args,
            call_id=f"email-{index}",
        )
        verdict = decision.verdict
        if output is None:
            print(
                f"[{label}] decision={verdict.decision.value} "
                f"executed=False reason={verdict.reason}"
            )
        else:
            print(
                f"[{label}] decision={verdict.decision.value} "
                f"sent={output['sent']} body={output['body']}"
            )


if __name__ == "__main__":
    main()
