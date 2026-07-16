# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Run a framework-neutral email tool through the AGT ACS host path."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agt.policies import EvaluationResult, SnapshotBuilder
from agt.policies.runtime import AgtRuntime

from email_policy import EmailPolicy

ROOT = Path(__file__).parent


def send_email(args: dict[str, str]) -> dict[str, Any]:
    """Stand-in side effect that returns the arguments it received."""
    return {"sent": True, **args}


def enforce_email(
    runtime: AgtRuntime,
    session: SnapshotBuilder,
    args: dict[str, str],
    *,
    call_id: str,
) -> tuple[EvaluationResult, dict[str, Any] | None]:
    """Evaluate, enforce, and conditionally execute one email tool call."""
    snapshot = session.pre_tool_call(
        tool_name="send_email",
        args=args,
        call_id=call_id,
    )
    decision = runtime.evaluate_intervention_point("pre_tool_call", snapshot)

    if not decision.allowed:
        return decision, None

    enforced_args: dict[str, str] = args
    if decision.verdict == "transform":
        if decision.transform is None:
            raise RuntimeError("ACS returned transform without transform data")
        applied_value = decision.transform.get("applied_value")
        if not isinstance(applied_value, dict):
            raise RuntimeError("ACS transform did not produce an argument object")
        enforced_args = applied_value

    output = send_email(enforced_args)
    session.record_tool_call()
    return decision, output


def main() -> None:
    runtime = AgtRuntime(
        ROOT / "manifest.yaml",
        policy_dispatcher=EmailPolicy(),
    )
    session = SnapshotBuilder(agent_id="email-agent", session_id="demo-session")

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

    try:
        for index, (label, args) in enumerate(cases, start=1):
            decision, output = enforce_email(
                runtime,
                session,
                args,
                call_id=f"email-{index}",
            )
            if output is None:
                print(
                    f"[{label}] decision={decision.verdict} "
                    f"executed=False reason={decision.reason}"
                )
            else:
                print(
                    f"[{label}] decision={decision.verdict} "
                    f"sent={output['sent']} body={output['body']}"
                )
    finally:
        runtime.close()


if __name__ == "__main__":
    main()
