# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Workshop lab for native ACS policy evaluation."""

from pathlib import Path

from agent_control_specification import AgentControl, HostSession


SCENARIOS = (
    ("read_customer_data", 100),
    ("execute_code", 50),
    ("write_database", 200),
    ("read_reports", 3000),
    ("read_inventory", 150),
)


def run_lab() -> None:
    manifest = Path(__file__).with_name("lab1-manifest.yaml")
    runtime = AgentControl.from_path(str(manifest))
    session = HostSession(
        runtime,
        agent_id="workshop-agent",
        session_id="lab1",
    )

    for tool_name, token_count in SCENARIOS:
        evaluation = session.input(
            body={"tool_name": tool_name, "token_count": token_count}
        )
        print(
            f"{evaluation.verdict:5} "
            f"{tool_name:20} "
            f"tokens={token_count:<4} "
            f"{evaluation.verdict.reason}"
        )


if __name__ == "__main__":
    run_lab()
