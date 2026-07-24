# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Healthcare scenario: allow a non-diagnostic visit-note update via ACS policy."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agent_os.mute_agent import MuteAgent, MutePolicy

from support import (
    PolicyDecision,
    ScenarioResult,
    assert_exercised,
    assert_no_raw_secrets,
    evaluate_pre_tool_call,
    load_acs_runtime,
    not_exercised_result,
    select_model,
    tool_schema,
    write_artifact,
)


POLICY_DIR = Path(__file__).parent


class MockPatientRecords:
    def __init__(self) -> None:
        self.note_updates: list[dict[str, Any]] = []

    def update_visit_notes(self, **arguments: Any) -> None:
        self.note_updates.append(arguments)


def run_healthcare() -> tuple[
    ScenarioResult,
    MockPatientRecords,
    PolicyDecision | None,
]:
    scenario_id = "healthcare"
    records = MockPatientRecords()
    model = select_model()
    reply = model.complete(
        scenario_id,
        "Record this follow-up as a non-diagnostic visit note: patient reports improved sleep.",
        [
            tool_schema(
                "update_visit_notes",
                "Append non-diagnostic notes to the patient visit record.",
                {
                    "patient_id": {
                        "type": "string",
                        "description": "Identifier of the patient whose visit note is updated.",
                    },
                    "note": {
                        "type": "string",
                        "description": "Non-diagnostic visit note text to append.",
                    },
                },
            )
        ],
    )
    call = reply.tool_call
    if call is None or call.name != "update_visit_notes":
        return not_exercised_result(
            scenario_id,
            "tool_call=update_visit_notes",
            reply,
            model.inputs,
        ), records, None

    runtime = load_acs_runtime(POLICY_DIR)
    decision = evaluate_pre_tool_call(
        runtime,
        agent_id="clinic-intake-agent",
        tool_name=call.name,
        arguments=call.arguments,
    )
    if decision.allowed:
        records.update_visit_notes(**call.arguments)
    scrubber = MuteAgent(MutePolicy(enabled_builtins=["email", "ssn", "api_key"]))
    safe_arguments = {
        key: scrubber.scrub_text(value) if isinstance(value, str) else value
        for key, value in call.arguments.items()
    }
    return ScenarioResult(
        decision=decision.verdict,
        executed_tools=[call.name] if decision.allowed else [],
        model_inputs=model.inputs,
        tool_arguments=[safe_arguments],
    ), records, decision


def test_healthcare_note_update_is_allowed(artifact_dir: Path) -> None:
    result, records, policy_decision = run_healthcare()
    assert_exercised(result)

    assert result.decision == "allow"
    assert result.executed_tools == ["update_visit_notes"]
    assert len(records.note_updates) == 1
    assert policy_decision is not None
    assert policy_decision.reason == "healthcare.allow-visit-note-update"

    write_artifact(result, artifact_dir, "healthcare")
    assert_no_raw_secrets(artifact_dir / "healthcare.json")
