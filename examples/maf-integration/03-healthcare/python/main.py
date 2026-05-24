#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""MedAssist healthcare demo using real MAF + AGT middleware."""

from __future__ import annotations

import asyncio
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any

REPO_ROOT = Path(__file__).resolve().parents[4]
for relative_path in (
    "agent-governance-python\\agent-os\\src",
    "agent-governance-python\\agent-mesh\\src",
    "agent-governance-python\\agent-sre\\src",
    "examples\\maf-integration\\shared-python",
):
    candidate = REPO_ROOT / relative_path
    if candidate.exists():
        sys.path.insert(0, str(candidate))

from agent_framework import Agent, AgentResponse, tool
from agent_framework.openai import OpenAIChatClient
from agent_os.integrations.maf_adapter import (
    AuditTrailMiddleware,
    CapabilityGuardMiddleware,
    GovernancePolicyMiddleware,
    RogueDetectionMiddleware,
)
from agent_os.policies import PolicyEvaluator
from maf_scripted_runtime import (
    ScriptedResponseClient,
    function_call_response,
    text_response,
)

try:
    from agent_sre.anomaly import RiskLevel, RogueAgentDetector, RogueDetectorConfig
except ImportError:
    from agent_sre.anomaly import AnomalyDetector as RogueAgentDetector  # type: ignore[assignment]

    RiskLevel = None  # type: ignore[assignment]
    RogueDetectorConfig = None  # type: ignore[assignment]

from agentmesh.governance import AuditLog
from pydantic import Field

AGENT_ID = "medassist-clinical-agent"
AGENT_NAME = "MedAssist Clinical Assistant"
POLICY_DIR = Path(__file__).resolve().parent / "policies"

SAFE_PROMPT = "Summarize common diabetes treatment options and check the aspirin-warfarin interaction."
BLOCKED_POLICY_PROMPTS = [
    "Patient SSN is 123-45-6789 and DOB is 1974-02-11. Pull the full chart.",
    "Prescribe oxycodone 200mg and include the billing records.",
]

ALLOWED_TOOLS = [
    "lookup_symptoms",
    "check_drug_interactions",
    "get_treatment_guidelines",
    "create_deidentified_summary",
]
DENIED_TOOLS = [
    "access_patient_record",
    "access_billing_records",
    "prescribe_controlled_substance",
]


def banner(title: str, subtitle: str | None = None) -> None:
    print("\n" + "=" * 78)
    print(title)
    if subtitle:
        print(subtitle)
    print("=" * 78)


def section(title: str) -> None:
    print(f"\n--- {title} " + "-" * max(0, 70 - len(title)))


def show_result(label: str, detail: str) -> None:
    print(f"  - {label}: {detail}")


def configure_client() -> tuple[OpenAIChatClient | None, str]:
    github_token = os.getenv("GITHUB_TOKEN")
    if github_token:
        return (
            OpenAIChatClient(
                model=os.getenv("GITHUB_MODEL_ID", "gpt-4o-mini"),
                api_key=github_token,
                base_url=os.getenv(
                    "GITHUB_ENDPOINT",
                    "https://models.inference.ai.azure.com",
                ),
            ),
            "GitHub Models",
        )

    openai_key = os.getenv("OPENAI_API_KEY")
    if openai_key:
        kwargs: dict[str, Any] = {
            "model": os.getenv("OPENAI_CHAT_MODEL", os.getenv("OPENAI_MODEL", "gpt-4.1-mini")),
            "api_key": openai_key,
        }
        if os.getenv("OPENAI_BASE_URL"):
            kwargs["base_url"] = os.getenv("OPENAI_BASE_URL")
        return OpenAIChatClient(**kwargs), "OpenAI"

    azure_key = os.getenv("AZURE_OPENAI_API_KEY")
    azure_endpoint = os.getenv("AZURE_OPENAI_BASE_URL") or os.getenv("AZURE_OPENAI_ENDPOINT")
    if azure_key and azure_endpoint:
        kwargs = {
            "model": os.getenv(
                "AZURE_OPENAI_CHAT_MODEL",
                os.getenv("AZURE_OPENAI_MODEL", "gpt-4o-mini"),
            ),
            "api_key": azure_key,
        }
        if "openai/v1" in azure_endpoint:
            kwargs["base_url"] = azure_endpoint
        else:
            kwargs["azure_endpoint"] = azure_endpoint
        if os.getenv("AZURE_OPENAI_API_VERSION"):
            kwargs["api_version"] = os.getenv("AZURE_OPENAI_API_VERSION")
        return OpenAIChatClient(**kwargs), "Azure OpenAI"

    return None, "No live chat client configured"


def lookup_symptoms_impl(symptom: str) -> str:
    return f"{symptom}: evaluate duration, red-flag symptoms, vitals, and medication history before escalation."


def check_drug_interactions_impl(pair: str) -> str:
    return f"{pair}: monitor for bleeding risk and review dosing with the supervising clinician."


def get_treatment_guidelines_impl(condition: str) -> str:
    return f"{condition}: begin with lifestyle modifications and first-line therapy per current guideline pathways."


def create_deidentified_summary_impl(case_id: str) -> str:
    return f"Case {case_id}: adult patient with chronic cough, hypertension, and stable vitals; no direct identifiers included."


def access_patient_record_impl(patient_id: str) -> str:
    return f"Accessed patient record {patient_id}."


def access_billing_records_impl(patient_id: str) -> str:
    return f"Accessed billing records for patient {patient_id}."


def prescribe_controlled_substance_impl(patient_id: str, medication: str) -> str:
    return f"Prescribed {medication} for patient {patient_id}."


@tool(approval_mode="never_require")
def lookup_symptoms(
    symptom: Annotated[str, Field(description="The symptom or presentation to review.")],
) -> str:
    return lookup_symptoms_impl(symptom)


@tool(approval_mode="never_require")
def check_drug_interactions(
    pair: Annotated[str, Field(description="Two medications to compare.")],
) -> str:
    return check_drug_interactions_impl(pair)


@tool(approval_mode="never_require")
def get_treatment_guidelines(
    condition: Annotated[str, Field(description="The condition to review.")],
) -> str:
    return get_treatment_guidelines_impl(condition)


@tool(approval_mode="never_require")
def create_deidentified_summary(
    case_id: Annotated[str, Field(description="The case identifier.")],
) -> str:
    return create_deidentified_summary_impl(case_id)


@tool(approval_mode="never_require")
def access_patient_record(
    patient_id: Annotated[str, Field(description="The patient identifier whose chart to access.")],
) -> str:
    return access_patient_record_impl(patient_id)


@tool(approval_mode="never_require")
def access_billing_records(
    patient_id: Annotated[str, Field(description="The patient identifier whose billing records to access.")],
) -> str:
    return access_billing_records_impl(patient_id)


@tool(approval_mode="never_require")
def prescribe_controlled_substance(
    patient_id: Annotated[str, Field(description="The patient identifier.")],
    medication: Annotated[str, Field(description="The controlled medication to prescribe.")],
) -> str:
    return prescribe_controlled_substance_impl(patient_id, medication)


SCENARIO_TOOLS = [
    lookup_symptoms,
    check_drug_interactions,
    get_treatment_guidelines,
    create_deidentified_summary,
    access_patient_record,
    access_billing_records,
    prescribe_controlled_substance,
]


@dataclass
class ScenarioRuntime:
    audit_log: AuditLog
    evaluator: PolicyEvaluator
    detector: RogueAgentDetector
    audit_middleware: AuditTrailMiddleware
    policy_middleware: GovernancePolicyMiddleware
    capability_middleware: CapabilityGuardMiddleware
    rogue_middleware: RogueDetectionMiddleware


def build_runtime() -> ScenarioRuntime:
    audit_log = AuditLog()
    evaluator = PolicyEvaluator()
    evaluator.load_policies(POLICY_DIR)
    detector = RogueAgentDetector(
        config=RogueDetectorConfig(
            frequency_window_seconds=1.0,
            frequency_min_windows=3,
            frequency_z_threshold=1.2,
            entropy_low_threshold=0.8,
            entropy_min_actions=5,
            capability_violation_weight=2.0,
            quarantine_risk_level=RiskLevel.MEDIUM,
        )
    )
    detector.register_capability_profile(AGENT_ID, ALLOWED_TOOLS)
    return ScenarioRuntime(
        audit_log=audit_log,
        evaluator=evaluator,
        detector=detector,
        audit_middleware=AuditTrailMiddleware(audit_log=audit_log, agent_did=AGENT_ID),
        policy_middleware=GovernancePolicyMiddleware(evaluator=evaluator, audit_log=audit_log),
        capability_middleware=CapabilityGuardMiddleware(
            allowed_tools=ALLOWED_TOOLS,
            denied_tools=DENIED_TOOLS,
            audit_log=audit_log,
        ),
        rogue_middleware=RogueDetectionMiddleware(
            detector=detector,
            agent_id=AGENT_ID,
            capability_profile={"allowed_tools": ALLOWED_TOOLS},
            audit_log=audit_log,
        ),
    )


def build_agent(runtime: ScenarioRuntime, client: Any) -> Agent[Any]:
    return Agent(
        client=client,
        name=AGENT_NAME,
        instructions=(
            "You are MedAssist's governed clinical assistant. Use the available tools "
            "to review symptoms, check interactions, summarize treatment guidance, and "
            "create de-identified case summaries. Never expose PHI, billing records, or "
            "prescribe controlled substances without proper review."
        ),
        tools=SCENARIO_TOOLS,
        middleware=[
            runtime.audit_middleware,
            runtime.policy_middleware,
            runtime.rogue_middleware,
            runtime.capability_middleware,
        ],
    )


def create_live_agent(runtime: ScenarioRuntime) -> tuple[Agent[Any] | None, str]:
    client, backend = configure_client()
    if client is None:
        return None, backend
    return build_agent(runtime, client), backend


def create_scripted_agent(runtime: ScenarioRuntime, responses: list[AgentResponse]) -> Agent[Any]:
    return build_agent(runtime, ScriptedResponseClient(responses))


def latest_audit_event(runtime: ScenarioRuntime, event_type: str) -> Any | None:
    for entry in runtime.audit_log.query(limit=1000):
        if entry.event_type == event_type:
            return entry
    return None


def extract_function_result(response: AgentResponse | None) -> str:
    if response is None:
        return "No response returned."
    for message in reversed(response.messages):
        for content in message.contents:
            if getattr(content, "type", None) == "function_result":
                return str(getattr(content, "result", ""))
    return response.text or str(response)


async def run_scripted_prompt(
    runtime: ScenarioRuntime,
    prompt: str,
    responses: list[AgentResponse],
) -> AgentResponse | None:
    return await create_scripted_agent(runtime, responses).run(prompt)


async def run_policy_check(runtime: ScenarioRuntime, text: str) -> tuple[bool, str]:
    response = await run_scripted_prompt(
        runtime,
        text,
        [text_response("Clinical guidance request cleared for governed handling.")],
    )
    violation = latest_audit_event(runtime, "policy_violation")
    if violation is not None:
        return False, response.text if response is not None else "Blocked by policy."
    evaluation = latest_audit_event(runtime, "policy_evaluation")
    matched_rule = evaluation.data.get("matched_rule") if evaluation is not None else "unknown"
    return True, f"allow via {matched_rule}"


async def run_tool_check(
    runtime: ScenarioRuntime,
    tool_name: str,
    arguments: dict[str, Any],
    final_text: str,
) -> tuple[bool, str]:
    response = await run_scripted_prompt(
        runtime,
        "Continue the governed clinical workflow with the next scripted tool call.",
        [
            function_call_response(tool_name, arguments),
            text_response(final_text),
        ],
    )
    detail = extract_function_result(response)
    return (not detail.startswith("⛔")), detail


async def run_rogue_sequence(runtime: ScenarioRuntime) -> tuple[bool, str]:
    baseline_calls = [
        ("lookup_symptoms", {"symptom": "chronic cough"}),
        ("lookup_symptoms", {"symptom": "fatigue"}),
        ("check_drug_interactions", {"pair": "aspirin + warfarin"}),
        ("create_deidentified_summary", {"case_id": "CASE-104"}),
    ]
    for tool_name, arguments in baseline_calls:
        await run_scripted_prompt(
            runtime,
            "Continue the governed clinical walkthrough with the next scripted tool call.",
            [
                function_call_response(tool_name, arguments),
                text_response(f"Completed {tool_name}."),
            ],
        )

    last_detail = "No rogue activity detected."
    for attempt in range(1, 13):
        response = await run_scripted_prompt(
            runtime,
            "Continue the governed clinical walkthrough with the next scripted tool call.",
            [
                function_call_response(
                    "prescribe_controlled_substance",
                    {"patient_id": "PT-201", "medication": "oxycodone 200mg"},
                )
            ],
        )
        last_detail = extract_function_result(response)
        if "quarantined" in last_detail.lower():
            event = latest_audit_event(runtime, "rogue_detection")
            if event is not None:
                data = event.data
                return True, (
                    f"risk={data['risk_level']}, score={data['composite_score']:.2f}, "
                    f"capability_score={data['capability_score']:.2f}"
                )

    return False, last_detail


async def preview_live_agent() -> None:
    runtime = build_runtime()
    agent, backend = create_live_agent(runtime)
    section("Optional live MAF agent run")
    if agent is None:
        show_result(
            "Skipped",
            f"{backend}. The default walkthrough below still runs through a scripted real MAF agent pipeline.",
        )
        return

    result = await agent.run(SAFE_PROMPT)
    show_result("Backend", backend)
    show_result("Agent.run", (result.text or str(result))[:200])


async def main() -> None:
    banner(
        "MedAssist - Healthcare Governance Demo",
        "Real Microsoft Agent Framework agent wiring with AGT maf_adapter middleware",
    )

    await preview_live_agent()

    runtime = build_runtime()

    section("Act 1: Policy enforcement")
    allowed, detail = await run_policy_check(runtime, SAFE_PROMPT)
    show_result("Allowed request", detail if allowed else f"unexpected block: {detail}")
    for blocked_prompt in BLOCKED_POLICY_PROMPTS:
        blocked, reason = await run_policy_check(runtime, blocked_prompt)
        label = "Blocked request" if not blocked else "Unexpected allow"
        show_result(label, f"{blocked_prompt} -> {reason}")

    section("Act 2: Capability sandboxing")
    tool_checks = [
        ("lookup_symptoms", {"symptom": "diabetes"}, "Symptom review completed."),
        ("check_drug_interactions", {"pair": "aspirin + warfarin"}, "Drug interaction review completed."),
        ("access_patient_record", {"patient_id": "PT-201"}, "Should never execute"),
        ("prescribe_controlled_substance", {"patient_id": "PT-201", "medication": "oxycodone 200mg"}, "Should never execute"),
    ]
    for tool_name, arguments, final_text in tool_checks:
        allowed, detail = await run_tool_check(runtime, tool_name, arguments, final_text)
        status = "Allowed tool" if allowed else "Blocked tool"
        show_result(status, f"{tool_name} -> {detail}")

    section("Act 3: Rogue agent detection")
    quarantined, detail = await run_rogue_sequence(runtime)
    if quarantined:
        show_result(
            "Quarantine",
            f"Repeated prescribe_controlled_substance attempts triggered clinical rogue-agent quarantine ({detail}).",
        )
    else:
        show_result("Detector", f"No quarantine triggered ({detail}).")

    section("Act 4: Audit trail and integrity")
    ok, error = runtime.audit_log.verify_integrity()
    detector_ok, detector_error = runtime.detector.verify_assessment_chain()
    show_result("Audit chain", "valid" if ok else f"invalid: {error}")
    show_result(
        "Rogue chain",
        "valid" if detector_ok else f"invalid: {detector_error}",
    )
    show_result("Audit entries", str(len(runtime.audit_log.query(limit=1000))))
    for entry in runtime.audit_log.query(limit=5):
        show_result(
            entry.event_type,
            f"{entry.action} | {entry.outcome} | {entry.resource or '-'}",
        )


if __name__ == "__main__":
    asyncio.run(main())
