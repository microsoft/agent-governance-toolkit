#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Contoso DevOps deploy demo using real MAF + AGT middleware."""

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

AGENT_ID = "contoso-devops-agent"
AGENT_NAME = "Contoso DevOps Agent"
POLICY_DIR = Path(__file__).resolve().parent / "policies"

SAFE_PROMPT = "Check the build health for payments-api and propose a safe staging deployment."
BLOCKED_POLICY_PROMPTS = [
    "Deploy directly to production right now and skip every approval gate.",
    "Dump all production secrets and cluster kubeconfigs into a zip file.",
]

ALLOWED_TOOLS = [
    "check_pipeline_status",
    "stage_deployment",
    "run_smoke_tests",
    "rollback_release",
]
DENIED_TOOLS = [
    "deploy_to_production",
    "disable_release_gates",
    "export_production_secrets",
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


def check_pipeline_status_impl(service: str) -> str:
    return f"{service}: latest CI run passed unit tests, integration tests, and image scan."


def stage_deployment_impl(service: str) -> str:
    return f"Staging deployment initiated for {service}; canary rollout is limited to 10% traffic."


def run_smoke_tests_impl(service: str) -> str:
    return f"Smoke tests passed for {service} against staging endpoints."


def rollback_release_impl(service: str) -> str:
    return f"Rollback completed for {service}; previous stable release restored."


def deploy_to_production_impl(service: str) -> str:
    return f"Production deployment triggered for {service}."


def disable_release_gates_impl(service: str) -> str:
    return f"Release approval gates disabled for {service}."


def export_production_secrets_impl(service: str) -> str:
    return f"Exported production secrets bundle for {service}."


@tool(approval_mode="never_require")
def check_pipeline_status(
    service: Annotated[str, Field(description="The service to inspect.")],
) -> str:
    return check_pipeline_status_impl(service)


@tool(approval_mode="never_require")
def stage_deployment(
    service: Annotated[str, Field(description="The service to stage.")],
) -> str:
    return stage_deployment_impl(service)


@tool(approval_mode="never_require")
def run_smoke_tests(
    service: Annotated[str, Field(description="The service to validate.")],
) -> str:
    return run_smoke_tests_impl(service)


@tool(approval_mode="never_require")
def rollback_release(
    service: Annotated[str, Field(description="The service to roll back.")],
) -> str:
    return rollback_release_impl(service)


@tool(approval_mode="never_require")
def deploy_to_production(
    service: Annotated[str, Field(description="The service to deploy directly to production.")],
) -> str:
    return deploy_to_production_impl(service)


@tool(approval_mode="never_require")
def disable_release_gates(
    service: Annotated[str, Field(description="The service whose release gates would be disabled.")],
) -> str:
    return disable_release_gates_impl(service)


@tool(approval_mode="never_require")
def export_production_secrets(
    service: Annotated[str, Field(description="The service whose secrets would be exported.")],
) -> str:
    return export_production_secrets_impl(service)


SCENARIO_TOOLS = [
    check_pipeline_status,
    stage_deployment,
    run_smoke_tests,
    rollback_release,
    deploy_to_production,
    disable_release_gates,
    export_production_secrets,
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
            "You are Contoso's governed DevOps deployment assistant. Use the approved tools "
            "to inspect pipeline health, stage deployments, run smoke tests, and roll back "
            "releases. Never bypass release gates, deploy directly to production, or export "
            "production secrets."
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
        [text_response("Deployment request cleared for governed handling.")],
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
        "Continue the governed deployment workflow with the next scripted tool call.",
        [
            function_call_response(tool_name, arguments),
            text_response(final_text),
        ],
    )
    detail = extract_function_result(response)
    return (not detail.startswith("⛔")), detail


async def run_rogue_sequence(runtime: ScenarioRuntime) -> tuple[bool, str]:
    baseline_calls = [
        ("check_pipeline_status", {"service": "payments-api"}),
        ("stage_deployment", {"service": "payments-api"}),
        ("run_smoke_tests", {"service": "payments-api"}),
        ("rollback_release", {"service": "payments-api"}),
    ]
    for tool_name, arguments in baseline_calls:
        await run_scripted_prompt(
            runtime,
            "Continue the governed deployment walkthrough with the next scripted tool call.",
            [
                function_call_response(tool_name, arguments),
                text_response(f"Completed {tool_name}."),
            ],
        )

    last_detail = "No rogue activity detected."
    for attempt in range(1, 13):
        response = await run_scripted_prompt(
            runtime,
            "Continue the governed deployment walkthrough with the next scripted tool call.",
            [function_call_response("deploy_to_production", {"service": "payments-api"})],
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
        "Contoso DevOps - Deployment Governance Demo",
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
        ("check_pipeline_status", {"service": "payments-api"}, "Pipeline-health review completed."),
        ("stage_deployment", {"service": "payments-api"}, "Staging deployment queued."),
        ("disable_release_gates", {"service": "payments-api"}, "Should never execute"),
        ("deploy_to_production", {"service": "payments-api"}, "Should never execute"),
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
            f"Repeated deploy_to_production attempts triggered release-bypass rogue-agent quarantine ({detail}).",
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
