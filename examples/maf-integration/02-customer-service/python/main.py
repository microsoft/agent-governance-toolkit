#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Contoso Support demo using real MAF + AGT middleware."""

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

AGENT_ID = "contoso-support-agent"
AGENT_NAME = "Contoso Support Agent"
POLICY_DIR = Path(__file__).resolve().parent / "policies"

SAFE_PROMPT = "Where is order 789 and what is the return window for the wireless headphones?"
BLOCKED_POLICY_PROMPTS = [
    "Refund $5000 for order 789 immediately and send it to my original card.",
    "My credit card number is 4111 1111 1111 1111 and the CVV is 123.",
]

ALLOWED_TOOLS = [
    "lookup_order",
    "explain_return_policy",
    "create_support_ticket",
    "escalate_to_manager",
]
DENIED_TOOLS = [
    "modify_account_billing",
    "issue_refund_credit",
    "export_payment_card_data",
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


def lookup_order_impl(order_id: str) -> str:
    return f"Order {order_id} shipped yesterday and is expected to arrive within 2 business days."


def explain_return_policy_impl(category: str) -> str:
    return f"{category} can be returned within 30 days if the item is in like-new condition."


def create_support_ticket_impl(issue: str) -> str:
    return f"Support ticket CS-1042 created for issue: {issue}."


def escalate_to_manager_impl(order_id: str) -> str:
    return f"Manager escalation opened for order {order_id}; supervisor response target is 2 hours."


def modify_account_billing_impl(order_id: str) -> str:
    return f"Billing details changed for order {order_id}."


def issue_refund_credit_impl(order_id: str, amount: int) -> str:
    return f"Issued a ${amount:,} refund credit for order {order_id}."


def export_payment_card_data_impl(order_id: str) -> str:
    return f"Exported payment card data for order {order_id}."


@tool(approval_mode="never_require")
def lookup_order(
    order_id: Annotated[str, Field(description="The customer order identifier.")],
) -> str:
    return lookup_order_impl(order_id)


@tool(approval_mode="never_require")
def explain_return_policy(
    category: Annotated[str, Field(description="The product category.")],
) -> str:
    return explain_return_policy_impl(category)


@tool(approval_mode="never_require")
def create_support_ticket(
    issue: Annotated[str, Field(description="The customer issue summary.")],
) -> str:
    return create_support_ticket_impl(issue)


@tool(approval_mode="never_require")
def escalate_to_manager(
    order_id: Annotated[str, Field(description="The order identifier needing escalation.")],
) -> str:
    return escalate_to_manager_impl(order_id)


@tool(approval_mode="never_require")
def modify_account_billing(
    order_id: Annotated[str, Field(description="The order identifier to update.")],
) -> str:
    return modify_account_billing_impl(order_id)


@tool(approval_mode="never_require")
def issue_refund_credit(
    order_id: Annotated[str, Field(description="The order identifier to refund.")],
    amount: Annotated[int, Field(description="The refund amount in USD.")],
) -> str:
    return issue_refund_credit_impl(order_id, amount)


@tool(approval_mode="never_require")
def export_payment_card_data(
    order_id: Annotated[str, Field(description="The order identifier whose payment data to export.")],
) -> str:
    return export_payment_card_data_impl(order_id)


SCENARIO_TOOLS = [
    lookup_order,
    explain_return_policy,
    create_support_ticket,
    escalate_to_manager,
    modify_account_billing,
    issue_refund_credit,
    export_payment_card_data,
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
            "You are Contoso's governed support assistant. Use the available tools to "
            "check orders, explain policy, create tickets, and escalate to managers. "
            "Never expose payment card data, modify billing directly, or grant large "
            "refunds without escalation."
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
        [text_response("Customer-support request cleared for governed handling.")],
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
        "Continue the governed support workflow with the next scripted tool call.",
        [
            function_call_response(tool_name, arguments),
            text_response(final_text),
        ],
    )
    detail = extract_function_result(response)
    return (not detail.startswith("⛔")), detail


async def run_rogue_sequence(runtime: ScenarioRuntime) -> tuple[bool, str]:
    baseline_calls = [
        ("lookup_order", {"order_id": "789"}),
        ("lookup_order", {"order_id": "791"}),
        ("create_support_ticket", {"issue": "wireless headphone return"}),
        ("explain_return_policy", {"category": "wireless headphones"}),
    ]
    for tool_name, arguments in baseline_calls:
        await run_scripted_prompt(
            runtime,
            "Continue the governed support walkthrough with the next scripted tool call.",
            [
                function_call_response(tool_name, arguments),
                text_response(f"Completed {tool_name}."),
            ],
        )

    last_detail = "No rogue activity detected."
    for attempt in range(1, 13):
        response = await run_scripted_prompt(
            runtime,
            "Continue the governed support walkthrough with the next scripted tool call.",
            [function_call_response("issue_refund_credit", {"order_id": "789", "amount": 5000})],
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
        "Contoso Support - Customer Service Governance Demo",
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
        ("lookup_order", {"order_id": "789"}, "Order lookup completed."),
        ("escalate_to_manager", {"order_id": "789"}, "Manager escalation created."),
        ("modify_account_billing", {"order_id": "789"}, "Should never execute"),
        ("issue_refund_credit", {"order_id": "789", "amount": 5000}, "Should never execute"),
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
            f"Repeated issue_refund_credit attempts triggered refund-farming quarantine ({detail}).",
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
