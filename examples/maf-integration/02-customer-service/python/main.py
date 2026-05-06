#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Contoso Support demo using real MAF + AGT middleware."""

from __future__ import annotations

import asyncio
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Annotated, Any

REPO_ROOT = Path(__file__).resolve().parents[4]
for relative_path in (
    "packages\\agent-os\\src",
    "packages\\agent-mesh\\src",
    "packages\\agent-sre\\src",
):
    candidate = REPO_ROOT / relative_path
    if candidate.exists():
        sys.path.insert(0, str(candidate))

from agent_framework import Agent, Message, tool
from agent_framework.openai import OpenAIChatClient
from agent_os.integrations.maf_adapter import (
    AuditTrailMiddleware,
    CapabilityGuardMiddleware,
    GovernancePolicyMiddleware,
    MiddlewareTermination,
    RogueDetectionMiddleware,
)
from agent_os.policies import PolicyEvaluator

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


def create_agent(runtime: ScenarioRuntime) -> tuple[Agent[Any] | None, str]:
    client, backend = configure_client()
    if client is None:
        return None, backend

    agent = Agent(
        client=client,
        name=AGENT_NAME,
        instructions=(
            "You are Contoso's governed support assistant. Use the available tools to "
            "check orders, explain policy, create tickets, and escalate to managers. "
            "Never expose payment card data, modify billing directly, or grant large "
            "refunds without escalation."
        ),
        tools=[
            lookup_order,
            explain_return_policy,
            create_support_ticket,
            escalate_to_manager,
        ],
        middleware=[
            runtime.audit_middleware,
            runtime.policy_middleware,
            runtime.capability_middleware,
            runtime.rogue_middleware,
        ],
    )
    return agent, backend


def make_agent_context(text: str) -> Any:
    return SimpleNamespace(
        agent=SimpleNamespace(name=AGENT_ID),
        messages=[Message(role="user", contents=[text])],
        metadata={},
        result=None,
        stream=False,
    )


def make_function_context(tool_name: str, arguments: dict[str, Any] | None = None) -> Any:
    return SimpleNamespace(
        function=SimpleNamespace(name=tool_name),
        arguments=arguments or {},
        metadata={},
        result=None,
    )


async def run_policy_pipeline(runtime: ScenarioRuntime, text: str) -> tuple[bool, str]:
    context = make_agent_context(text)

    async def final_call() -> None:
        context.result = "Message cleared for customer support handling."

    async def policy_call() -> None:
        await runtime.policy_middleware.process(context, final_call)

    try:
        await runtime.audit_middleware.process(context, policy_call)
        decision = context.metadata.get("governance_decision")
        return True, f"{decision.action} via {decision.matched_rule}"
    except MiddlewareTermination as exc:
        return False, str(exc)


async def run_tool_check(
    runtime: ScenarioRuntime,
    tool_name: str,
    callback: Any,
    arguments: dict[str, Any] | None = None,
) -> tuple[bool, str]:
    context = make_function_context(tool_name, arguments)

    async def final_call() -> None:
        context.result = callback()

    try:
        await runtime.capability_middleware.process(context, final_call)
        return True, str(context.result)
    except MiddlewareTermination as exc:
        return False, str(exc)


def simulate_rogue_activity(runtime: ScenarioRuntime) -> tuple[bool, str]:
    base = time.time() - 10
    baseline = [
        ("lookup_order", base + 0.0),
        ("lookup_order", base + 1.2),
        ("create_support_ticket", base + 2.4),
        ("explain_return_policy", base + 2.7),
    ]
    for tool_name, timestamp in baseline:
        runtime.detector.record_action(
            agent_id=AGENT_ID,
            action=tool_name,
            tool_name=tool_name,
            timestamp=timestamp,
        )
        runtime.detector.assess(AGENT_ID, timestamp=timestamp)

    assessment = None
    for offset in range(5):
        timestamp = base + 3.6 + (offset * 0.1)
        runtime.detector.record_action(
            agent_id=AGENT_ID,
            action="issue_refund_credit",
            tool_name="issue_refund_credit",
            timestamp=timestamp,
        )
        assessment = runtime.detector.assess(AGENT_ID, timestamp=timestamp)

    assert assessment is not None
    if assessment.quarantine_recommended:
        runtime.audit_log.log(
            event_type="rogue_detection",
            agent_did=AGENT_ID,
            action="quarantine",
            resource="issue_refund_credit",
            data=assessment.to_dict(),
            outcome="denied",
        )
    return assessment.quarantine_recommended, (
        f"risk={assessment.risk_level.value}, score={assessment.composite_score:.2f}, "
        f"capability_score={assessment.capability_score:.2f}"
    )


async def preview_live_agent() -> None:
    runtime = build_runtime()
    agent, backend = create_agent(runtime)
    section("Optional live MAF agent run")
    if agent is None:
        show_result(
            "Skipped",
            f"{backend}. The deterministic walkthrough below still exercises the real AGT middleware objects.",
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
    allowed, detail = await run_policy_pipeline(runtime, SAFE_PROMPT)
    show_result("Allowed request", detail if allowed else f"unexpected block: {detail}")
    for blocked_prompt in BLOCKED_POLICY_PROMPTS:
        blocked, reason = await run_policy_pipeline(runtime, blocked_prompt)
        label = "Blocked request" if not blocked else "Unexpected allow"
        show_result(label, f"{blocked_prompt} -> {reason}")

    section("Act 2: Capability sandboxing")
    tool_checks = [
        ("lookup_order", lambda: lookup_order_impl("789"), {"order_id": "789"}),
        (
            "escalate_to_manager",
            lambda: escalate_to_manager_impl("789"),
            {"order_id": "789"},
        ),
        (
            "modify_account_billing",
            lambda: "Should never execute",
            {"order_id": "789"},
        ),
        (
            "issue_refund_credit",
            lambda: "Should never execute",
            {"order_id": "789", "amount": 5000},
        ),
    ]
    for tool_name, callback, arguments in tool_checks:
        allowed, detail = await run_tool_check(runtime, tool_name, callback, arguments)
        status = "Allowed tool" if allowed else "Blocked tool"
        show_result(status, f"{tool_name} -> {detail}")

    section("Act 3: Rogue agent detection")
    quarantined, detail = simulate_rogue_activity(runtime)
    if quarantined:
        show_result(
            "Quarantine",
            f"Repeated issue_refund_credit telemetry triggered refund-farming quarantine ({detail}).",
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
