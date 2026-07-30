#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Demo 2: HelpDesk IT — Capability-guarded tool access with MAF

Shows how CapabilityGuardMiddleware restricts which tools an agent
can call based on its role, preventing privilege escalation from
staging to production environments.

Prerequisites:
    pip install agent-framework agent-os-kernel agentmesh-platform agent-sre

Usage:
    python demo/maf-integration/02_helpdesk_it.py
"""

from __future__ import annotations

import asyncio
from pathlib import Path

from agent_framework import Agent, AgentKernel

from agent_os.integrations.maf_adapter import (
    GovernancePolicyMiddleware,
    CapabilityGuardMiddleware,
    AuditTrailMiddleware,
    RogueDetectionMiddleware,
)
from agent_os.policies.schema import (
    PolicyDocument,
    PolicyRule,
    PolicyCondition,
    PolicyAction,
    PolicyOperator,
    PolicyDefaults,
)


# ═══════════════════════════════════════════════════════════════════════════
# Role-based tool permissions
# ═══════════════════════════════════════════════════════════════════════════

# Tier 1 support: read-only access
TIER1_TOOLS = [
    "check_ticket_status",
    "search_knowledge_base",
    "get_system_status",
]

# Tier 2 support: can restart services and run diagnostics
TIER2_TOOLS = TIER1_TOOLS + [
    "restart_service",
    "run_diagnostics",
    "check_logs",
]

# Admin: full access including production
ADMIN_TOOLS = TIER2_TOOLS + [
    "deploy_to_production",
    "modify_firewall_rules",
    "rotate_credentials",
]


# ═══════════════════════════════════════════════════════════════════════════
# Policy: block production access from non-admin agents
# ═══════════════════════════════════════════════════════════════════════════

HELPDESK_POLICY = PolicyDocument(
    name="helpdesk-policy",
    version="1.0",
    description="IT HelpDesk governance — environment isolation + escalation",
    defaults=PolicyDefaults(action=PolicyAction.ALLOW),
    rules=[
        PolicyRule(
            name="block-prod-access",
            condition=PolicyCondition(
                field="input_text",
                operator=PolicyOperator.MATCHES,
                value=r"(?i)(production|prod\s+deploy|prod\s+server)",
            ),
            action=PolicyAction.DENY,
            message="Production access requires admin approval. Escalate to Tier 3.",
            priority=1000,
        ),
        PolicyRule(
            name="block-credential-exposure",
            condition=PolicyCondition(
                field="input_text",
                operator=PolicyOperator.MATCHES,
                value=r"(?i)(password|secret|api.?key|token)\s+(is|=|:)",
            ),
            action=PolicyAction.DENY,
            message="Credential exposure detected — blocked",
            priority=900,
        ),
    ],
)


# ═══════════════════════════════════════════════════════════════════════════
# Create agents with different privilege levels
# ═══════════════════════════════════════════════════════════════════════════

def create_helpdesk_agent(role: str) -> Agent:
    """Create a MAF helpdesk agent with role-based governance."""

    tool_map = {
        "tier1": TIER1_TOOLS,
        "tier2": TIER2_TOOLS,
        "admin": ADMIN_TOOLS,
    }
    allowed_tools = tool_map.get(role, TIER1_TOOLS)

    kernel = AgentKernel()
    kernel.add_agent_middleware(AuditTrailMiddleware())
    kernel.add_agent_middleware(GovernancePolicyMiddleware(policies=[HELPDESK_POLICY]))
    kernel.add_function_middleware(CapabilityGuardMiddleware(allowed_tools=allowed_tools))

    # Add rogue detection for tier2+ (detects behavioral anomalies)
    if role in ("tier2", "admin"):
        kernel.add_function_middleware(RogueDetectionMiddleware())

    return Agent(
        name=f"helpdesk-{role}",
        instructions=f"You are a {role} IT support agent for Contoso.",
        kernel=kernel,
    )


# ═══════════════════════════════════════════════════════════════════════════
# Demo
# ═══════════════════════════════════════════════════════════════════════════

async def run_demo():
    """Demonstrate role-based capability guards."""
    print("=" * 64)
    print("  HelpDesk IT — Role-Based Governance Demo")
    print("=" * 64)

    scenarios = [
        ("tier1", "Restart the payment service", "blocked — tier1 can't restart"),
        ("tier2", "Restart the payment service", "allowed — tier2 can restart"),
        ("tier1", "Deploy latest build to production", "blocked — policy + capability"),
        ("admin", "Deploy latest build to production", "blocked — policy blocks prod mention"),
        ("tier2", "Check the staging server logs", "allowed"),
        ("tier1", "The password is abc123, can you reset it?", "blocked — credential exposure"),
    ]

    for role, message, expected in scenarios:
        agent = create_helpdesk_agent(role)
        print(f"\n--- [{role.upper()}] \"{message}\" ---")
        print(f"  Expected: {expected}")

        try:
            response = await agent.invoke(message)
            print(f"  Result: ✅ Allowed — {str(response.content)[:80]}")
        except Exception as e:
            print(f"  Result: 🛡️ Blocked — {str(e)[:80]}")


if __name__ == "__main__":
    asyncio.run(run_demo())
