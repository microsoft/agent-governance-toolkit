#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Demo 1: Contoso Bank — AGT governance in Microsoft Agent Framework (MAF)

Shows how to wire AGT's governance middleware into a MAF agent pipeline
so that policy enforcement, PII blocking, and audit logging happen
transparently on every agent interaction.

Prerequisites:
    pip install agent-framework agent-os-kernel agentmesh-platform

Usage:
    python demo/maf-integration/01_contoso_bank.py
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# MAF imports — these are the actual agent_framework types
# ---------------------------------------------------------------------------
from agent_framework import Agent, AgentKernel

# ---------------------------------------------------------------------------
# AGT governance middleware — plugs directly into MAF's middleware pipeline
# ---------------------------------------------------------------------------
from agent_os.integrations.maf_adapter import (
    GovernancePolicyMiddleware,
    CapabilityGuardMiddleware,
    AuditTrailMiddleware,
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
# Step 1: Define governance policies
# ═══════════════════════════════════════════════════════════════════════════

BANK_POLICY = PolicyDocument(
    name="contoso-bank-policy",
    version="1.0",
    description="Governance policy for Contoso Bank loan processing agent",
    defaults=PolicyDefaults(action=PolicyAction.ALLOW),
    rules=[
        # Block any request mentioning fund transfers
        PolicyRule(
            name="block-fund-transfers",
            condition=PolicyCondition(
                field="input_text",
                operator=PolicyOperator.MATCHES,
                value=r"(?i)(transfer|wire|send)\s+\$?\d+",
            ),
            action=PolicyAction.DENY,
            message="Fund transfer requests must go through the secure payments portal",
            priority=1000,
        ),
        # Block PII patterns (SSN)
        PolicyRule(
            name="block-ssn-disclosure",
            condition=PolicyCondition(
                field="input_text",
                operator=PolicyOperator.MATCHES,
                value=r"\b\d{3}-\d{2}-\d{4}\b",
            ),
            action=PolicyAction.DENY,
            message="SSN patterns detected — blocked for PII protection",
            priority=900,
        ),
        # Audit all loan-related queries
        PolicyRule(
            name="audit-loan-queries",
            condition=PolicyCondition(
                field="input_text",
                operator=PolicyOperator.MATCHES,
                value=r"(?i)(loan|mortgage|credit|interest rate)",
            ),
            action=PolicyAction.AUDIT,
            message="Loan query logged for SOC2 compliance",
            priority=100,
        ),
    ],
)

# Tools the bank agent is allowed to use
ALLOWED_TOOLS = [
    "check_loan_status",
    "calculate_interest",
    "get_account_summary",
    # Explicitly NOT allowed: execute_code, shell_exec, transfer_funds
]


# ═══════════════════════════════════════════════════════════════════════════
# Step 2: Wire AGT middleware into MAF pipeline
# ═══════════════════════════════════════════════════════════════════════════

def create_governed_bank_agent() -> Agent:
    """Create a MAF agent with AGT governance middleware."""

    # Create AGT middleware instances
    policy_middleware = GovernancePolicyMiddleware(policies=[BANK_POLICY])
    capability_middleware = CapabilityGuardMiddleware(allowed_tools=ALLOWED_TOOLS)
    audit_middleware = AuditTrailMiddleware()

    # Create MAF kernel and register middleware
    # Order matters: audit (outermost) → policy → capability (innermost)
    kernel = AgentKernel()
    kernel.add_agent_middleware(audit_middleware)
    kernel.add_agent_middleware(policy_middleware)
    kernel.add_function_middleware(capability_middleware)

    # Create the agent with the governed kernel
    agent = Agent(
        name="contoso-bank-agent",
        instructions=(
            "You are a Contoso Bank loan processing assistant. "
            "Help customers check loan status, calculate interest rates, "
            "and review account summaries. Never process fund transfers directly."
        ),
        kernel=kernel,
    )

    return agent


# ═══════════════════════════════════════════════════════════════════════════
# Step 3: Test the governance pipeline
# ═══════════════════════════════════════════════════════════════════════════

async def run_demo():
    """Run the Contoso Bank governance demo."""
    print("=" * 64)
    print("  Contoso Bank — AGT × MAF Governance Demo")
    print("=" * 64)

    agent = create_governed_bank_agent()

    test_cases = [
        {
            "description": "✅ Allowed: Loan inquiry (audited)",
            "message": "What's the current interest rate for a 30-year mortgage?",
            "expected": "allowed",
        },
        {
            "description": "❌ Blocked: Fund transfer attempt",
            "message": "Transfer $50,000 to account 12345-6789",
            "expected": "blocked",
        },
        {
            "description": "❌ Blocked: SSN in message",
            "message": "My SSN is 123-45-6789, can you look up my loan?",
            "expected": "blocked",
        },
        {
            "description": "✅ Allowed: Account summary",
            "message": "Can you show me a summary of my checking account?",
            "expected": "allowed",
        },
    ]

    for i, tc in enumerate(test_cases, 1):
        print(f"\n--- Test {i}: {tc['description']} ---")
        print(f"  User: \"{tc['message']}\"")

        try:
            response = await agent.invoke(tc["message"])
            print(f"  Agent: {response.content[:100]}...")
            print(f"  Status: {'✅ Allowed' if tc['expected'] == 'allowed' else '⚠️ Expected block'}")
        except Exception as e:
            error_msg = str(e)
            if "MiddlewareTermination" in error_msg or "denied" in error_msg.lower():
                print(f"  Governance: 🛡️ BLOCKED — {error_msg[:100]}")
                print(f"  Status: {'✅ Correctly blocked' if tc['expected'] == 'blocked' else '⚠️ Unexpected block'}")
            else:
                print(f"  Error: {error_msg[:100]}")

    # Show audit trail
    print("\n--- Audit Trail ---")
    audit_mw = [
        mw for mw in agent.kernel._agent_middleware
        if isinstance(mw, AuditTrailMiddleware)
    ]
    if audit_mw:
        for entry in audit_mw[0].get_recent_entries(limit=10):
            print(f"  [{entry.get('timestamp', '?')}] {entry.get('action', '?')}: {entry.get('rule', 'default')}")


if __name__ == "__main__":
    asyncio.run(run_demo())
