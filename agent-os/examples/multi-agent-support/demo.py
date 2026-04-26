#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Multi-Agent Customer Service Demo with Governance
==================================================

Demonstrates how Agent OS governance policies protect a multi-agent
customer service system.  Three mock agents collaborate to handle
support tickets while governance enforces:

  1. Rate limiting   – max 5 tool calls per agent session
  2. PII redaction   – blocks SSN and credit-card patterns
  3. Audit logging   – every tool call is recorded for review

Run:  python demo.py          (no dependencies beyond agent-os)
"""

from __future__ import annotations

import sys
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Ensure the repo root's src/ is importable when running from the example dir.
# ---------------------------------------------------------------------------
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(_REPO_ROOT, "src"))

from agent_os.integrations.base import (
    BaseIntegration,
    ExecutionContext,
    GovernancePolicy,
    GovernanceEventType,
    PatternType,
    ToolCallRequest,
    ToolCallResult,
    PolicyInterceptor,
)

# ═══════════════════════════════════════════════════════════════════════════
# 1. GOVERNANCE POLICY
#    Define a single policy shared by all agents.  Uses only community-
#    edition features: allowed_tools, blocked_patterns (regex), and
#    max_tool_calls for rate limiting.
# ═══════════════════════════════════════════════════════════════════════════

# Regex patterns that match common PII formats.
# These are intentionally broad to catch test data in the demo.
SSN_PATTERN = r"\b\d{3}-\d{2}-\d{4}\b"             # e.g. 123-45-6789
CREDIT_CARD_PATTERN = r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"  # 16-digit card

support_policy = GovernancePolicy(
    name="customer_support",
    # Rate limiting: each agent may make at most 5 tool calls per session.
    max_tool_calls=5,
    # Allowed tools: only these actions are permitted.
    allowed_tools=[
        "lookup_customer",
        "search_kb",
        "create_ticket",
        "escalate",
        "send_reply",
    ],
    # PII redaction: block any input that contains SSN or credit-card numbers.
    blocked_patterns=[
        (SSN_PATTERN, PatternType.REGEX),
        (CREDIT_CARD_PATTERN, PatternType.REGEX),
    ],
    # Audit: log every call, checkpoint every 3 calls.
    log_all_calls=True,
    checkpoint_frequency=3,
    version="1.0.0",
)

# ═══════════════════════════════════════════════════════════════════════════
# 2. AUDIT LOG
#    A simple in-memory audit log that governance events are written to.
# ═══════════════════════════════════════════════════════════════════════════

audit_log: List[Dict[str, Any]] = []


def audit_listener(event: Dict[str, Any]) -> None:
    """Append every governance event to the audit log."""
    audit_log.append(event)


# ═══════════════════════════════════════════════════════════════════════════
# 3. INTEGRATION SUBCLASS
#    A minimal concrete BaseIntegration so we can use pre_execute / emit.
# ═══════════════════════════════════════════════════════════════════════════

class DemoIntegration(BaseIntegration):
    """Thin integration used only to access governance helpers."""

    def wrap(self, agent: Any) -> Any:
        return agent  # no real wrapping needed for the demo

    def unwrap(self, governed_agent: Any) -> Any:
        return governed_agent


# ═══════════════════════════════════════════════════════════════════════════
# 4. MOCK AGENTS
#    Each agent is a simple class that simulates LLM responses.  No real
#    model calls are made — the focus is on governance, not generation.
# ═══════════════════════════════════════════════════════════════════════════

class RouterAgent:
    """Routes incoming messages to the right specialist agent."""

    name = "RouterAgent"

    ESCALATION_KEYWORDS = {"manager", "supervisor", "urgent", "escalate", "complaint"}

    def route(self, message: str) -> str:
        """Return 'escalation' if keywords match, otherwise 'support'."""
        lower = message.lower()
        if any(kw in lower for kw in self.ESCALATION_KEYWORDS):
            return "escalation"
        return "support"


class SupportAgent:
    """Handles routine customer enquiries with mock responses."""

    name = "SupportAgent"

    # Simulated knowledge-base answers keyed by topic keyword.
    KB: Dict[str, str] = {
        "refund": "Refunds are processed within 5-7 business days after approval.",
        "shipping": "Standard shipping takes 3-5 business days; express is 1-2 days.",
        "password": "You can reset your password at https://example.com/reset.",
        "default": "I've found some information that may help. Let me look into this.",
    }

    def respond(self, message: str) -> str:
        lower = message.lower()
        for topic, answer in self.KB.items():
            if topic in lower:
                return answer
        return self.KB["default"]


class EscalationAgent:
    """Handles urgent or sensitive cases by creating a support ticket."""

    name = "EscalationAgent"

    def respond(self, message: str) -> str:
        return (
            "I understand this is urgent. I've created a priority ticket "
            "and a supervisor will contact you within 1 hour."
        )


# ═══════════════════════════════════════════════════════════════════════════
# 5. GOVERNED EXECUTION HELPER
#    Wraps each "tool call" through the governance layer so that policies
#    are checked before execution.
# ═══════════════════════════════════════════════════════════════════════════

def governed_call(
    integration: DemoIntegration,
    ctx: ExecutionContext,
    interceptor: PolicyInterceptor,
    tool_name: str,
    arguments: Dict[str, Any],
) -> Optional[str]:
    """
    Execute a tool call through governance.

    Returns the mock result string on success, or None if blocked.
    """
    # Build a vendor-neutral tool-call request.
    request = ToolCallRequest(
        tool_name=tool_name,
        arguments=arguments,
        call_id=f"call-{ctx.call_count + 1}",
        agent_id=ctx.agent_id,
    )

    # --- Pre-execution policy check via the interceptor ----
    result: ToolCallResult = interceptor.intercept(request)

    if not result.allowed:
        # Governance blocked this call — emit an event and log it.
        integration.emit(
            GovernanceEventType.TOOL_CALL_BLOCKED,
            {
                "agent_id": ctx.agent_id,
                "tool": tool_name,
                "reason": result.reason,
                "timestamp": datetime.now().isoformat(),
            },
        )
        print(f"  \u2718 BLOCKED  | tool={tool_name}")
        print(f"             | reason: {result.reason}")
        return None

    # --- Call allowed — increment counter and "execute" ----
    ctx.call_count += 1

    # Record the call in the context for audit purposes.
    call_record = {
        "call_id": request.call_id,
        "tool": tool_name,
        "arguments": arguments,
        "timestamp": datetime.now().isoformat(),
    }
    ctx.tool_calls.append(call_record)

    # Emit an audit event when log_all_calls is enabled.
    if ctx.policy.log_all_calls:
        integration.emit(
            GovernanceEventType.POLICY_CHECK,
            {
                "agent_id": ctx.agent_id,
                "tool": tool_name,
                "call_count": ctx.call_count,
                "timestamp": datetime.now().isoformat(),
            },
        )

    # Checkpoint every N calls (governance feature).
    if ctx.call_count % ctx.policy.checkpoint_frequency == 0:
        checkpoint_id = f"cp-{ctx.call_count}"
        ctx.checkpoints.append(checkpoint_id)
        integration.emit(
            GovernanceEventType.CHECKPOINT_CREATED,
            {
                "agent_id": ctx.agent_id,
                "checkpoint": checkpoint_id,
                "call_count": ctx.call_count,
                "timestamp": datetime.now().isoformat(),
            },
        )
        print(f"  \u25cb CHECKPOINT created: {checkpoint_id} (after {ctx.call_count} calls)")

    print(f"  \u2714 ALLOWED  | tool={tool_name} (call {ctx.call_count}/{ctx.policy.max_tool_calls})")
    return f"mock_result_for_{tool_name}"


# ═══════════════════════════════════════════════════════════════════════════
# 6. DEMO SCENARIOS
# ═══════════════════════════════════════════════════════════════════════════

def print_header(title: str) -> None:
    width = 64
    print()
    print("=" * width)
    print(f"  {title}")
    print("=" * width)


def print_section(title: str) -> None:
    print(f"\n--- {title} ---")


def run_demo() -> None:
    # Set up the integration with the shared policy and wire up audit.
    integration = DemoIntegration(policy=support_policy)
    integration.on(GovernanceEventType.POLICY_CHECK, audit_listener)
    integration.on(GovernanceEventType.POLICY_VIOLATION, audit_listener)
    integration.on(GovernanceEventType.TOOL_CALL_BLOCKED, audit_listener)
    integration.on(GovernanceEventType.CHECKPOINT_CREATED, audit_listener)

    # Instantiate agents.
    router = RouterAgent()
    support = SupportAgent()
    escalation = EscalationAgent()

    # Create per-agent execution contexts (each gets its own call counter).
    ctx_router = integration.create_context("router-agent")
    ctx_support = integration.create_context("support-agent")
    ctx_escalation = integration.create_context("escalation-agent")

    # Build a PolicyInterceptor for each context so rate limits are per-agent.
    pi_router = PolicyInterceptor(support_policy, ctx_router)
    pi_support = PolicyInterceptor(support_policy, ctx_support)
    pi_escalation = PolicyInterceptor(support_policy, ctx_escalation)

    # ── Print policy summary ──────────────────────────────────────────
    print_header("Multi-Agent Customer Service Demo")
    print(f"\n  Policy: {support_policy.name} (v{support_policy.version})")
    print(f"  Max tool calls per agent: {support_policy.max_tool_calls}")
    print(f"  Allowed tools: {', '.join(support_policy.allowed_tools)}")
    print(f"  Blocked patterns: SSN regex, credit-card regex")
    print(f"  Audit logging: {'ON' if support_policy.log_all_calls else 'OFF'}")
    print(f"  Checkpoint frequency: every {support_policy.checkpoint_frequency} calls")

    # ── Scenario 1: Normal support flow ───────────────────────────────
    print_section("Scenario 1: Normal support request")
    message = "Hi, I need help with my refund."
    print(f'  Customer: "{message}"')
    route = router.route(message)
    print(f'  Router  : route -> "{route}"')

    # SupportAgent looks up customer, searches KB, sends reply.
    governed_call(integration, ctx_support, pi_support, "lookup_customer", {"email": "alice@example.com"})
    governed_call(integration, ctx_support, pi_support, "search_kb", {"query": "refund"})
    reply = support.respond(message)
    governed_call(integration, ctx_support, pi_support, "send_reply", {"message": reply})
    print(f"  Agent   : \"{reply}\"")

    # ── Scenario 2: PII blocked ───────────────────────────────────────
    print_section("Scenario 2: PII redaction (SSN blocked)")
    pii_message = "My SSN is 123-45-6789, can you update my account?"
    print(f'  Customer: "{pii_message}"')
    governed_call(
        integration, ctx_support, pi_support,
        "lookup_customer", {"note": pii_message},
    )
    print("  (Governance blocked the call because it contained an SSN pattern)")

    print_section("Scenario 2b: PII redaction (credit card blocked)")
    cc_message = "Charge card 4111-1111-1111-1111 for the order."
    print(f'  Customer: "{cc_message}"')
    governed_call(
        integration, ctx_support, pi_support,
        "create_ticket", {"note": cc_message},
    )
    print("  (Governance blocked the call because it contained a credit-card pattern)")

    # ── Scenario 3: Escalation flow ───────────────────────────────────
    print_section("Scenario 3: Escalation to supervisor")
    urgent_msg = "This is urgent, I want to speak to a manager!"
    print(f'  Customer: "{urgent_msg}"')
    route = router.route(urgent_msg)
    print(f"  Router  : route -> \"{route}\"")

    governed_call(integration, ctx_escalation, pi_escalation, "create_ticket", {"priority": "high", "message": urgent_msg})
    governed_call(integration, ctx_escalation, pi_escalation, "escalate", {"level": "supervisor"})
    reply = escalation.respond(urgent_msg)
    governed_call(integration, ctx_escalation, pi_escalation, "send_reply", {"message": reply})
    print(f"  Agent   : \"{reply}\"")

    # ── Scenario 4: Rate limiting ─────────────────────────────────────
    print_section("Scenario 4: Rate limiting (max 5 calls)")
    print("  SupportAgent already used 3 calls; making 2 more to hit the limit...")
    governed_call(integration, ctx_support, pi_support, "search_kb", {"query": "shipping times"})
    governed_call(integration, ctx_support, pi_support, "send_reply", {"message": "Shipping info sent."})
    print("  Now attempting a 6th call (should be blocked):")
    governed_call(integration, ctx_support, pi_support, "search_kb", {"query": "return policy"})

    # ── Scenario 5: Disallowed tool ───────────────────────────────────
    print_section("Scenario 5: Disallowed tool blocked")
    print("  Attempting to call 'delete_account' (not in allowed_tools):")
    governed_call(integration, ctx_escalation, pi_escalation, "delete_account", {"user": "alice"})

    # ── Audit log summary ─────────────────────────────────────────────
    print_header("Audit Log Summary")
    for i, entry in enumerate(audit_log, 1):
        agent = entry.get("agent_id", "?")
        tool = entry.get("tool", "")
        reason = entry.get("reason", "")
        checkpoint = entry.get("checkpoint", "")
        call_count = entry.get("call_count", "")
        ts = entry.get("timestamp", "")

        if reason:
            print(f"  {i:>2}. [{agent}] BLOCKED  tool={tool}  reason={reason}")
        elif checkpoint:
            print(f"  {i:>2}. [{agent}] CHECKPOINT {checkpoint}  (calls={call_count})")
        else:
            print(f"  {i:>2}. [{agent}] ALLOWED  tool={tool}  (calls={call_count})")

    print(f"\n  Total audit entries: {len(audit_log)}")

    # ── Context summaries ─────────────────────────────────────────────
    print_header("Agent Context Summaries")
    for label, ctx in [("Router", ctx_router), ("Support", ctx_support), ("Escalation", ctx_escalation)]:
        print(f"  {label:>12}: calls={ctx.call_count}/{ctx.policy.max_tool_calls}  checkpoints={ctx.checkpoints}")

    print("\n  Demo complete.\n")


# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    run_demo()
