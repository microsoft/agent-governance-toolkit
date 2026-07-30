#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Finance Agent with SOC2 Compliance — Agent OS Demo
====================================================

Demonstrates Agent OS governance for SOC2-compliant financial operations
with role-based access control, sanctions screening, and approval workflows.

Features:
  1. Role-based access  – accounts_payable, finance_manager, cfo
  2. Human approval     – transactions over $10,000 require approval
  3. Blocked patterns   – sanctioned entities, SSN/credit-card PII
  4. Rate limiting      – max transfers per agent session
  5. Immutable audit    – append-only JSON log with CSV/JSON export

Run:  python main.py          (no dependencies beyond agent-os)
"""

from __future__ import annotations

import csv
import json
import os
import sys
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
    PolicyInterceptor,
    ToolCallRequest,
    ToolCallResult,
)

# ═══════════════════════════════════════════════════════════════════════════
# 1. CONSTANTS & CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

SANCTIONED_ENTITIES = ["SanctionedCorp", "BadActor LLC", "Blocked Inc"]
SSN_PATTERN = r"\b\d{3}-\d{2}-\d{4}\b"
CREDIT_CARD_PATTERN = r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"

APPROVAL_THRESHOLD = 10_000.00
RATE_LIMIT_PER_SESSION = 10

# Role definitions: allowed tools, max single transfer, approval capability
ROLES: Dict[str, Dict[str, Any]] = {
    "accounts_payable": {
        "allowed_tools": ["transfer", "query_balance"],
        "max_transfer": 5_000.00,
        "can_approve": False,
    },
    "finance_manager": {
        "allowed_tools": ["transfer", "approve", "query_balance"],
        "max_transfer": 50_000.00,
        "can_approve": True,
    },
    "cfo": {
        "allowed_tools": ["transfer", "approve", "query_balance", "generate_report"],
        "max_transfer": float("inf"),
        "can_approve": True,
    },
}

# ═══════════════════════════════════════════════════════════════════════════
# 2. GOVERNANCE POLICIES (one per role)
#    SOC2-oriented policies using real Agent OS GovernancePolicy:
#    require_human_approval, max_tool_calls, allowed_tools, blocked_patterns.
# ═══════════════════════════════════════════════════════════════════════════

COMMON_BLOCKED_PATTERNS: list = [
    (SSN_PATTERN, PatternType.REGEX),
    (CREDIT_CARD_PATTERN, PatternType.REGEX),
    "password",
    "secret",
] + list(SANCTIONED_ENTITIES)


def make_role_policy(role: str) -> GovernancePolicy:
    """Create a SOC2 governance policy scoped to a specific role."""
    cfg = ROLES[role]
    return GovernancePolicy(
        name=f"soc2_{role}",
        require_human_approval=True,
        max_tool_calls=20,
        allowed_tools=cfg["allowed_tools"],
        blocked_patterns=COMMON_BLOCKED_PATTERNS,
        log_all_calls=True,
        checkpoint_frequency=5,
        version="1.0.0",
    )


# ═══════════════════════════════════════════════════════════════════════════
# 3. IMMUTABLE AUDIT LOG
#    Append-only list written to JSON and CSV files at the end.
# ═══════════════════════════════════════════════════════════════════════════

audit_log: List[Dict[str, Any]] = []


def audit_listener(event: Dict[str, Any]) -> None:
    """Append every governance event to the immutable audit log."""
    audit_log.append(event)


def save_audit_json(path: str) -> None:
    """Write the audit log to an append-only JSON file."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(audit_log, fh, indent=2)


def save_audit_csv(path: str) -> None:
    """Export the audit log to CSV for compliance review."""
    if not audit_log:
        return
    fieldnames = [
        "timestamp", "agent_id", "event_type", "tool", "role",
        "call_count", "reason", "checkpoint", "amount", "recipient", "decision",
    ]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for entry in audit_log:
            writer.writerow(entry)


# ═══════════════════════════════════════════════════════════════════════════
# 4. INTEGRATION SUBCLASS
# ═══════════════════════════════════════════════════════════════════════════

class SOC2Integration(BaseIntegration):
    """Thin integration used to access Agent OS governance helpers."""

    def wrap(self, agent: Any) -> Any:
        return agent

    def unwrap(self, governed_agent: Any) -> Any:
        return governed_agent


# ═══════════════════════════════════════════════════════════════════════════
# 5. CUSTOM SOC2 INTERCEPTOR
#    Role-aware interceptor enforcing SOC2 controls:
#    - Allowed tools per role (separation of duties, CC6.1)
#    - Blocked patterns: sanctions + PII (CC7.3)
#    - Transfer amount limits per role (CC6.3)
#    - Rate limiting (CC8.1)
#    - Max tool calls
# ═══════════════════════════════════════════════════════════════════════════

class SOC2Interceptor:
    """Role-aware interceptor that enforces SOC2 governance controls."""

    def __init__(
        self,
        policy: GovernancePolicy,
        context: ExecutionContext,
        role: str,
    ) -> None:
        self.policy = policy
        self.context = context
        self.role = role
        self.role_config = ROLES[role]
        self._transfer_count = 0

    def intercept(self, request: ToolCallRequest) -> ToolCallResult:
        # 1. Check allowed tools for this role (SOC2 CC6.1 separation of duties)
        if (
            self.policy.allowed_tools
            and request.tool_name not in self.policy.allowed_tools
        ):
            return ToolCallResult(
                allowed=False,
                reason=f"Tool '{request.tool_name}' not permitted for role '{self.role}'",
            )

        # 2. Check blocked patterns: sanctions + PII (SOC2 CC7.3)
        args_str = str(request.arguments)
        matched = self.policy.matches_pattern(args_str)
        if matched:
            return ToolCallResult(
                allowed=False,
                reason=f"Blocked pattern detected: {matched[0]}",
            )

        # 3. Check max tool calls
        if self.context.call_count >= self.policy.max_tool_calls:
            return ToolCallResult(
                allowed=False,
                reason=f"Max tool calls exceeded ({self.policy.max_tool_calls})",
            )

        # 4. Transfer-specific checks
        if request.tool_name == "transfer":
            self._transfer_count += 1
            if self._transfer_count > RATE_LIMIT_PER_SESSION:
                return ToolCallResult(
                    allowed=False,
                    reason=f"Rate limit exceeded ({RATE_LIMIT_PER_SESSION} transfers/session)",
                )
            amount = request.arguments.get("amount", 0)
            max_transfer = self.role_config["max_transfer"]
            if amount > max_transfer:
                return ToolCallResult(
                    allowed=False,
                    reason=f"Amount ${amount:,.2f} exceeds role limit of ${max_transfer:,.2f}",
                )

        return ToolCallResult(allowed=True)


# ═══════════════════════════════════════════════════════════════════════════
# 6. MOCK FINANCIAL AGENT
#    Simulates an LLM-based agent that processes financial transactions.
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class Transaction:
    tx_id: str
    amount: float
    recipient: str
    description: str
    status: str = "pending"


class FinancialAgent:
    """Mock agent that processes financial transactions."""

    def __init__(self) -> None:
        self._tx_counter = 0

    def process(self, amount: float, recipient: str, description: str) -> Transaction:
        """Simulate processing a transaction with SOC2 approval rules."""
        self._tx_counter += 1
        tx = Transaction(
            tx_id=f"TX-{self._tx_counter:04d}",
            amount=amount,
            recipient=recipient,
            description=description,
        )
        if amount > APPROVAL_THRESHOLD:
            tx.status = "pending_approval"
        else:
            tx.status = "approved"
        return tx

    def query_balance(self, account: str) -> Dict[str, Any]:
        """Return a mock account balance."""
        return {"account": account, "balance": 125_000.00, "currency": "USD"}


# ═══════════════════════════════════════════════════════════════════════════
# 7. GOVERNED EXECUTION HELPER
# ═══════════════════════════════════════════════════════════════════════════

def governed_call(
    integration: SOC2Integration,
    ctx: ExecutionContext,
    interceptor: SOC2Interceptor,
    tool_name: str,
    arguments: Dict[str, Any],
) -> Optional[str]:
    """
    Execute a tool call through the SOC2 governance layer.

    Returns the mock result string on success, or None if blocked.
    """
    request = ToolCallRequest(
        tool_name=tool_name,
        arguments=arguments,
        call_id=f"call-{ctx.call_count + 1}",
        agent_id=ctx.agent_id,
    )

    result: ToolCallResult = interceptor.intercept(request)

    if not result.allowed:
        integration.emit(
            GovernanceEventType.TOOL_CALL_BLOCKED,
            {
                "agent_id": ctx.agent_id,
                "tool": tool_name,
                "role": interceptor.role,
                "reason": result.reason,
                "event_type": "BLOCKED",
                "decision": "blocked",
                "timestamp": datetime.now().isoformat(),
            },
        )
        print(f"  \u2718 BLOCKED  | tool={tool_name}")
        print(f"             | reason: {result.reason}")
        return None

    ctx.call_count += 1
    ctx.tool_calls.append({
        "call_id": request.call_id,
        "tool": tool_name,
        "arguments": arguments,
        "timestamp": datetime.now().isoformat(),
    })

    if ctx.policy.log_all_calls:
        integration.emit(
            GovernanceEventType.POLICY_CHECK,
            {
                "agent_id": ctx.agent_id,
                "tool": tool_name,
                "role": interceptor.role,
                "call_count": ctx.call_count,
                "event_type": "ALLOWED",
                "decision": "allowed",
                "timestamp": datetime.now().isoformat(),
            },
        )

    if ctx.call_count % ctx.policy.checkpoint_frequency == 0:
        checkpoint_id = f"cp-{ctx.call_count}"
        ctx.checkpoints.append(checkpoint_id)
        integration.emit(
            GovernanceEventType.CHECKPOINT_CREATED,
            {
                "agent_id": ctx.agent_id,
                "checkpoint": checkpoint_id,
                "call_count": ctx.call_count,
                "event_type": "CHECKPOINT",
                "decision": "checkpoint",
                "timestamp": datetime.now().isoformat(),
            },
        )
        print(f"  \u25cb CHECKPOINT created: {checkpoint_id} (after {ctx.call_count} calls)")

    print(f"  \u2714 ALLOWED  | tool={tool_name} (call {ctx.call_count}/{ctx.policy.max_tool_calls})")
    return f"mock_result_for_{tool_name}"


# ═══════════════════════════════════════════════════════════════════════════
# 8. DISPLAY HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def print_header(title: str) -> None:
    width = 64
    print()
    print("=" * width)
    print(f"  {title}")
    print("=" * width)


def print_section(title: str) -> None:
    print(f"\n--- {title} ---")


def _wire_listeners(integration: SOC2Integration) -> None:
    """Register audit listeners on all relevant event types."""
    for evt in (
        GovernanceEventType.POLICY_CHECK,
        GovernanceEventType.POLICY_VIOLATION,
        GovernanceEventType.TOOL_CALL_BLOCKED,
        GovernanceEventType.CHECKPOINT_CREATED,
    ):
        integration.on(evt, audit_listener)


# ═══════════════════════════════════════════════════════════════════════════
# 9. DEMO SCENARIOS
# ═══════════════════════════════════════════════════════════════════════════

def run_demo() -> None:
    # -- Set up role-specific integrations & interceptors -------------------
    ap_policy = make_role_policy("accounts_payable")
    ap_integration = SOC2Integration(policy=ap_policy)
    _wire_listeners(ap_integration)
    ap_ctx = ap_integration.create_context("soc2-ap-agent")
    ap_interceptor = SOC2Interceptor(ap_policy, ap_ctx, "accounts_payable")

    fm_policy = make_role_policy("finance_manager")
    fm_integration = SOC2Integration(policy=fm_policy)
    _wire_listeners(fm_integration)
    fm_ctx = fm_integration.create_context("soc2-fm-agent")
    fm_interceptor = SOC2Interceptor(fm_policy, fm_ctx, "finance_manager")

    cfo_policy = make_role_policy("cfo")
    cfo_integration = SOC2Integration(policy=cfo_policy)
    _wire_listeners(cfo_integration)
    cfo_ctx = cfo_integration.create_context("soc2-cfo-agent")
    cfo_interceptor = SOC2Interceptor(cfo_policy, cfo_ctx, "cfo")

    agent = FinancialAgent()

    # -- Print policy summary ----------------------------------------------
    print_header("Finance SOC2 Compliance Demo \u2014 Agent OS")
    print(f"\n  Roles: {', '.join(ROLES.keys())}")
    print(f"  Human approval required: YES (transactions > ${APPROVAL_THRESHOLD:,.0f})")
    print(f"  Max tool calls per session: {ap_policy.max_tool_calls}")
    print(f"  Rate limit: {RATE_LIMIT_PER_SESSION} transfers/session")
    print(f"  Blocked patterns: SSN regex, credit-card regex, sanctions list, PII keywords")
    print(f"  Audit logging: {'ON' if ap_policy.log_all_calls else 'OFF'}")
    print(f"  Sanctioned entities: {', '.join(SANCTIONED_ENTITIES)}")

    # -- Scenario 1: Small transfer (auto-approved) ------------------------
    print_section("Scenario 1: Small transfer \u2014 accounts_payable (auto-approved)")
    print(f"\n  $500.00 \u2192 Vendor ABC (within AP limit of $5,000)")
    result = governed_call(
        ap_integration, ap_ctx, ap_interceptor,
        "transfer",
        {"amount": 500.00, "recipient": "Vendor ABC", "description": "Office supplies"},
    )
    if result:
        tx = agent.process(500.00, "Vendor ABC", "Office supplies")
        audit_log.append({
            "agent_id": ap_ctx.agent_id,
            "event_type": "TRANSACTION",
            "tool": "transfer",
            "role": "accounts_payable",
            "amount": 500.00,
            "recipient": "Vendor ABC",
            "decision": tx.status,
            "timestamp": datetime.now().isoformat(),
        })
        print(f"  \u2705 PROCESSED: ${tx.amount:,.2f} to {tx.recipient} \u2014 {tx.status}")

    # -- Scenario 2: Large transfer (needs approval) -----------------------
    print_section("Scenario 2: Large transfer \u2014 finance_manager (needs approval)")
    print(f"\n  $25,000.00 \u2192 Vendor XYZ (within FM limit of $50,000)")
    result = governed_call(
        fm_integration, fm_ctx, fm_interceptor,
        "transfer",
        {"amount": 25_000.00, "recipient": "Vendor XYZ", "description": "Q2 consulting fees"},
    )
    if result:
        tx = agent.process(25_000.00, "Vendor XYZ", "Q2 consulting fees")
        audit_log.append({
            "agent_id": fm_ctx.agent_id,
            "event_type": "TRANSACTION",
            "tool": "transfer",
            "role": "finance_manager",
            "amount": 25_000.00,
            "recipient": "Vendor XYZ",
            "decision": tx.status,
            "timestamp": datetime.now().isoformat(),
        })
        if tx.status == "pending_approval":
            print(f"  \u23f3 PENDING APPROVAL: ${tx.amount:,.2f} to {tx.recipient}")
            print("  >> Approval request sent to: finance_manager, cfo")
        else:
            print(f"  \u2705 PROCESSED: ${tx.amount:,.2f} to {tx.recipient} \u2014 {tx.status}")

    # -- Scenario 3: Sanctioned entity (blocked) ---------------------------
    print_section("Scenario 3: Sanctioned entity \u2014 blocked by governance")
    print(f"\n  $100.00 \u2192 SanctionedCorp (on OFAC sanctions list)")
    governed_call(
        ap_integration, ap_ctx, ap_interceptor,
        "transfer",
        {"amount": 100.00, "recipient": "SanctionedCorp", "description": "Payment"},
    )
    print("  \U0001f6a8 Alert sent to compliance team")

    # -- Scenario 4: Rate limit test ---------------------------------------
    print_section("Scenario 4: Rate limit test \u2014 burst transfers")
    burst_policy = make_role_policy("accounts_payable")
    burst_integration = SOC2Integration(policy=burst_policy)
    _wire_listeners(burst_integration)
    burst_ctx = burst_integration.create_context("soc2-burst-test")
    burst_interceptor = SOC2Interceptor(burst_policy, burst_ctx, "accounts_payable")
    # Pre-fill counter to simulate prior transfers and keep output concise
    burst_interceptor._transfer_count = RATE_LIMIT_PER_SESSION - 1

    print(f"\n  Simulating burst: {RATE_LIMIT_PER_SESSION - 1} prior transfers already made")
    print(f"  Transfer #{RATE_LIMIT_PER_SESSION}: $200 \u2192 Vendor D")
    governed_call(
        burst_integration, burst_ctx, burst_interceptor,
        "transfer",
        {"amount": 200.00, "recipient": "Vendor D", "description": "Last allowed transfer"},
    )
    print(f"\n  Transfer #{RATE_LIMIT_PER_SESSION + 1}: $300 \u2192 Vendor E (should be rate-limited)")
    governed_call(
        burst_integration, burst_ctx, burst_interceptor,
        "transfer",
        {"amount": 300.00, "recipient": "Vendor E", "description": "Over rate limit"},
    )

    # -- Scenario 5: Balance query (allowed) -------------------------------
    print_section("Scenario 5: Balance query \u2014 accounts_payable (allowed)")
    result = governed_call(
        ap_integration, ap_ctx, ap_interceptor,
        "query_balance",
        {"account": "operating-account"},
    )
    if result:
        bal = agent.query_balance("operating-account")
        print(f"  Balance: ${bal['balance']:,.2f} ({bal['currency']})")

    # -- Scenario 6: Role escalation attempt (AP tries to approve) ---------
    print_section("Scenario 6: Role escalation \u2014 AP tries to approve (blocked)")
    print(f"\n  accounts_payable attempting 'approve' tool (not in allowed_tools)")
    governed_call(
        ap_integration, ap_ctx, ap_interceptor,
        "approve",
        {"tx_id": "TX-0002", "approver": "accounts_payable"},
    )
    print("  \U0001f512 Separation of duties enforced (SOC2 CC6.1)")

    # -- Audit log summary -------------------------------------------------
    print_header("Audit Trail Summary")
    for i, entry in enumerate(audit_log, 1):
        agent_id = entry.get("agent_id", "?")
        tool = entry.get("tool", "")
        reason = entry.get("reason", "")
        checkpoint = entry.get("checkpoint", "")
        call_count = entry.get("call_count", "")
        decision = entry.get("decision", "")
        amount = entry.get("amount", "")

        if reason:
            print(f"  {i:>2}. [{agent_id}] BLOCKED    tool={tool}  reason={reason}")
        elif checkpoint:
            print(f"  {i:>2}. [{agent_id}] CHECKPOINT {checkpoint}  (calls={call_count})")
        elif decision in ("approved", "pending_approval"):
            label = "APPROVED" if decision == "approved" else "PENDING"
            suffix = "" if decision == "approved" else "  (needs human approval)"
            print(f"  {i:>2}. [{agent_id}] {label:<11} ${amount:,.2f} \u2192 {entry.get('recipient', '')}{suffix}")
        else:
            print(f"  {i:>2}. [{agent_id}] ALLOWED    tool={tool}  (calls={call_count})")

    print(f"\n  Total audit entries: {len(audit_log)}")

    # -- Context summary ---------------------------------------------------
    print_header("Agent Context Summary")
    for label, ctx in [
        ("Accounts Payable", ap_ctx),
        ("Finance Manager", fm_ctx),
        ("CFO", cfo_ctx),
    ]:
        print(f"  {label}:")
        print(f"    Agent ID:    {ctx.agent_id}")
        print(f"    Tool calls:  {ctx.call_count}/{ctx.policy.max_tool_calls}")
        print(f"    Checkpoints: {ctx.checkpoints}")

    # -- Export audit trail ------------------------------------------------
    script_dir = os.path.dirname(os.path.abspath(__file__))
    json_path = os.path.join(script_dir, "soc2_audit_trail.json")
    csv_path = os.path.join(script_dir, "soc2_audit_trail.csv")

    save_audit_json(json_path)
    save_audit_csv(csv_path)

    print_header("Audit Trail Exported")
    print(f"  JSON: {json_path}")
    print(f"  CSV:  {csv_path}")
    print(f"\n  These files provide an immutable record for SOC2 compliance review.")
    print(f"  Retention policy: 7 years per SOC2 Trust Service Criteria.\n")


# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    run_demo()
