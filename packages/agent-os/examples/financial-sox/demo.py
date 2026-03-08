#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Financial SOX Compliance Demo
==============================

Demonstrates Agent OS governance for Sarbanes-Oxley (SOX) compliant
financial transaction processing.  A mock agent processes transactions
while governance enforces:

  1. Human approval   – transactions over $1,000 require approval
  2. Blocked patterns – SSN and credit-card numbers are rejected
  3. Allowed tools    – only approved financial operations are permitted
  4. Rate limiting    – max tool calls per agent session
  5. Immutable audit  – append-only JSON log with CSV/JSON export

Run:  python demo.py          (no dependencies beyond agent-os)
"""

from __future__ import annotations

import csv
import io
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


def _redact(value, visible_chars: int = 0) -> str:
    """Redact a sensitive value for safe logging."""
    import hashlib
    raw = str(value)
    if not raw:
        return "[REDACTED]"
    digest = hashlib.sha256(raw.encode()).hexdigest()[:8]
    return f"***{digest}"

# ═══════════════════════════════════════════════════════════════════════════
# 1. GOVERNANCE POLICY
#    SOX-oriented policy using only community-edition features:
#    require_human_approval, max_tool_calls, allowed_tools, blocked_patterns.
# ═══════════════════════════════════════════════════════════════════════════

APPROVAL_THRESHOLD = 1000.00  # Transactions above this require human approval

SSN_PATTERN = r"\b\d{3}-\d{2}-\d{4}\b"
CREDIT_CARD_PATTERN = r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"

sox_policy = GovernancePolicy(
    name="financial_sox",
    require_human_approval=True,
    max_tool_calls=15,
    allowed_tools=[
        "process_transaction",
        "query_balance",
        "generate_report",
        "flag_for_review",
    ],
    blocked_patterns=[
        (SSN_PATTERN, PatternType.REGEX),
        (CREDIT_CARD_PATTERN, PatternType.REGEX),
        "password",
        "secret",
    ],
    log_all_calls=True,
    checkpoint_frequency=3,
    version="1.0.0",
)

# ═══════════════════════════════════════════════════════════════════════════
# 2. IMMUTABLE AUDIT LOG
#    Append-only list written to a JSON file at the end.  Each entry is
#    timestamped and cannot be modified once appended.
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
        "timestamp",
        "agent_id",
        "event_type",
        "tool",
        "call_count",
        "reason",
        "checkpoint",
        "amount",
        "recipient",
        "decision",
    ]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for entry in audit_log:
            writer.writerow(entry)


# ═══════════════════════════════════════════════════════════════════════════
# 3. INTEGRATION SUBCLASS
# ═══════════════════════════════════════════════════════════════════════════

class SOXIntegration(BaseIntegration):
    """Thin integration used to access governance helpers."""

    def wrap(self, agent: Any) -> Any:
        return agent

    def unwrap(self, governed_agent: Any) -> Any:
        return governed_agent


# ═══════════════════════════════════════════════════════════════════════════
# 4. MOCK FINANCIAL AGENT
#    Simulates an LLM-based agent that processes financial transactions.
#    No real model calls are made.
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

    name = "FinancialAgent"

    def __init__(self) -> None:
        self._tx_counter = 0

    def process(self, amount: float, recipient: str, description: str) -> Transaction:
        """Simulate processing a transaction with SOX rules."""
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
        return {"account": account, "balance": 487_250.00, "currency": "USD"}

    def generate_report(self) -> str:
        """Return a mock compliance report summary."""
        return "SOX Compliance Report: all controls operating effectively."


# ═══════════════════════════════════════════════════════════════════════════
# 5. GOVERNED EXECUTION HELPER
# ═══════════════════════════════════════════════════════════════════════════

def governed_call(
    integration: SOXIntegration,
    ctx: ExecutionContext,
    interceptor: PolicyInterceptor,
    tool_name: str,
    arguments: Dict[str, Any],
) -> Optional[str]:
    """
    Execute a tool call through the governance layer.

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
    call_record = {
        "call_id": request.call_id,
        "tool": tool_name,
        "arguments": arguments,
        "timestamp": datetime.now().isoformat(),
    }
    ctx.tool_calls.append(call_record)

    if ctx.policy.log_all_calls:
        integration.emit(
            GovernanceEventType.POLICY_CHECK,
            {
                "agent_id": ctx.agent_id,
                "tool": tool_name,
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
# 6. DISPLAY HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def print_header(title: str) -> None:
    width = 64
    print()
    print("=" * width)
    print(f"  {title}")
    print("=" * width)


def print_section(title: str) -> None:
    print(f"\n--- {title} ---")


# ═══════════════════════════════════════════════════════════════════════════
# 7. DEMO SCENARIOS
# ═══════════════════════════════════════════════════════════════════════════

DEMO_TRANSACTIONS = [
    {"amount": 250.00, "recipient": "Office Supplies Inc", "desc": "Printer paper"},
    {"amount": 15_000.00, "recipient": "Acme Consulting LLC", "desc": "Q2 consulting fees"},
    {"amount": 800.00, "recipient": "Cloud Services Co", "desc": "Monthly hosting"},
    {"amount": 5_500.00, "recipient": "Legal Partners LLP", "desc": "Contract review"},
    {"amount": 45_000.00, "recipient": "Enterprise Software Corp", "desc": "Annual license renewal"},
]


def run_demo() -> None:
    # -- Set up integration and wire audit listeners -----------------------
    integration = SOXIntegration(policy=sox_policy)
    integration.on(GovernanceEventType.POLICY_CHECK, audit_listener)
    integration.on(GovernanceEventType.POLICY_VIOLATION, audit_listener)
    integration.on(GovernanceEventType.TOOL_CALL_BLOCKED, audit_listener)
    integration.on(GovernanceEventType.CHECKPOINT_CREATED, audit_listener)

    agent = FinancialAgent()
    ctx = integration.create_context("sox-agent")
    interceptor = PolicyInterceptor(sox_policy, ctx)

    # -- Print policy summary ----------------------------------------------
    print_header("Financial SOX Compliance Demo \u2014 Agent OS")
    print(f"\n  Policy: {sox_policy.name} (v{sox_policy.version})")
    print(f"  Human approval required: YES (transactions > ${APPROVAL_THRESHOLD:,.0f})")
    print(f"  Max tool calls: {sox_policy.max_tool_calls}")
    print(f"  Allowed tools: {', '.join(sox_policy.allowed_tools)}")
    print(f"  Blocked patterns: SSN regex, credit-card regex, password, secret")
    print(f"  Audit logging: {'ON' if sox_policy.log_all_calls else 'OFF'}")
    print(f"  Checkpoint frequency: every {sox_policy.checkpoint_frequency} calls")

    # -- Scenario 1-5: Process transactions --------------------------------
    print_section("Scenario 1-5: Financial transactions")
    for i, txn in enumerate(DEMO_TRANSACTIONS, 1):
        amount = txn["amount"]
        recipient = txn["recipient"]
        desc = txn["desc"]

        print(f"\n  [{i}] ${amount:,.2f} \u2192 {recipient} ({desc})")

        result = governed_call(
            integration, ctx, interceptor,
            "process_transaction",
            {"amount": amount, "recipient": recipient, "description": desc},
        )
        if result is None:
            continue

        tx = agent.process(amount, recipient, desc)

        # Record transaction details in audit log
        audit_log.append({
            "agent_id": ctx.agent_id,
            "event_type": "TRANSACTION",
            "tool": "process_transaction",
            "amount": amount,
            "recipient": recipient,
            "decision": tx.status,
            "timestamp": datetime.now().isoformat(),
        })

        if tx.status == "pending_approval":
            print(f"  \u23f3 PENDING APPROVAL: ${amount:,.2f} to {recipient}")
            print("  >> Approval request sent to: CFO, Controller")
        else:
            print(f"  \u2705 PROCESSED: ${amount:,.2f} to {recipient} \u2014 auto-approved")

    # -- Scenario 6: Blocked PII (SSN) ------------------------------------
    print_section("Scenario 6: Blocked PII (SSN detected)")
    ssn_message = "Pay vendor 123-45-6789 for invoice #42"
    import re
    redacted_msg = re.sub(r'\d{3}-\d{2}-\d{4}', 'XXX-XX-XXXX', ssn_message)
    print(f'  Input: "{_redact(ssn_message, 11)}"')
    governed_call(
        integration, ctx, interceptor,
        "process_transaction",
        {"note": ssn_message, "amount": 500},
    )
    print("  (Governance blocked: input contains SSN pattern)")

    # -- Scenario 7: Blocked PII (credit card) ----------------------------
    print_section("Scenario 7: Blocked PII (credit card detected)")
    cc_message = "Refund to card 4111-1111-1111-1111"
    print(f'  Input: "{cc_message}"')
    governed_call(
        integration, ctx, interceptor,
        "process_transaction",
        {"note": cc_message, "amount": 200},
    )
    print("  (Governance blocked: input contains credit-card pattern)")

    # -- Scenario 8: Unauthorized tool -------------------------------------
    print_section("Scenario 8: Unauthorized tool blocked")
    print('  Attempting to call "delete_ledger_entry" (not in allowed_tools):')
    governed_call(
        integration, ctx, interceptor,
        "delete_ledger_entry",
        {"entry_id": "LE-0042"},
    )

    # -- Scenario 9: Query balance (allowed) -------------------------------
    print_section("Scenario 9: Balance query (allowed)")
    result = governed_call(
        integration, ctx, interceptor,
        "query_balance",
        {"account": "operating-account"},
    )
    if result:
        bal = agent.query_balance("operating-account")
        print(f"  Balance: ${bal['balance']:,.2f} ({bal['currency']})")

    # -- Scenario 10: Generate report (allowed) ----------------------------
    print_section("Scenario 10: Generate compliance report")
    result = governed_call(
        integration, ctx, interceptor,
        "generate_report",
        {"type": "sox_quarterly"},
    )
    if result:
        report = agent.generate_report()
        print(f"  {report}")

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
        elif decision == "approved":
            print(f"  {i:>2}. [{agent_id}] APPROVED   ${amount:,.2f} \u2192 {entry.get('recipient', '')}")
        elif decision == "pending_approval":
            print(f"  {i:>2}. [{agent_id}] PENDING    ${amount:,.2f} \u2192 {entry.get('recipient', '')}  (needs human approval)")
        else:
            print(f"  {i:>2}. [{agent_id}] ALLOWED    tool={tool}  (calls={call_count})")

    print(f"\n  Total audit entries: {len(audit_log)}")

    # -- Context summary ---------------------------------------------------
    print_header("Agent Context Summary")
    print(f"  Agent ID:     {ctx.agent_id}")
    print(f"  Tool calls:   {ctx.call_count}/{ctx.policy.max_tool_calls}")
    print(f"  Checkpoints:  {ctx.checkpoints}")

    # -- Export audit trail ------------------------------------------------
    script_dir = os.path.dirname(os.path.abspath(__file__))
    json_path = os.path.join(script_dir, "sox_audit_trail.json")
    csv_path = os.path.join(script_dir, "sox_audit_trail.csv")

    save_audit_json(json_path)
    save_audit_csv(csv_path)

    print_header("Audit Trail Exported")
    print(f"  JSON: {json_path}")
    print(f"  CSV:  {csv_path}")
    print(f"\n  These files provide an immutable record for SOX compliance review.")
    print(f"  Retention policy: 7 years per SOX \u00a7802.\n")


# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    run_demo()
