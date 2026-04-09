# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Chapter 5: Approval Workflows — Human-in-the-Loop Escalation

Shows how to add a third decision tier (escalate) between allow and deny.
Sensitive actions like transferring money pause the agent and wait for a
human to approve or reject — or time out with a safe default.

Run from the repo root:
    pip install agent-os-kernel[full]
    python docs/tutorials/policy-as-code/examples/05_approval_workflows.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow running from the repo root without installing the packages.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent.parent
sys.path.insert(0, str(_REPO_ROOT / "packages" / "agent-os" / "src"))

from agent_os.policies import PolicyEvaluator
from agent_os.policies.schema import PolicyDocument
from agent_os.integrations.escalation import (
    DefaultTimeoutAction,
    EscalationHandler,
    InMemoryApprovalQueue,
)

import logging

# Silence library-level log lines so the tutorial output stays clean.
logging.getLogger("agent_os.integrations.escalation").setLevel(logging.CRITICAL)

EXAMPLES_DIR = Path(__file__).parent

ESCALATION_KEYWORD = "requires human approval"


def classify(decision):
    """Classify a policy decision into one of three tiers.

    Returns (tier, icon, short_reason) where tier is one of:
    - "allow"    — action is permitted
    - "deny"     — action is blocked outright
    - "escalate" — action needs a human to decide
    """
    if decision.allowed:
        return ("allow", "\u2705 allow   ", decision.reason)
    if decision.reason and ESCALATION_KEYWORD in decision.reason.lower():
        return ("escalate", "\u23f3 escalate", decision.reason)
    return ("deny", "\U0001f6ab deny    ", decision.reason)


# ── Part 1: The three-outcome model ──────────────────────────────────

print("=" * 60)
print("  Chapter 5: Approval Workflows")
print("=" * 60)

print("\n--- Part 1: The three-outcome model ---\n")

policy = PolicyDocument.from_yaml(EXAMPLES_DIR / "05_approval_policy.yaml")
evaluator = PolicyEvaluator(policies=[policy])

tools = [
    "search_documents",
    "write_file",
    "delete_database",
    "transfer_funds",
    "send_email",
]

print(f"  {'Tool':<22s} {'Decision':<14s} Reason")
print(f"  {'-' * 55}")
for tool in tools:
    decision = evaluator.evaluate({"tool_name": tool})
    tier, icon, reason = classify(decision)
    print(f"  {tool:<22s} {icon}  {reason}")

print()
print("  For the first time, the system has three outcomes.")
print("  transfer_funds and send_email are not automatically")
print("  allowed or denied \u2014 they are paused until a human reviews.")

# ── Part 2: Creating an escalation request ───────────────────────────

print("\n--- Part 2: Creating an escalation request ---\n")

queue = InMemoryApprovalQueue()
handler = EscalationHandler(backend=queue, timeout_seconds=300)

request = handler.escalate(
    agent_id="finance-agent",
    action="transfer_funds",
    reason="Agent wants to transfer $5,000 to vendor account",
)

short_id = request.request_id[:8] + "..."
print(f"  Request ID:  {short_id}")
print(f"  Agent:       {request.agent_id}")
print(f"  Action:      {request.action}")
print(f"  Reason:      {request.reason}")
print(f"  Status:      \u23f3 {request.decision.value}")
print()
print(f"  Pending requests in queue: {len(queue.list_pending())}")
print()
print("  The agent is now suspended. A ticket exists in the")
print("  approval queue. Someone needs to review it.")

# ── Part 3: Human approves ───────────────────────────────────────────

print("\n--- Part 3: Human approves ---\n")

queue.approve(request.request_id, approver="manager@corp.com")
final = handler.resolve(request.request_id)

print(f"  manager@corp.com approved request {short_id}")
print(f"  Final decision: \u2705 {final.value}")
print()
print("  The manager approved the transfer. The agent can proceed.")

# ── Part 4: Human denies ─────────────────────────────────────────────

print("\n--- Part 4: Human denies ---\n")

request2 = handler.escalate(
    agent_id="support-agent",
    action="send_email",
    reason="Agent wants to email 10,000 customers a promotional offer",
)
short_id2 = request2.request_id[:8] + "..."

queue.deny(request2.request_id, approver="compliance@corp.com")
final2 = handler.resolve(request2.request_id)

print(f"  compliance@corp.com denied request {short_id2}")
print(f"  Final decision: \U0001f6ab {final2.value}")
print()
print("  Compliance reviewed the request and said no.")
print("  The agent must not send the email.")

# ── Part 5: Timeout — nobody responds ────────────────────────────────

print("\n--- Part 5: Timeout \u2014 nobody responds ---\n")

timeout_queue = InMemoryApprovalQueue()
timeout_handler = EscalationHandler(
    backend=timeout_queue,
    timeout_seconds=0,
    default_action=DefaultTimeoutAction.DENY,
)

request3 = timeout_handler.escalate(
    agent_id="finance-agent",
    action="transfer_funds",
    reason="Agent wants to transfer $500 to supplier",
)
short_id3 = request3.request_id[:8] + "..."

print(f"  Request {short_id3} is waiting for approval...")

# Nobody approves or denies — resolve will hit the timeout.
final3 = timeout_handler.resolve(request3.request_id)
print(f"  Timeout after 0s with no response.")
print(f"  Final decision: \U0001f6ab {final3.value} (safe default)")
print()
print("  When nobody responds, the system fails safe.")
print("  DefaultTimeoutAction.DENY ensures unanswered")
print("  requests do not become silent approvals.")
print()
print("  In production, timeouts are typically 300 seconds")
print("  (5 minutes) or more \u2014 enough time for a human to")
print("  review, but not so long that the agent waits forever.")

print("\n" + "=" * 60)
print("  The policy system now has three tiers: allow, deny,")
print("  and escalate. Sensitive actions wait for a human")
print("  before the agent proceeds \u2014 or time out safely.")
print("=" * 60)
