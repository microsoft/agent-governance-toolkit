#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Contoso Support — Customer Service Governance Demo

Demonstrates Agent Governance Toolkit (AGT) integration with
Microsoft Agent Framework (MAF) middleware for customer service.

Four governance layers are exercised end-to-end:
  1. Policy Enforcement   — YAML rules intercept support requests
  2. Capability Sandboxing — tool allow/deny lists for support tools
  3. Rogue Agent Detection — refund-farming anomaly detection
  4. Audit Trail           — Merkle-chained tamper-proof logging

Usage:
  python main.py                          # Simulated LLM (no key needed)
  GITHUB_TOKEN=ghp_... python main.py     # GitHub Models
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import statistics
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Ensure UTF-8 output on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    sys.stderr.reconfigure(encoding="utf-8")  # type: ignore[union-attr]


# ═══════════════════════════════════════════════════════════════════════════
# ANSI colour helpers
# ═══════════════════════════════════════════════════════════════════════════


class C:
    """ANSI escape helpers — degrades gracefully on dumb terminals."""

    _enabled = sys.stdout.isatty() or os.environ.get("FORCE_COLOR")

    RESET = "\033[0m" if _enabled else ""
    BOLD = "\033[1m" if _enabled else ""
    DIM = "\033[2m" if _enabled else ""

    RED = "\033[91m" if _enabled else ""
    GREEN = "\033[92m" if _enabled else ""
    YELLOW = "\033[93m" if _enabled else ""
    BLUE = "\033[94m" if _enabled else ""
    MAGENTA = "\033[95m" if _enabled else ""
    CYAN = "\033[96m" if _enabled else ""
    WHITE = "\033[97m" if _enabled else ""

    BOX_TL = "╔"
    BOX_TR = "╗"
    BOX_BL = "╚"
    BOX_BR = "╝"
    BOX_H = "═"
    BOX_V = "║"
    DASH = "━"


# ═══════════════════════════════════════════════════════════════════════════
# Display helpers
# ═══════════════════════════════════════════════════════════════════════════


def print_header() -> None:
    """Print the main demo banner."""
    w = 64
    print()
    print(f"{C.CYAN}{C.BOLD}{C.BOX_TL}{C.BOX_H * w}{C.BOX_TR}{C.RESET}")
    print(
        f"{C.CYAN}{C.BOLD}{C.BOX_V}  {C.WHITE}🎧 Contoso Support — Customer Service Governance Demo"
        f"{' ' * 6}{C.CYAN}{C.BOX_V}{C.RESET}"
    )
    print(
        f"{C.CYAN}{C.BOLD}{C.BOX_V}  {C.DIM}{C.WHITE}"
        f"Agent Governance Toolkit · MAF Middleware · Merkle Audit"
        f"{' ' * 4}{C.CYAN}{C.BOLD}{C.BOX_V}{C.RESET}"
    )
    print(f"{C.CYAN}{C.BOLD}{C.BOX_BL}{C.BOX_H * w}{C.BOX_BR}{C.RESET}")
    print()


def print_section(title: str) -> None:
    """Print a section header."""
    print(
        f"\n{C.YELLOW}{C.BOLD}{C.DASH * 3} {title} "
        f"{C.DASH * max(1, 60 - len(title))}{C.RESET}\n"
    )


def print_result(icon: str, color: str, label: str, detail: str) -> None:
    """Print a formatted result line."""
    print(f"  {color}{icon} {label}:{C.RESET} {detail}")


def print_box(title: str, lines: list[str]) -> None:
    """Print a bordered info box."""
    w = max(len(title) + 4, max((len(line) for line in lines), default=40) + 4)
    w = min(w, 66)
    print(f"  {C.DIM}┌{'─' * w}┐{C.RESET}")
    print(f"  {C.DIM}│{C.RESET} {C.BOLD}{title}{' ' * (w - len(title) - 2)}{C.DIM}│{C.RESET}")
    print(f"  {C.DIM}├{'─' * w}┤{C.RESET}")
    for line in lines:
        padded = line[: w - 2] + " " * max(0, w - 2 - len(line))
        print(f"  {C.DIM}│{C.RESET} {padded}{C.DIM}│{C.RESET}")
    print(f"  {C.DIM}└{'─' * w}┘{C.RESET}")


# ═══════════════════════════════════════════════════════════════════════════
# LLM Client — auto-detection hierarchy
# ═══════════════════════════════════════════════════════════════════════════


def create_llm_client() -> tuple[Any, str, str]:
    """Auto-detect LLM backend: GitHub Models → Azure OpenAI → Simulated.

    Returns:
        (client, model_name, backend_label)
    """
    github_token = os.environ.get("GITHUB_TOKEN")
    if github_token:
        try:
            import openai

            client = openai.OpenAI(
                base_url="https://models.inference.ai.azure.com",
                api_key=github_token,
            )
            return client, "gpt-4o-mini", "GitHub Models (gpt-4o-mini)"
        except ImportError:
            pass

    azure_endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT")
    azure_key = os.environ.get("AZURE_OPENAI_API_KEY")
    if azure_endpoint and azure_key:
        try:
            import openai

            client = openai.AzureOpenAI(
                azure_endpoint=azure_endpoint,
                api_key=azure_key,
                api_version="2024-02-15-preview",
            )
            model = os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-4o-mini")
            return client, model, f"Azure OpenAI ({model})"
        except ImportError:
            pass

    return None, "", "Simulated (no API key — fully offline)"


def call_llm(client: Any, model: str, prompt: str, system: str = "") -> str:
    """Call the LLM or return a simulated response."""
    if client is None:
        return simulated_llm(prompt)

    try:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        resp = client.chat.completions.create(
            model=model, messages=messages, max_tokens=200
        )
        return resp.choices[0].message.content or simulated_llm(prompt)
    except Exception as exc:
        print(f"  {C.YELLOW}⚠ LLM error ({type(exc).__name__}), using simulation{C.RESET}")
        return simulated_llm(prompt)


def simulated_llm(prompt: str) -> str:
    """Return realistic mock responses for customer support queries."""
    p = prompt.lower()
    if "refund" in p and "$150" in prompt:
        return (
            "I'll process the $150 refund for order #789 right away. "
            "The refund will be credited to your original payment method "
            "within 3-5 business days."
        )
    if "refund" in p and ("$2,000" in prompt or "$2000" in prompt):
        return (
            "I understand you're requesting a $2,000 refund. This amount "
            "exceeds our standard limit and requires manager approval."
        )
    if "order" in p and "status" in p:
        return (
            "Order #789 was placed on 2024-01-15. Current status: Delivered "
            "on 2024-01-18 via Express Shipping."
        )
    if "credit card" in p or "card number" in p or "cvv" in p:
        return "I can help verify your identity through our secure portal instead."
    if "escalat" in p or "manager" in p:
        return (
            "I'll escalate this to a manager right away. A supervisor will "
            "contact you within 2 hours."
        )
    if "lookup" in p or "order" in p:
        return (
            "I found order #789: Wireless Headphones ($149.99), ordered "
            "2024-01-15, delivered 2024-01-18."
        )
    return "Thank you for contacting Contoso Support. How can I help you today?"


# ═══════════════════════════════════════════════════════════════════════════
# Policy Evaluator (inline)
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class PolicyDecision:
    """Result of policy evaluation."""

    allowed: bool
    rule_name: str
    reason: str


@dataclass
class PolicyRule:
    """A single policy rule."""

    name: str
    field: str
    operator: str
    value: str
    action: str
    priority: int
    message: str


@dataclass
class PolicyEngine:
    """Inline YAML policy evaluator."""

    rules: list[PolicyRule] = field(default_factory=list)
    default_action: str = "allow"

    @classmethod
    def from_yaml(cls, path: str | Path) -> "PolicyEngine":
        """Load policies from a YAML file."""
        import yaml

        with open(path) as f:
            data = yaml.safe_load(f)

        engine = cls(default_action=data.get("defaults", {}).get("action", "allow"))
        for rule in data.get("rules", []):
            cond = rule["condition"]
            engine.rules.append(
                PolicyRule(
                    name=rule["name"],
                    field=cond["field"],
                    operator=cond["operator"],
                    value=cond["value"],
                    action=rule["action"],
                    priority=rule.get("priority", 50),
                    message=rule.get("message", ""),
                )
            )
        # Sort by priority descending (highest priority first)
        engine.rules.sort(key=lambda r: r.priority, reverse=True)
        return engine

    def evaluate(self, message: str) -> PolicyDecision:
        """Evaluate a message against all rules."""
        msg_lower = message.lower()

        for rule in self.rules:
            matched = False
            if rule.operator == "contains":
                matched = rule.value.lower() in msg_lower
            elif rule.operator == "contains_any":
                keywords = [kw.strip().lower() for kw in rule.value.split(",")]
                matched = any(kw in msg_lower for kw in keywords)
            elif rule.operator == "regex":
                matched = bool(re.search(rule.value, message, re.IGNORECASE))
            elif rule.operator == "gte":
                try:
                    matched = float(message) >= float(rule.value)
                except (ValueError, TypeError):
                    matched = False

            if matched:
                return PolicyDecision(
                    allowed=(rule.action == "allow"),
                    rule_name=rule.name,
                    reason=rule.message,
                )

        return PolicyDecision(
            allowed=(self.default_action == "allow"),
            rule_name="default",
            reason="Default policy applied",
        )


# ═══════════════════════════════════════════════════════════════════════════
# MAF-style Middleware (inline)
# ═══════════════════════════════════════════════════════════════════════════


class GovernancePolicyMiddleware:
    """Evaluates YAML policies and blocks denied messages."""

    def __init__(self, engine: PolicyEngine) -> None:
        self.engine = engine

    def evaluate(self, message: str) -> PolicyDecision:
        return self.engine.evaluate(message)


class CapabilityGuardMiddleware:
    """Allow/deny tool lists for agent capabilities."""

    def __init__(
        self,
        allowed_tools: list[str] | None = None,
        denied_tools: list[str] | None = None,
    ) -> None:
        self.allowed_tools = set(allowed_tools or [])
        self.denied_tools = set(denied_tools or [])

    def check_tool(self, tool_name: str) -> tuple[bool, str]:
        """Check if a tool invocation is permitted.

        Returns:
            (allowed, reason)
        """
        if tool_name in self.denied_tools:
            return False, f"Tool '{tool_name}' is in the denied list"
        if self.allowed_tools and tool_name not in self.allowed_tools:
            return False, f"Tool '{tool_name}' is not in the allowed list"
        return True, f"Tool '{tool_name}' is permitted"


@dataclass
class AnomalyScore:
    """Behavioral anomaly scores."""

    z_score: float = 0.0
    entropy: float = 1.0
    capability_deviation: float = 0.0
    is_anomalous: bool = False
    reason: str = ""


class RogueDetectionMiddleware:
    """Detects refund-farming and other behavioral anomalies."""

    def __init__(self, window_size: int = 20, z_threshold: float = 2.0) -> None:
        self.window_size = window_size
        self.z_threshold = z_threshold
        self.history: list[dict[str, Any]] = []
        self.quarantined = False

    def record_action(self, action: str, tool: str = "", amount: float = 0.0) -> AnomalyScore:
        """Record an agent action and compute anomaly scores."""
        self.history.append(
            {"action": action, "tool": tool, "amount": amount, "ts": time.time()}
        )

        if len(self.history) < 5:
            return AnomalyScore()

        # Compute Z-score on action frequency in recent window
        recent = self.history[-self.window_size :]
        tool_counts: dict[str, int] = {}
        for h in recent:
            t = h.get("tool", "unknown")
            tool_counts[t] = tool_counts.get(t, 0) + 1

        counts = list(tool_counts.values())
        if len(counts) < 2:
            return AnomalyScore()

        mean = statistics.mean(counts)
        stdev = statistics.stdev(counts) if len(counts) > 1 else 1.0
        max_count = max(counts)
        z_score = (max_count - mean) / stdev if stdev > 0 else 0.0

        # Shannon entropy — low entropy means repetitive behavior
        total = sum(counts)
        entropy = 0.0
        for c in counts:
            if c > 0:
                p = c / total
                entropy -= p * math.log2(p)

        # Capability deviation — fraction of actions using a single tool
        cap_dev = max_count / total if total > 0 else 0.0

        is_anomalous = (
            z_score > self.z_threshold
            or (cap_dev > 0.70 and len(recent) > 10)
        )

        if is_anomalous:
            self.quarantined = True

        return AnomalyScore(
            z_score=round(z_score, 2),
            entropy=round(entropy, 2),
            capability_deviation=round(cap_dev, 2),
            is_anomalous=is_anomalous,
            reason="Refund-farming pattern detected" if is_anomalous else "",
        )


# ═══════════════════════════════════════════════════════════════════════════
# Merkle-Chained Audit Trail
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class AuditEntry:
    """Single audit log entry in the Merkle chain."""

    index: int
    timestamp: str
    event_type: str
    detail: str
    prev_hash: str
    entry_hash: str = ""

    def __post_init__(self) -> None:
        if not self.entry_hash:
            self.entry_hash = self._compute_hash()

    def _compute_hash(self) -> str:
        payload = f"{self.index}|{self.timestamp}|{self.event_type}|{self.detail}|{self.prev_hash}"
        return hashlib.sha256(payload.encode()).hexdigest()


class AuditTrail:
    """Merkle-chained tamper-proof audit log."""

    def __init__(self) -> None:
        self.entries: list[AuditEntry] = []
        genesis = AuditEntry(
            index=0,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            event_type="GENESIS",
            detail="Audit chain initialized",
            prev_hash="0" * 64,
        )
        self.entries.append(genesis)

    def log(self, event_type: str, detail: str) -> AuditEntry:
        """Append an entry to the Merkle chain."""
        entry = AuditEntry(
            index=len(self.entries),
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            event_type=event_type,
            detail=detail,
            prev_hash=self.entries[-1].entry_hash,
        )
        self.entries.append(entry)
        return entry

    def verify_integrity(self) -> tuple[bool, int]:
        """Verify the entire chain. Returns (valid, entries_checked)."""
        for i in range(1, len(self.entries)):
            if self.entries[i].prev_hash != self.entries[i - 1].entry_hash:
                return False, i
            recomputed = self.entries[i]._compute_hash()
            if recomputed != self.entries[i].entry_hash:
                return False, i
        return True, len(self.entries)


# ═══════════════════════════════════════════════════════════════════════════
# Domain-Specific Tools (mock implementations)
# ═══════════════════════════════════════════════════════════════════════════


def lookup_order(order_id: str) -> dict[str, Any]:
    """Look up order details."""
    orders = {
        "ORD-789": {
            "order_id": "ORD-789",
            "item": "Wireless Headphones (Contoso Pro X)",
            "price": 149.99,
            "date": "2024-01-15",
            "status": "Delivered",
            "delivery_date": "2024-01-18",
        },
        "ORD-456": {
            "order_id": "ORD-456",
            "item": "Premium Laptop Stand Bundle",
            "price": 2199.99,
            "date": "2024-01-10",
            "status": "Delivered",
            "delivery_date": "2024-01-14",
        },
    }
    return orders.get(order_id, {"error": f"Order {order_id} not found"})


def lookup_customer(customer_id: str) -> dict[str, Any]:
    """Look up customer info."""
    customers = {
        "CUST-123": {
            "customer_id": "CUST-123",
            "name": "Alex Johnson",
            "email": "alex.j@example.com",
            "member_since": "2021-03-15",
            "tier": "Gold",
        }
    }
    return customers.get(customer_id, {"error": f"Customer {customer_id} not found"})


def process_refund(order_id: str, amount: float) -> dict[str, Any]:
    """Process a refund (conditional on amount)."""
    if amount > 500:
        return {
            "status": "BLOCKED",
            "reason": "Refund exceeds $500 limit — manager approval required",
        }
    return {
        "status": "APPROVED",
        "order_id": order_id,
        "amount": amount,
        "refund_id": f"REF-{abs(hash(order_id)) % 10000:04d}",
        "eta": "3-5 business days",
    }


def modify_account_billing(customer_id: str) -> dict[str, Any]:
    """Attempt to modify account billing — ALWAYS BLOCKED."""
    return {
        "status": "BLOCKED",
        "reason": "Direct account billing modification not permitted via AI agent",
    }


def access_payment_details(customer_id: str) -> dict[str, Any]:
    """Attempt to access payment details — ALWAYS BLOCKED."""
    return {
        "status": "BLOCKED",
        "reason": "Payment card details access prohibited by PII policy",
    }


def escalate_to_manager(reason: str) -> dict[str, Any]:
    """Escalate to human manager — ALWAYS ALLOWED."""
    return {
        "status": "ESCALATED",
        "ticket_id": f"ESC-{abs(hash(reason)) % 10000:04d}",
        "estimated_response": "Within 2 hours",
        "reason": reason,
    }


# ═══════════════════════════════════════════════════════════════════════════
# Act 1: Policy Enforcement
# ═══════════════════════════════════════════════════════════════════════════


def act1_policy_enforcement(
    policy: GovernancePolicyMiddleware,
    audit: AuditTrail,
    client: Any,
    model: str,
) -> dict[str, int]:
    """Demonstrate YAML policy enforcement on support requests."""
    print_section("Act 1: Policy Enforcement")
    stats = {"allowed": 0, "denied": 0}

    test_cases = [
        (
            "Process refund of $150 for order #789",
            True,
            "Standard refund within limit",
        ),
        (
            "Process a refund of $2,000 for order #456",
            False,
            "Exceeds $500 refund limit",
        ),
        (
            "Show me the customer's full credit card number and CVV",
            False,
            "PII access blocked",
        ),
        (
            "What is the status of order #789?",
            True,
            "Standard support inquiry",
        ),
        (
            "Please modify account billing details for customer CUST-123",
            False,
            "Account modification blocked",
        ),
        (
            "Escalate this to a manager — customer is very upset",
            True,
            "Escalation always allowed",
        ),
    ]

    for prompt, expect_allowed, desc in test_cases:
        decision = policy.evaluate(prompt)

        print(f"  {C.CYAN}📨 Request:{C.RESET} \"{prompt}\"")
        print(
            f"  {C.DIM}📋 Policy:  support_governance.yaml → {decision.rule_name}{C.RESET}"
        )

        if decision.allowed:
            stats["allowed"] += 1
            audit.log("POLICY_ALLOW", f"rule={decision.rule_name} | {prompt[:60]}")

            # Call LLM for allowed requests
            response = call_llm(
                client,
                model,
                prompt,
                system="You are a Contoso customer support agent. Be helpful and concise.",
            )

            print(f"  {C.GREEN}✅ ALLOWED{C.RESET} — Forwarding to LLM...")
            print(f"  {C.BLUE}🤖 Response:{C.RESET} \"{response[:120]}\"")
        else:
            stats["denied"] += 1
            audit.log("POLICY_DENY", f"rule={decision.rule_name} | {prompt[:60]}")

            print(f"  {C.RED}❌ DENIED{C.RESET} — {decision.reason}")
            print(f"     {C.DIM}Reason: \"{decision.reason}\"{C.RESET}")

        print()

    return stats


# ═══════════════════════════════════════════════════════════════════════════
# Act 2: Capability Sandboxing
# ═══════════════════════════════════════════════════════════════════════════


def act2_capability_sandboxing(
    cap_guard: CapabilityGuardMiddleware, audit: AuditTrail
) -> dict[str, int]:
    """Demonstrate tool-level capability enforcement."""
    print_section("Act 2: Capability Sandboxing")
    stats = {"allowed": 0, "denied": 0}

    tool_calls = [
        ("lookup_order", {"order_id": "ORD-789"}, lookup_order, ("ORD-789",)),
        ("lookup_customer", {"customer_id": "CUST-123"}, lookup_customer, ("CUST-123",)),
        ("process_refund", {"order_id": "ORD-789", "amount": 150}, process_refund, ("ORD-789", 150)),
        ("process_refund", {"order_id": "ORD-456", "amount": 2000}, process_refund, ("ORD-456", 2000)),
        ("modify_account_billing", {"customer_id": "CUST-123"}, modify_account_billing, ("CUST-123",)),
        ("access_payment_details", {"customer_id": "CUST-123"}, access_payment_details, ("CUST-123",)),
        ("escalate_to_manager", {"reason": "Customer requesting large refund"}, escalate_to_manager, ("Customer requesting large refund",)),
    ]

    for tool_name, args_dict, func, func_args in tool_calls:
        allowed, reason = cap_guard.check_tool(tool_name)
        args_str = json.dumps(args_dict)

        print(f"  {C.CYAN}🔧 Tool:{C.RESET} {tool_name}({args_str})")

        if allowed:
            result = func(*func_args)
            status = result.get("status", "OK")

            if status == "BLOCKED":
                # Tool itself rejected the request (e.g., refund > $500)
                stats["denied"] += 1
                audit.log(
                    "TOOL_BLOCKED",
                    f"tool={tool_name} | {result.get('reason', 'blocked')}",
                )
                print(
                    f"  {C.RED}❌ BLOCKED (by tool):{C.RESET} {result.get('reason', '')}"
                )
            else:
                stats["allowed"] += 1
                audit.log("TOOL_ALLOWED", f"tool={tool_name} | {args_str[:60]}")
                # Show compact result
                compact = json.dumps(result)
                if len(compact) > 100:
                    compact = compact[:97] + "..."
                print(f"  {C.GREEN}✅ ALLOWED{C.RESET} → {compact}")
        else:
            stats["denied"] += 1
            audit.log("CAPABILITY_DENY", f"tool={tool_name} | {reason}")
            print(f"  {C.RED}❌ BLOCKED (capability guard):{C.RESET} {reason}")

        print()

    return stats


# ═══════════════════════════════════════════════════════════════════════════
# Act 3: Rogue Agent Detection
# ═══════════════════════════════════════════════════════════════════════════


def act3_rogue_detection(
    rogue: RogueDetectionMiddleware, audit: AuditTrail
) -> dict[str, int]:
    """Demonstrate behavioral anomaly detection for refund farming."""
    print_section("Act 3: Rogue Agent Detection")
    stats = {"normal": 0, "anomalies": 0}

    print(f"  {C.BOLD}Phase 1: Normal support activity (establishing baseline){C.RESET}\n")

    normal_actions = [
        ("inquiry", "lookup_order", 0),
        ("inquiry", "lookup_customer", 0),
        ("inquiry", "lookup_order", 0),
        ("refund", "process_refund", 49.99),
        ("inquiry", "escalate_to_manager", 0),
    ]

    for action, tool, amount in normal_actions:
        score = rogue.record_action(action, tool, amount)
        stats["normal"] += 1
        audit.log("NORMAL_ACTION", f"tool={tool} amount=${amount:.2f}")
        z_str = f"{score.z_score:.2f}" if score.z_score else "—"
        ent_str = f"{score.entropy:.2f}" if score.entropy else "—"
        print(
            f"  {C.GREEN}●{C.RESET} {tool}({f'${amount:.2f}' if amount else '...'}) "
            f"{C.DIM}│ Z={z_str} Entropy={ent_str}{C.RESET}"
        )

    print(
        f"\n  {C.BOLD}Phase 2: Refund-farming attack "
        f"(15 rapid refund calls){C.RESET}\n"
    )

    for i in range(15):
        amount = 450 + (i % 5) * 10
        score = rogue.record_action("refund", "process_refund", amount)

        if score.is_anomalous:
            stats["anomalies"] += 1
            icon = f"{C.RED}🚨"
            status = f"{C.RED}ANOMALY{C.RESET}"
            audit.log(
                "ANOMALY_DETECTED",
                f"z={score.z_score} ent={score.entropy} dev={score.capability_deviation}",
            )
        else:
            stats["normal"] += 1
            icon = f"{C.YELLOW}▲"
            status = f"{C.YELLOW}elevated{C.RESET}"
            audit.log(
                "ELEVATED_RISK",
                f"z={score.z_score} ent={score.entropy}",
            )

        print(
            f"  {icon}{C.RESET} process_refund(${amount:.2f}) "
            f"{C.DIM}│ Z={score.z_score:5.2f}  Ent={score.entropy:.2f}  "
            f"Dev={score.capability_deviation:.2f}{C.RESET} → {status}"
        )

        if score.is_anomalous and not any(
            "QUARANTINE" in e.event_type for e in audit.entries
        ):
            audit.log("QUARANTINE", "Agent quarantined — refund-farming detected")
            print(
                f"\n  {C.RED}{C.BOLD}⚠ QUARANTINE TRIGGERED{C.RESET}\n"
                f"  {C.RED}Agent suspended — refund-farming pattern detected{C.RESET}\n"
                f"  {C.DIM}Z-score: {score.z_score:.2f} (threshold: 2.00){C.RESET}\n"
                f"  {C.DIM}Entropy: {score.entropy:.2f} (low = repetitive){C.RESET}\n"
                f"  {C.DIM}Capability deviation: {score.capability_deviation:.0%}{C.RESET}"
            )
            break

    print()
    return stats


# ═══════════════════════════════════════════════════════════════════════════
# Act 4: Audit Trail & Compliance
# ═══════════════════════════════════════════════════════════════════════════


def act4_audit_trail(audit: AuditTrail) -> None:
    """Display the Merkle-chained audit trail and verify integrity."""
    print_section("Act 4: Audit Trail & Compliance")

    # Show chain excerpt
    print(f"  {C.BOLD}Merkle Chain (last 8 entries):{C.RESET}\n")

    start = max(1, len(audit.entries) - 8)
    for entry in audit.entries[start:]:
        h = entry.entry_hash[:16]
        ph = entry.prev_hash[:16]
        evt_color = C.GREEN if "ALLOW" in entry.event_type else (
            C.RED if "DENY" in entry.event_type or "ANOMALY" in entry.event_type
            or "QUARANTINE" in entry.event_type or "BLOCK" in entry.event_type
            else C.YELLOW
        )
        detail_trunc = entry.detail[:50] + ("..." if len(entry.detail) > 50 else "")
        print(
            f"  {C.DIM}#{entry.index:03d}{C.RESET} "
            f"{evt_color}{entry.event_type:<20}{C.RESET} "
            f"{C.DIM}{h}…{C.RESET} "
            f"{C.DIM}← {ph}…{C.RESET}"
        )
        print(f"       {C.DIM}{detail_trunc}{C.RESET}")

    # Verify integrity
    print(f"\n  {C.BOLD}Chain Integrity Verification:{C.RESET}")
    valid, checked = audit.verify_integrity()
    if valid:
        print(
            f"  {C.GREEN}✅ Chain valid{C.RESET} — {checked} entries verified, "
            f"all SHA-256 hashes match"
        )
    else:
        print(f"  {C.RED}❌ Chain BROKEN at entry {checked}{C.RESET}")

    # Summary stats
    total = len(audit.entries) - 1  # Exclude genesis
    allows = sum(1 for e in audit.entries if "ALLOW" in e.event_type)
    denials = sum(
        1 for e in audit.entries
        if "DENY" in e.event_type or "BLOCK" in e.event_type
    )
    anomalies = sum(
        1 for e in audit.entries
        if "ANOMALY" in e.event_type or "QUARANTINE" in e.event_type
    )

    print(f"\n  {C.BOLD}Compliance Summary:{C.RESET}")
    print_box(
        "Session Statistics",
        [
            f"Total events:   {total}",
            f"Allowed:        {allows}",
            f"Denied/Blocked: {denials}",
            f"Anomalies:      {anomalies}",
            f"Chain entries:  {len(audit.entries)} (incl. genesis)",
            f"Chain hash:     {audit.entries[-1].entry_hash[:32]}...",
        ],
    )

    # Proof generation
    print(f"\n  {C.BOLD}Compliance Proof:{C.RESET}")
    root_hash = audit.entries[-1].entry_hash
    print(f"  {C.DIM}Root hash:{C.RESET} {root_hash}")
    print(
        f"  {C.DIM}Proof:    All {total} events are chained with SHA-256, "
        f"tamper-evident from genesis{C.RESET}"
    )
    print(
        f"  {C.DIM}Export:   Audit trail can be exported for SOC2/ISO-27001 "
        f"compliance review{C.RESET}"
    )


# ═══════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════


def main() -> None:
    """Run the full 4-act customer service governance demo."""
    print_header()

    # LLM setup
    client, model, backend = create_llm_client()
    print(f"  {C.BOLD}Using LLM:{C.RESET} {C.CYAN}{backend}{C.RESET}")
    print()

    # Load policy
    policy_path = Path(__file__).resolve().parent / "policies" / "support_governance.yaml"
    if not policy_path.exists():
        print(f"{C.RED}✗ Policy file not found: {policy_path}{C.RESET}")
        sys.exit(1)

    engine = PolicyEngine.from_yaml(policy_path)
    policy_mw = GovernancePolicyMiddleware(engine)

    # Capability guard — support agent's allowed tools
    cap_guard = CapabilityGuardMiddleware(
        allowed_tools=[
            "lookup_order",
            "lookup_customer",
            "process_refund",
            "escalate_to_manager",
        ],
        denied_tools=[
            "modify_account_billing",
            "access_payment_details",
        ],
    )

    # Rogue detector
    rogue = RogueDetectionMiddleware(window_size=20, z_threshold=2.0)

    # Audit trail
    audit = AuditTrail()

    # ── Act 1 ──
    act1_policy_enforcement(policy_mw, audit, client, model)

    # ── Act 2 ──
    act2_capability_sandboxing(cap_guard, audit)

    # ── Act 3 ──
    act3_rogue_detection(rogue, audit)

    # ── Act 4 ──
    act4_audit_trail(audit)

    # Final footer
    print(
        f"\n{C.CYAN}{C.BOLD}{C.BOX_TL}{C.BOX_H * 64}{C.BOX_TR}{C.RESET}"
    )
    print(
        f"{C.CYAN}{C.BOLD}{C.BOX_V}  {C.GREEN}Demo complete!{C.RESET}"
        f"{C.CYAN}{C.BOLD}{' ' * 49}{C.BOX_V}{C.RESET}"
    )
    print(
        f"{C.CYAN}{C.BOLD}{C.BOX_V}  {C.DIM}{C.WHITE}"
        f"All 4 governance layers demonstrated successfully"
        f"{' ' * 12}{C.CYAN}{C.BOLD}{C.BOX_V}{C.RESET}"
    )
    print(
        f"{C.CYAN}{C.BOLD}{C.BOX_BL}{C.BOX_H * 64}{C.BOX_BR}{C.RESET}\n"
    )


if __name__ == "__main__":
    main()
