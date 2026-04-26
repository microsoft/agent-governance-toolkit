#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Multi-Agent Trading Governance Demo
====================================
Governed agent pipeline for institutional trading operations.

Pipeline: ResearchAgent -> RiskAgent -> ComplianceAgent -> ExecutionAgent

Governance at every stage:
  - Research:   Ring 3 (read-only) — no trade execution
  - Risk:       Ring 2 (standard)  — can set limits, cannot execute
  - Compliance: Ring 1 (privileged) — can approve/reject, cannot modify orders
  - Execution:  Ring 1 (privileged, limited) — can execute approved orders only

Scenarios:
  1. Normal trade flow         — AAPL 100 shares, passes all gates
  2. Risk limit breach         — Large position triggers VaR rejection
  3. Restricted list hit       — Compliance blocks insider trading window
  4. Research tries to execute — Governance blocks (wrong privilege level)
  5. Large order escalation    — >$1M notional requires human approval
  6. Wash trading detection    — Compliance detects buy-sell-buy pattern

Run:  python demo.py   (no dependencies beyond agent-os)
"""

from __future__ import annotations

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
# 1. GOVERNANCE POLICIES — one per agent privilege level
# ═══════════════════════════════════════════════════════════════════════════

research_policy = GovernancePolicy(
    name="research_readonly",
    require_human_approval=False,
    max_tool_calls=20,
    allowed_tools=["analyze_market", "screen_stocks", "generate_signal"],
    blocked_patterns=[],
    log_all_calls=True,
    checkpoint_frequency=5,
    version="1.0.0",
)

risk_policy = GovernancePolicy(
    name="risk_standard",
    require_human_approval=False,
    max_tool_calls=15,
    allowed_tools=["calculate_var", "check_exposure", "set_position_limit"],
    blocked_patterns=[],
    log_all_calls=True,
    checkpoint_frequency=3,
    version="1.0.0",
)

compliance_policy = GovernancePolicy(
    name="compliance_privileged",
    require_human_approval=False,
    max_tool_calls=20,
    allowed_tools=[
        "check_restricted_list", "verify_trading_window",
        "approve_order", "reject_order",
    ],
    blocked_patterns=[],
    log_all_calls=True,
    checkpoint_frequency=3,
    version="1.0.0",
)

execution_policy = GovernancePolicy(
    name="execution_privileged",
    require_human_approval=False,
    max_tool_calls=10,
    allowed_tools=["execute_order", "cancel_order", "check_fill_status"],
    blocked_patterns=[],
    log_all_calls=True,
    checkpoint_frequency=2,
    version="1.0.0",
)

# ═══════════════════════════════════════════════════════════════════════════
# 2. TRADE ORDER
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class TradeOrder:
    """Represents a trade order flowing through the governance pipeline.

    Status transitions:
      NEW -> RESEARCH_APPROVED -> RISK_CHECKED -> COMPLIANCE_APPROVED -> EXECUTED
      Any stage may set status to *_REJECTED or GOVERNANCE_BLOCKED.
    """
    order_id: str
    symbol: str
    side: str                                   # BUY / SELL
    quantity: int
    price: float
    notional: float                             # quantity * price
    order_type: str                             # MARKET / LIMIT
    status: str = "NEW"
    research_signal: Dict[str, Any] = field(default_factory=dict)
    risk_assessment: Dict[str, Any] = field(default_factory=dict)
    compliance_check: Dict[str, Any] = field(default_factory=dict)
    execution_result: Dict[str, Any] = field(default_factory=dict)
    audit_trail: List[Dict[str, Any]] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════════════
# 3. IMMUTABLE AUDIT LOG
# ═══════════════════════════════════════════════════════════════════════════

audit_log: List[Dict[str, Any]] = []


def audit_listener(event: Dict[str, Any]) -> None:
    """Append every governance event to the immutable audit log."""
    audit_log.append(event)


# ═══════════════════════════════════════════════════════════════════════════
# 4. INTEGRATION SUBCLASS
# ═══════════════════════════════════════════════════════════════════════════

class TradingIntegration(BaseIntegration):
    """Thin integration used to access governance helpers."""

    def wrap(self, agent: Any) -> Any:
        return agent

    def unwrap(self, governed_agent: Any) -> Any:
        return governed_agent


# ═══════════════════════════════════════════════════════════════════════════
# 5. MOCK AGENTS — no real LLM calls
# ═══════════════════════════════════════════════════════════════════════════

class ResearchAgent:
    """Ring 3 — read-only market data and signal generation."""

    name = "ResearchAgent"
    privilege_ring = 3

    _MOCK_DATA: Dict[str, Dict[str, Any]] = {
        "AAPL": {"trend": "bullish",  "momentum":  0.72, "support": 148.50, "resistance": 155.00},
        "TSLA": {"trend": "bearish",  "momentum": -0.45, "support": 220.00, "resistance": 260.00},
        "MSFT": {"trend": "bullish",  "momentum":  0.65, "support": 380.00, "resistance": 400.00},
    }

    def analyze_market(self, symbol: str) -> Dict[str, Any]:
        return self._MOCK_DATA.get(
            symbol,
            {"trend": "neutral", "momentum": 0.0, "support": 0.0, "resistance": 0.0},
        )

    def generate_signal(self, symbol: str, analysis: Dict[str, Any]) -> Dict[str, Any]:
        momentum = analysis.get("momentum", 0)
        return {
            "symbol": symbol,
            "action": "BUY" if momentum > 0 else "SELL",
            "confidence": abs(momentum),
            "target_price": (
                analysis.get("resistance", 0) if momentum > 0
                else analysis.get("support", 0)
            ),
            "timestamp": datetime.now().isoformat(),
        }


class RiskAgent:
    """Ring 2 — position risk evaluation and limit management."""

    name = "RiskAgent"
    privilege_ring = 2

    POSITION_LIMIT = 500_000       # $500 K max single-name exposure
    CONCENTRATION_LIMIT = 0.10     # 10 % of portfolio
    VAR_THRESHOLD = 50_000         # $50 K one-day 95 % VaR limit

    def __init__(self) -> None:
        self.portfolio_value = 5_000_000
        self.positions: Dict[str, float] = {
            "AAPL": 150_000, "MSFT": 200_000, "GOOG": 100_000,
        }

    def calculate_var(self, symbol: str, quantity: int, price: float) -> Dict[str, Any]:
        notional = quantity * price
        var_estimate = notional * 0.05          # simple 5 % VaR proxy
        return {
            "symbol": symbol,
            "notional": notional,
            "var_1day_95": var_estimate,
            "var_exceeds_limit": var_estimate > self.VAR_THRESHOLD,
            "limit": self.VAR_THRESHOLD,
        }

    def check_exposure(self, symbol: str, additional_notional: float) -> Dict[str, Any]:
        current = self.positions.get(symbol, 0)
        new_total = current + additional_notional
        concentration = new_total / self.portfolio_value
        return {
            "symbol": symbol,
            "current_exposure": current,
            "proposed_exposure": new_total,
            "concentration": concentration,
            "exceeds_position_limit": new_total > self.POSITION_LIMIT,
            "exceeds_concentration": concentration > self.CONCENTRATION_LIMIT,
            "position_limit": self.POSITION_LIMIT,
            "concentration_limit": self.CONCENTRATION_LIMIT,
        }


class ComplianceAgent:
    """Ring 1 — regulatory checks, approval / rejection authority."""

    name = "ComplianceAgent"
    privilege_ring = 1

    RESTRICTED_LIST = ["INSIDER_CORP", "PENDING_MERGER_CO", "UNDER_INVESTIGATION_INC"]
    TRADING_WINDOW_CLOSED = ["INSIDER_CORP", "EARNINGS_CO"]
    HUMAN_APPROVAL_THRESHOLD = 1_000_000       # $1 M notional

    def __init__(self) -> None:
        self.recent_trades: List[Dict[str, str]] = []

    def check_restricted_list(self, symbol: str) -> Dict[str, Any]:
        restricted = symbol in self.RESTRICTED_LIST
        return {
            "symbol": symbol,
            "restricted": restricted,
            "reason": "Symbol on restricted / insider list" if restricted else "Clear",
        }

    def verify_trading_window(self, symbol: str) -> Dict[str, Any]:
        closed = symbol in self.TRADING_WINDOW_CLOSED
        return {
            "symbol": symbol,
            "window_open": not closed,
            "reason": "Trading window closed (earnings blackout)" if closed else "Open",
        }

    def check_wash_trading(self, symbol: str, side: str) -> Dict[str, Any]:
        recent = [t for t in self.recent_trades if t["symbol"] == symbol]
        if len(recent) >= 2:
            sides = [t["side"] for t in recent[-2:]] + [side]
            if sides in (["BUY", "SELL", "BUY"], ["SELL", "BUY", "SELL"]):
                return {
                    "wash_trading_detected": True,
                    "pattern": "\u2192".join(sides),
                    "symbol": symbol,
                }
        return {"wash_trading_detected": False, "symbol": symbol}

    def approve_order(self, order: TradeOrder) -> Dict[str, Any]:
        return {
            "order_id": order.order_id,
            "decision": "APPROVED",
            "compliance_officer": "auto",
            "timestamp": datetime.now().isoformat(),
        }

    def reject_order(self, order: TradeOrder, reason: str) -> Dict[str, Any]:
        return {
            "order_id": order.order_id,
            "decision": "REJECTED",
            "reason": reason,
            "compliance_officer": "auto",
            "timestamp": datetime.now().isoformat(),
        }


class ExecutionAgent:
    """Ring 1 (limited) — executes only compliance-approved orders."""

    name = "ExecutionAgent"
    privilege_ring = 1

    def execute_order(self, order: TradeOrder) -> Dict[str, Any]:
        if order.status != "COMPLIANCE_APPROVED":
            return {
                "order_id": order.order_id,
                "executed": False,
                "reason": f"Order not approved (status: {order.status})",
            }
        return {
            "order_id": order.order_id,
            "executed": True,
            "fill_price": round(order.price * 1.001, 2),
            "fill_quantity": order.quantity,
            "venue": "NYSE",
            "timestamp": datetime.now().isoformat(),
        }


# ═══════════════════════════════════════════════════════════════════════════
# 6. GOVERNED EXECUTION HELPER
# ═══════════════════════════════════════════════════════════════════════════

def governed_call(
    integration: TradingIntegration,
    ctx: ExecutionContext,
    interceptor: PolicyInterceptor,
    tool_name: str,
    arguments: Dict[str, Any],
    agent_name: str = "",
) -> Optional[str]:
    """Execute a tool call through the governance layer.

    Returns a mock result string on success, or None if blocked.
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
                "agent_name": agent_name,
                "tool": tool_name,
                "reason": result.reason,
                "event_type": "BLOCKED",
                "decision": "blocked",
                "timestamp": datetime.now().isoformat(),
            },
        )
        print(f"    \u2718 BLOCKED  | {agent_name}.{tool_name}()")
        print(f"               | reason: {result.reason}")
        return None

    ctx.call_count += 1
    ctx.tool_calls.append({
        "call_id": request.call_id,
        "tool": tool_name,
        "arguments": {k: str(v)[:80] for k, v in arguments.items()},
        "timestamp": datetime.now().isoformat(),
    })

    if ctx.policy.log_all_calls:
        integration.emit(
            GovernanceEventType.POLICY_CHECK,
            {
                "agent_id": ctx.agent_id,
                "agent_name": agent_name,
                "tool": tool_name,
                "call_count": ctx.call_count,
                "event_type": "ALLOWED",
                "decision": "allowed",
                "timestamp": datetime.now().isoformat(),
            },
        )

    if ctx.call_count % ctx.policy.checkpoint_frequency == 0:
        cp_id = f"cp-{ctx.agent_id}-{ctx.call_count}"
        ctx.checkpoints.append(cp_id)
        integration.emit(
            GovernanceEventType.CHECKPOINT_CREATED,
            {
                "agent_id": ctx.agent_id,
                "checkpoint": cp_id,
                "call_count": ctx.call_count,
                "event_type": "CHECKPOINT",
                "timestamp": datetime.now().isoformat(),
            },
        )
        print(f"    \u25cb CHECKPOINT {cp_id} (after {ctx.call_count} calls)")

    print(
        f"    \u2714 ALLOWED  | {agent_name}.{tool_name}()"
        f" (call {ctx.call_count}/{ctx.policy.max_tool_calls})"
    )
    return f"mock_result_for_{tool_name}"


# ═══════════════════════════════════════════════════════════════════════════
# 7. DISPLAY HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def print_header(title: str) -> None:
    width = 72
    print()
    print("\u2550" * width)
    print(f"  {title}")
    print("\u2550" * width)


def print_section(title: str) -> None:
    print(f"\n\u2500\u2500\u2500 {title} \u2500\u2500\u2500")


def print_order(order: TradeOrder) -> None:
    print(
        f"    Order: {order.order_id} | {order.side} {order.quantity} "
        f"{order.symbol} @ ${order.price:.2f}"
    )
    print(
        f"    Notional: ${order.notional:,.2f} | Type: {order.order_type} "
        f"| Status: {order.status}"
    )


def print_agent_header(agent_name: str, ring: int) -> None:
    ring_labels = {3: "READ-ONLY", 2: "STANDARD", 1: "PRIVILEGED"}
    print(f"\n  \u25b6 {agent_name} (Ring {ring} \u2014 {ring_labels.get(ring, '?')})")


# ═══════════════════════════════════════════════════════════════════════════
# 8. TRADING PIPELINE
# ═══════════════════════════════════════════════════════════════════════════

class TradingPipeline:
    """Orchestrates the four-stage governed trading pipeline."""

    def __init__(self) -> None:
        # --- Agents ---
        self.research = ResearchAgent()
        self.risk = RiskAgent()
        self.compliance = ComplianceAgent()
        self.execution = ExecutionAgent()

        # --- Per-agent integrations ---
        self.research_integ = TradingIntegration(policy=research_policy)
        self.risk_integ = TradingIntegration(policy=risk_policy)
        self.compliance_integ = TradingIntegration(policy=compliance_policy)
        self.execution_integ = TradingIntegration(policy=execution_policy)

        for integ in (
            self.research_integ, self.risk_integ,
            self.compliance_integ, self.execution_integ,
        ):
            for evt in (
                GovernanceEventType.POLICY_CHECK,
                GovernanceEventType.POLICY_VIOLATION,
                GovernanceEventType.TOOL_CALL_BLOCKED,
                GovernanceEventType.CHECKPOINT_CREATED,
            ):
                integ.on(evt, audit_listener)

        # --- Contexts & interceptors ---
        self.research_ctx = self.research_integ.create_context("research-agent")
        self.risk_ctx = self.risk_integ.create_context("risk-agent")
        self.compliance_ctx = self.compliance_integ.create_context("compliance-agent")
        self.execution_ctx = self.execution_integ.create_context("execution-agent")

        self.research_icpt = PolicyInterceptor(research_policy, self.research_ctx)
        self.risk_icpt = PolicyInterceptor(risk_policy, self.risk_ctx)
        self.compliance_icpt = PolicyInterceptor(compliance_policy, self.compliance_ctx)
        self.execution_icpt = PolicyInterceptor(execution_policy, self.execution_ctx)

        self._order_counter = 0

    # ------------------------------------------------------------------
    def create_order(
        self, symbol: str, side: str, quantity: int, price: float,
        order_type: str = "LIMIT",
    ) -> TradeOrder:
        self._order_counter += 1
        return TradeOrder(
            order_id=f"ORD-{self._order_counter:04d}",
            symbol=symbol,
            side=side,
            quantity=quantity,
            price=price,
            notional=quantity * price,
            order_type=order_type,
        )

    # ------------------------------------------------------------------
    # Pipeline stages
    # ------------------------------------------------------------------
    def _research_stage(self, order: TradeOrder) -> bool:
        print_agent_header("ResearchAgent", 3)

        if governed_call(
            self.research_integ, self.research_ctx, self.research_icpt,
            "analyze_market", {"symbol": order.symbol}, "ResearchAgent",
        ) is None:
            return False

        analysis = self.research.analyze_market(order.symbol)

        if governed_call(
            self.research_integ, self.research_ctx, self.research_icpt,
            "generate_signal", {"symbol": order.symbol}, "ResearchAgent",
        ) is None:
            return False

        signal = self.research.generate_signal(order.symbol, analysis)
        order.research_signal = signal
        order.status = "RESEARCH_APPROVED"
        order.audit_trail.append({
            "stage": "research", "agent": "ResearchAgent", "ring": 3,
            "decision": "APPROVED", "signal": signal,
            "timestamp": datetime.now().isoformat(),
        })
        print(
            f"    Signal: {signal['action']} {order.symbol} "
            f"(confidence: {signal['confidence']:.0%})"
        )
        return True

    def _risk_stage(self, order: TradeOrder) -> bool:
        print_agent_header("RiskAgent", 2)

        if governed_call(
            self.risk_integ, self.risk_ctx, self.risk_icpt,
            "calculate_var",
            {"symbol": order.symbol, "quantity": order.quantity, "price": order.price},
            "RiskAgent",
        ) is None:
            return False

        var_result = self.risk.calculate_var(order.symbol, order.quantity, order.price)
        print(
            f"    VaR (1d 95%): ${var_result['var_1day_95']:,.2f} "
            f"(limit: ${var_result['limit']:,.2f})"
        )

        if governed_call(
            self.risk_integ, self.risk_ctx, self.risk_icpt,
            "check_exposure",
            {"symbol": order.symbol, "notional": order.notional},
            "RiskAgent",
        ) is None:
            return False

        exposure = self.risk.check_exposure(order.symbol, order.notional)
        print(
            f"    Exposure: ${exposure['proposed_exposure']:,.2f} "
            f"(concentration: {exposure['concentration']:.1%})"
        )

        if var_result["var_exceeds_limit"]:
            order.status = "RISK_REJECTED"
            order.risk_assessment = {
                "decision": "REJECTED", "reason": "VaR exceeds limit", **var_result,
            }
            order.audit_trail.append({
                "stage": "risk", "agent": "RiskAgent", "ring": 2,
                "decision": "REJECTED", "reason": "VaR exceeds limit",
                "timestamp": datetime.now().isoformat(),
            })
            print(
                f"    \u26a0 RISK REJECTED: VaR ${var_result['var_1day_95']:,.2f} "
                f"exceeds ${var_result['limit']:,.2f}"
            )
            return False

        if exposure["exceeds_position_limit"]:
            order.status = "RISK_REJECTED"
            order.risk_assessment = {
                "decision": "REJECTED", "reason": "Position limit exceeded",
                **exposure,
            }
            order.audit_trail.append({
                "stage": "risk", "agent": "RiskAgent", "ring": 2,
                "decision": "REJECTED", "reason": "Position limit exceeded",
                "timestamp": datetime.now().isoformat(),
            })
            print(
                f"    \u26a0 RISK REJECTED: exposure ${exposure['proposed_exposure']:,.2f} "
                f"exceeds ${exposure['position_limit']:,.2f}"
            )
            return False

        order.status = "RISK_CHECKED"
        order.risk_assessment = {"decision": "PASSED", **var_result, **exposure}
        order.audit_trail.append({
            "stage": "risk", "agent": "RiskAgent", "ring": 2,
            "decision": "PASSED", "timestamp": datetime.now().isoformat(),
        })
        print("    \u2714 Risk checks passed")
        return True

    def _compliance_stage(self, order: TradeOrder) -> bool:
        print_agent_header("ComplianceAgent", 1)

        # --- Restricted list ---
        if governed_call(
            self.compliance_integ, self.compliance_ctx, self.compliance_icpt,
            "check_restricted_list", {"symbol": order.symbol}, "ComplianceAgent",
        ) is None:
            return False

        restricted = self.compliance.check_restricted_list(order.symbol)
        if restricted["restricted"]:
            rej = self.compliance.reject_order(order, restricted["reason"])
            order.status = "COMPLIANCE_REJECTED"
            order.compliance_check = rej
            order.audit_trail.append({
                "stage": "compliance", "agent": "ComplianceAgent", "ring": 1,
                "decision": "REJECTED", "reason": restricted["reason"],
                "timestamp": datetime.now().isoformat(),
            })
            print(f"    \u26a0 COMPLIANCE REJECTED: {restricted['reason']}")
            return False

        # --- Trading window ---
        if governed_call(
            self.compliance_integ, self.compliance_ctx, self.compliance_icpt,
            "verify_trading_window", {"symbol": order.symbol}, "ComplianceAgent",
        ) is None:
            return False

        window = self.compliance.verify_trading_window(order.symbol)
        if not window["window_open"]:
            rej = self.compliance.reject_order(order, window["reason"])
            order.status = "COMPLIANCE_REJECTED"
            order.compliance_check = rej
            order.audit_trail.append({
                "stage": "compliance", "agent": "ComplianceAgent", "ring": 1,
                "decision": "REJECTED", "reason": window["reason"],
                "timestamp": datetime.now().isoformat(),
            })
            print(f"    \u26a0 COMPLIANCE REJECTED: {window['reason']}")
            return False

        # --- Wash trading ---
        wash = self.compliance.check_wash_trading(order.symbol, order.side)
        if wash["wash_trading_detected"]:
            rej = self.compliance.reject_order(
                order, f"Wash trading detected: {wash['pattern']}",
            )
            order.status = "COMPLIANCE_REJECTED"
            order.compliance_check = rej
            order.audit_trail.append({
                "stage": "compliance", "agent": "ComplianceAgent", "ring": 1,
                "decision": "REJECTED",
                "reason": f"Wash trading: {wash['pattern']}",
                "timestamp": datetime.now().isoformat(),
            })
            print(
                f"    \u26a0 COMPLIANCE REJECTED: Wash trading detected "
                f"({wash['pattern']})"
            )
            return False

        # --- Human escalation for large notional ---
        if order.notional > ComplianceAgent.HUMAN_APPROVAL_THRESHOLD:
            order.audit_trail.append({
                "stage": "compliance", "agent": "ComplianceAgent", "ring": 1,
                "decision": "ESCALATED",
                "reason": f"Notional ${order.notional:,.2f} > $1M threshold",
                "timestamp": datetime.now().isoformat(),
            })
            print(
                f"    \u23f3 ESCALATED: Notional ${order.notional:,.2f} "
                f"exceeds $1M human-approval threshold"
            )
            print("    >> Escalation sent to: Chief Compliance Officer")
            print("    >> [SIMULATED] Human approval GRANTED")

        # --- Approve ---
        if governed_call(
            self.compliance_integ, self.compliance_ctx, self.compliance_icpt,
            "approve_order", {"order_id": order.order_id}, "ComplianceAgent",
        ) is None:
            return False

        approval = self.compliance.approve_order(order)
        order.status = "COMPLIANCE_APPROVED"
        order.compliance_check = approval
        order.audit_trail.append({
            "stage": "compliance", "agent": "ComplianceAgent", "ring": 1,
            "decision": "APPROVED", "timestamp": datetime.now().isoformat(),
        })
        self.compliance.recent_trades.append({
            "symbol": order.symbol, "side": order.side,
        })
        print("    \u2714 Compliance approved")
        return True

    def _execution_stage(self, order: TradeOrder) -> bool:
        print_agent_header("ExecutionAgent", 1)

        if order.status != "COMPLIANCE_APPROVED":
            print(
                f"    \u2718 BLOCKED: Order status is '{order.status}', "
                f"not COMPLIANCE_APPROVED"
            )
            order.audit_trail.append({
                "stage": "execution", "agent": "ExecutionAgent", "ring": 1,
                "decision": "BLOCKED", "reason": f"Status: {order.status}",
                "timestamp": datetime.now().isoformat(),
            })
            return False

        if governed_call(
            self.execution_integ, self.execution_ctx, self.execution_icpt,
            "execute_order",
            {"order_id": order.order_id, "symbol": order.symbol},
            "ExecutionAgent",
        ) is None:
            return False

        execution = self.execution.execute_order(order)
        order.execution_result = execution

        if execution["executed"]:
            order.status = "EXECUTED"
            order.audit_trail.append({
                "stage": "execution", "agent": "ExecutionAgent", "ring": 1,
                "decision": "EXECUTED",
                "fill_price": execution["fill_price"],
                "venue": execution["venue"],
                "timestamp": datetime.now().isoformat(),
            })
            print(
                f"    \u2714 EXECUTED: {order.quantity} {order.symbol} "
                f"@ ${execution['fill_price']:.2f} on {execution['venue']}"
            )
        else:
            order.status = "EXECUTION_FAILED"
            order.audit_trail.append({
                "stage": "execution", "agent": "ExecutionAgent", "ring": 1,
                "decision": "FAILED", "reason": execution["reason"],
                "timestamp": datetime.now().isoformat(),
            })
            print(f"    \u2718 EXECUTION FAILED: {execution['reason']}")
            return False

        return True

    # ------------------------------------------------------------------
    def run_pipeline(self, order: TradeOrder) -> TradeOrder:
        """Send an order through the full governance pipeline."""
        print_order(order)
        if not self._research_stage(order):
            return order
        if not self._risk_stage(order):
            return order
        if not self._compliance_stage(order):
            return order
        self._execution_stage(order)
        return order


# ═══════════════════════════════════════════════════════════════════════════
# 9. DEMO SCENARIOS
# ═══════════════════════════════════════════════════════════════════════════

def run_demo() -> None:
    pipeline = TradingPipeline()

    # -- Policy summary ---------------------------------------------------
    print_header("Multi-Agent Trading Governance Demo \u2014 Agent OS")
    print("\n  Pipeline: ResearchAgent \u2192 RiskAgent \u2192 ComplianceAgent \u2192 ExecutionAgent")
    print()
    print("  Agent Privilege Matrix:")
    print("  \u250c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u252c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u252c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2510")
    print("  \u2502 Agent            \u2502 Ring   \u2502 Allowed Tools                       \u2502")
    print("  \u251c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u253c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u253c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2524")
    print("  \u2502 ResearchAgent    \u2502 Ring 3 \u2502 analyze_market, screen_stocks, ...  \u2502")
    print("  \u2502 RiskAgent        \u2502 Ring 2 \u2502 calculate_var, check_exposure, ...  \u2502")
    print("  \u2502 ComplianceAgent  \u2502 Ring 1 \u2502 check_restricted_list, approve, ... \u2502")
    print("  \u2502 ExecutionAgent   \u2502 Ring 1 \u2502 execute_order, cancel_order, ...    \u2502")
    print("  \u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2534\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2534\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518")

    # -- Scenario 1: Normal trade -----------------------------------------
    print_section("Scenario 1: Normal Trade Flow (AAPL 100 shares)")
    order1 = pipeline.create_order("AAPL", "BUY", 100, 150.00)
    pipeline.run_pipeline(order1)

    # -- Scenario 2: Risk limit breach ------------------------------------
    print_section("Scenario 2: Risk Limit Breach (large position)")
    order2 = pipeline.create_order("TSLA", "BUY", 5000, 250.00)  # $1.25 M notional
    pipeline.run_pipeline(order2)

    # -- Scenario 3: Restricted list hit ----------------------------------
    print_section("Scenario 3: Restricted List Hit (insider trading window)")
    order3 = pipeline.create_order("INSIDER_CORP", "BUY", 500, 50.00)
    pipeline.run_pipeline(order3)

    # -- Scenario 4: Research privilege violation -------------------------
    print_section("Scenario 4: Research Agent Tries to Execute (privilege violation)")
    order4 = pipeline.create_order("MSFT", "BUY", 200, 390.00)
    print_order(order4)
    print_agent_header("ResearchAgent", 3)
    print("    Attempting execute_order (not in ResearchAgent's allowed tools):")
    governed_call(
        pipeline.research_integ, pipeline.research_ctx, pipeline.research_icpt,
        "execute_order", {"order_id": order4.order_id}, "ResearchAgent",
    )
    order4.status = "GOVERNANCE_BLOCKED"
    order4.audit_trail.append({
        "stage": "research", "agent": "ResearchAgent", "ring": 3,
        "decision": "BLOCKED", "reason": "execute_order not in allowed_tools",
        "timestamp": datetime.now().isoformat(),
    })

    # -- Scenario 5: Large order escalation -------------------------------
    # Use GOOG — current position $100K, adding $1.05M stays under VaR
    # because VaR = 5% of notional = $52.5K > $50K — need to tweak.
    # Raise VaR threshold temporarily so risk passes but compliance escalates.
    original_var = RiskAgent.VAR_THRESHOLD
    RiskAgent.VAR_THRESHOLD = 100_000
    pipeline.risk.VAR_THRESHOLD = 100_000
    print_section("Scenario 5: Large Order Escalation (>$1M notional)")
    original_pos = RiskAgent.POSITION_LIMIT
    RiskAgent.POSITION_LIMIT = 2_000_000
    pipeline.risk.POSITION_LIMIT = 2_000_000
    order5 = pipeline.create_order("GOOG", "BUY", 7000, 175.00)  # $1.225 M
    pipeline.run_pipeline(order5)
    RiskAgent.VAR_THRESHOLD = original_var
    pipeline.risk.VAR_THRESHOLD = original_var
    RiskAgent.POSITION_LIMIT = original_pos
    pipeline.risk.POSITION_LIMIT = original_pos

    # -- Scenario 6: Wash trading detection -------------------------------
    print_section("Scenario 6: Wash Trading Detection (BUY\u2192SELL\u2192BUY)")
    # Scenario 1 already recorded AAPL BUY; inject AAPL SELL for pattern
    pipeline.compliance.recent_trades.append({"symbol": "AAPL", "side": "SELL"})
    order6 = pipeline.create_order("AAPL", "BUY", 100, 151.00)
    pipeline.run_pipeline(order6)

    # -- Complete audit trail ---------------------------------------------
    all_orders = [order1, order2, order3, order4, order5, order6]

    print_header("Complete Audit Trail")
    for order in all_orders:
        print(
            f"\n  {order.order_id} | {order.side} {order.quantity} {order.symbol} "
            f"@ ${order.price:.2f} | Status: {order.status}"
        )
        for entry in order.audit_trail:
            decision = entry.get("decision", "?")
            stage = entry.get("stage", "?")
            agent = entry.get("agent", "?")
            reason = entry.get("reason", "")
            suffix = f" \u2014 {reason}" if reason else ""
            print(f"    [{stage:>12}] {agent:>18} \u2192 {decision}{suffix}")

    # -- Governance statistics --------------------------------------------
    print_header("Governance Statistics")
    contexts = [
        ("ResearchAgent",   pipeline.research_ctx),
        ("RiskAgent",       pipeline.risk_ctx),
        ("ComplianceAgent", pipeline.compliance_ctx),
        ("ExecutionAgent",  pipeline.execution_ctx),
    ]
    for name, ctx in contexts:
        print(
            f"  {name:>18}: {ctx.call_count:>2}/{ctx.policy.max_tool_calls} calls "
            f"| Checkpoints: {len(ctx.checkpoints)}"
        )

    blocked = sum(1 for e in audit_log if e.get("decision") == "blocked")
    allowed = sum(1 for e in audit_log if e.get("decision") == "allowed")
    print(f"\n  Total governance events: {len(audit_log)}")
    print(f"  Allowed: {allowed} | Blocked: {blocked}")

    # -- Export audit JSON ------------------------------------------------
    script_dir = os.path.dirname(os.path.abspath(__file__))
    json_path = os.path.join(script_dir, "trading_audit_trail.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(audit_log, fh, indent=2)

    print_header("Audit Trail Exported")
    print(f"  JSON: {json_path}")
    print()
    print("  Regulatory compliance mapping:")
    print("    MiFID II Art. 17   \u2014 Algorithmic trading governance")
    print("    Reg NMS Rule 15c3-5 \u2014 Market access risk controls")
    print("    MAR Art. 12        \u2014 Market manipulation (wash trading)")
    print("    SOX \u00a7302/404       \u2014 Internal controls and audit trail")
    print()


# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    run_demo()
