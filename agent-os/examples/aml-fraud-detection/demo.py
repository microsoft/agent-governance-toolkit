#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
AML/KYC Fraud Detection Demo
=============================
Multi-agent Anti-Money Laundering system with Agent OS governance.

Architecture:
  TransactionMonitor → VelocityAnalyzer → SanctionsScreener → SARFiler

Each agent operates under governance:
  - Prompt injection protection on all inputs
  - PII redaction in logs (account numbers, SSNs)
  - Human approval for SAR filings
  - Immutable audit trail (BSA/AML §5318)
  - Rate limiting per agent

Run:  python demo.py          (no dependencies beyond agent-os)
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Force UTF-8 output on Windows to support Unicode box-drawing characters.
# ---------------------------------------------------------------------------
if sys.stdout.encoding != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if sys.stderr.encoding != "utf-8":
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# ---------------------------------------------------------------------------
# Ensure the repo root's src/ is importable when running from the example dir.
# ---------------------------------------------------------------------------
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(_REPO_ROOT, "src"))

from agent_os.integrations.base import (
    BaseIntegration,
    ExecutionContext,
    GovernanceEventType,
    GovernancePolicy,
    PatternType,
    PolicyInterceptor,
    ToolCallRequest,
    ToolCallResult,
)

# ═══════════════════════════════════════════════════════════════════════════
# 1. CONSTANTS & REFERENCE DATA
# ═══════════════════════════════════════════════════════════════════════════

CTR_THRESHOLD = 10_000.00  # Currency Transaction Report threshold
STRUCTURING_WINDOW_HOURS = 24
SAR_FILING_DEADLINE_DAYS = 30

# OFAC Specially Designated Nationals (mock subset)
OFAC_SDN_LIST = [
    {"name": "Viktor Bout", "country": "Russia", "program": "SDGT"},
    {"name": "Dawood Ibrahim", "country": "India", "program": "SDNTK"},
    {"name": "Joaquin Guzman", "country": "Mexico", "program": "SDNT"},
    {"name": "Al-Rashid Trading Co", "country": "Iran", "program": "IRAN"},
    {"name": "Petromax Holdings", "country": "Syria", "program": "SYRIA"},
]

# FATF high-risk jurisdictions
FATF_HIGH_RISK = {"Iran", "North Korea", "Myanmar", "Syria", "Yemen",
                  "Afghanistan", "Albania", "Barbados", "Burkina Faso",
                  "Cayman Islands", "Democratic Republic of Congo"}

# Politically Exposed Persons (mock)
PEP_DATABASE = {
    "Carlos Mendez": {"role": "Former Finance Minister", "country": "Panama"},
    "Li Wei": {"role": "Provincial Governor", "country": "China"},
    "Ahmed Al-Rashid": {"role": "Sovereign Wealth Fund Director", "country": "UAE"},
}

SSN_PATTERN = r"\b\d{3}-\d{2}-\d{4}\b"
ACCOUNT_PATTERN = r"\b\d{10,12}\b"


# ═══════════════════════════════════════════════════════════════════════════
# 2. GOVERNANCE POLICIES (one per agent)
# ═══════════════════════════════════════════════════════════════════════════

monitor_policy = GovernancePolicy(
    name="aml_transaction_monitor",
    require_human_approval=False,
    max_tool_calls=50,
    allowed_tools=[
        "scan_transaction", "flag_structuring", "flag_round_trip",
        "flag_dormant_activation", "score_geographic_risk",
    ],
    blocked_patterns=[
        (SSN_PATTERN, PatternType.REGEX),
        (ACCOUNT_PATTERN, PatternType.REGEX),
        "password", "secret",
    ],
    log_all_calls=True,
    checkpoint_frequency=3,
    version="1.0.0",
)

velocity_policy = GovernancePolicy(
    name="aml_velocity_analyzer",
    require_human_approval=False,
    max_tool_calls=30,
    allowed_tools=[
        "check_daily_velocity", "check_weekly_velocity",
        "compare_peer_group", "detect_activity_spike",
    ],
    blocked_patterns=[
        (SSN_PATTERN, PatternType.REGEX),
        (ACCOUNT_PATTERN, PatternType.REGEX),
    ],
    log_all_calls=True,
    checkpoint_frequency=3,
    version="1.0.0",
)

screener_policy = GovernancePolicy(
    name="aml_sanctions_screener",
    require_human_approval=False,
    max_tool_calls=30,
    allowed_tools=[
        "screen_ofac", "screen_country", "screen_pep",
        "fuzzy_name_match",
    ],
    blocked_patterns=[
        (SSN_PATTERN, PatternType.REGEX),
    ],
    log_all_calls=True,
    checkpoint_frequency=2,
    version="1.0.0",
)

# SAR filer requires human approval — uses a custom interceptor
sar_policy = GovernancePolicy(
    name="aml_sar_filer",
    require_human_approval=False,  # controlled by custom interceptor
    max_tool_calls=20,
    allowed_tools=[
        "generate_sar", "submit_sar", "check_filing_deadline",
    ],
    blocked_patterns=[
        (SSN_PATTERN, PatternType.REGEX),
    ],
    log_all_calls=True,
    checkpoint_frequency=1,
    version="1.0.0",
)


# ═══════════════════════════════════════════════════════════════════════════
# 3. CUSTOM INTERCEPTORS
# ═══════════════════════════════════════════════════════════════════════════

class SARApprovalInterceptor:
    """Requires human approval specifically for SAR submission."""

    def __init__(self, policy: GovernancePolicy, context: Optional[ExecutionContext] = None):
        self._base = PolicyInterceptor(policy, context)

    def intercept(self, request: ToolCallRequest) -> ToolCallResult:
        base_result = self._base.intercept(request)
        if not base_result.allowed:
            return base_result
        if request.tool_name == "submit_sar":
            return ToolCallResult(
                allowed=False,
                reason="SAR submission requires human approval (BSA/AML §5318(g))",
            )
        return ToolCallResult(allowed=True)


class PIIRedactionInterceptor:
    """Redacts PII from tool arguments before logging."""

    _SSN_RE = re.compile(SSN_PATTERN)
    _ACCT_RE = re.compile(ACCOUNT_PATTERN)

    def intercept(self, request: ToolCallRequest) -> ToolCallResult:
        args_str = str(request.arguments)
        if self._SSN_RE.search(args_str):
            return ToolCallResult(
                allowed=False,
                reason="PII detected: SSN pattern found in arguments",
            )
        return ToolCallResult(allowed=True)

    @classmethod
    def redact(cls, text: str) -> str:
        """Redact PII for display purposes."""
        text = cls._SSN_RE.sub("***-**-****", text)
        text = cls._ACCT_RE.sub("****" + text[-4:] if len(text) >= 4 else "****", text)
        return text


# ═══════════════════════════════════════════════════════════════════════════
# 4. IMMUTABLE AUDIT LOG
# ═══════════════════════════════════════════════════════════════════════════

audit_log: List[Dict[str, Any]] = []


def audit_listener(event: Dict[str, Any]) -> None:
    """Append every governance event to the immutable audit log."""
    audit_log.append(event)


def save_audit_json(path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(audit_log, fh, indent=2)


def save_audit_csv(path: str) -> None:
    if not audit_log:
        return
    fieldnames = [
        "timestamp", "agent_id", "event_type", "tool", "call_count",
        "reason", "checkpoint", "risk_score", "decision",
    ]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for entry in audit_log:
            writer.writerow(entry)


# ═══════════════════════════════════════════════════════════════════════════
# 5. INTEGRATION SUBCLASS
# ═══════════════════════════════════════════════════════════════════════════

class AMLIntegration(BaseIntegration):
    """Integration for AML/KYC governance."""

    def wrap(self, agent: Any) -> Any:
        return agent

    def unwrap(self, governed_agent: Any) -> Any:
        return governed_agent


# ═══════════════════════════════════════════════════════════════════════════
# 6. DATA MODELS
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class Transaction:
    tx_id: str
    amount: float
    sender: str
    receiver: str
    country: str = "US"
    description: str = ""
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class RiskAlert:
    alert_id: str
    tx_id: str
    alert_type: str
    risk_score: float  # 0.0 – 1.0
    description: str
    agent: str
    requires_sar: bool = False


@dataclass
class SARReport:
    sar_id: str
    subject: str
    alerts: List[RiskAlert] = field(default_factory=list)
    total_amount: float = 0.0
    filing_deadline: Optional[datetime] = None
    status: str = "draft"
    narrative: str = ""


# ═══════════════════════════════════════════════════════════════════════════
# 7. MOCK AGENTS
# ═══════════════════════════════════════════════════════════════════════════

class TransactionMonitor:
    """Watches transaction stream and flags anomalies."""

    name = "TransactionMonitor"

    def __init__(self) -> None:
        self._alert_counter = 0

    def _make_alert(self, tx: Transaction, alert_type: str,
                    score: float, desc: str, needs_sar: bool = False) -> RiskAlert:
        self._alert_counter += 1
        return RiskAlert(
            alert_id=f"ALT-{self._alert_counter:04d}",
            tx_id=tx.tx_id,
            alert_type=alert_type,
            risk_score=score,
            description=desc,
            agent=self.name,
            requires_sar=needs_sar,
        )

    def detect_structuring(self, transactions: List[Transaction]) -> Optional[RiskAlert]:
        """Multiple transactions just under $10K CTR threshold."""
        near_threshold = [t for t in transactions if 8_000 <= t.amount < CTR_THRESHOLD]
        if len(near_threshold) >= 2:
            total = sum(t.amount for t in near_threshold)
            return self._make_alert(
                near_threshold[0], "STRUCTURING", 0.92,
                f"Possible structuring: {len(near_threshold)} transactions totaling "
                f"${total:,.2f}, each just under ${CTR_THRESHOLD:,.0f} threshold",
                needs_sar=True,
            )
        return None

    def detect_round_trip(self, transactions: List[Transaction]) -> Optional[RiskAlert]:
        """A→B→C→A circular flow."""
        senders = [t.sender for t in transactions]
        receivers = [t.receiver for t in transactions]
        for sender in senders:
            if sender in receivers[1:]:
                return self._make_alert(
                    transactions[0], "ROUND_TRIP", 0.88,
                    f"Circular fund flow detected: funds return to originator '{sender}'",
                    needs_sar=True,
                )
        return None

    def detect_dormant_activation(self, tx: Transaction,
                                  last_activity_days: int) -> Optional[RiskAlert]:
        """Account dormant > 180 days suddenly active."""
        if last_activity_days > 180:
            return self._make_alert(
                tx, "DORMANT_ACTIVATION", 0.75,
                f"Dormant account reactivated after {last_activity_days} days "
                f"with ${tx.amount:,.2f} transaction",
            )
        return None

    def score_geographic_risk(self, tx: Transaction) -> Optional[RiskAlert]:
        """Flag transactions involving FATF high-risk jurisdictions."""
        if tx.country in FATF_HIGH_RISK:
            return self._make_alert(
                tx, "HIGH_RISK_JURISDICTION", 0.85,
                f"Transaction involves FATF high-risk jurisdiction: {tx.country}",
                needs_sar=True,
            )
        return None


class VelocityAnalyzer:
    """Checks transaction velocity patterns."""

    name = "VelocityAnalyzer"
    _alert_counter = 0

    # Mock velocity limits
    DAILY_LIMIT = 50_000
    WEEKLY_LIMIT = 200_000

    def _make_alert(self, tx: Transaction, alert_type: str,
                    score: float, desc: str) -> RiskAlert:
        self._alert_counter += 1
        return RiskAlert(
            alert_id=f"VEL-{self._alert_counter:04d}",
            tx_id=tx.tx_id,
            alert_type=alert_type,
            risk_score=score,
            description=desc,
            agent=self.name,
        )

    def check_velocity(self, tx: Transaction,
                       daily_total: float, weekly_total: float) -> Optional[RiskAlert]:
        if daily_total + tx.amount > self.DAILY_LIMIT:
            return self._make_alert(
                tx, "DAILY_VELOCITY_BREACH", 0.80,
                f"Daily velocity breach: ${daily_total + tx.amount:,.2f} "
                f"exceeds ${self.DAILY_LIMIT:,.0f} limit",
            )
        if weekly_total + tx.amount > self.WEEKLY_LIMIT:
            return self._make_alert(
                tx, "WEEKLY_VELOCITY_BREACH", 0.70,
                f"Weekly velocity breach: ${weekly_total + tx.amount:,.2f} "
                f"exceeds ${self.WEEKLY_LIMIT:,.0f} limit",
            )
        return None

    def detect_activity_spike(self, tx: Transaction,
                              avg_monthly_count: int,
                              current_month_count: int) -> Optional[RiskAlert]:
        """Flag if current month transactions exceed 3x average."""
        if avg_monthly_count > 0 and current_month_count > avg_monthly_count * 3:
            return self._make_alert(
                tx, "ACTIVITY_SPIKE", 0.78,
                f"Activity spike: {current_month_count} transactions this month "
                f"vs {avg_monthly_count} avg (>{3}x normal)",
            )
        return None


class SanctionsScreener:
    """OFAC/SDN list screening with fuzzy matching."""

    name = "SanctionsScreener"
    _alert_counter = 0

    def _make_alert(self, tx: Transaction, alert_type: str,
                    score: float, desc: str) -> RiskAlert:
        self._alert_counter += 1
        return RiskAlert(
            alert_id=f"SCR-{self._alert_counter:04d}",
            tx_id=tx.tx_id,
            alert_type=alert_type,
            risk_score=score,
            description=desc,
            agent=self.name,
            requires_sar=True,
        )

    @staticmethod
    def _levenshtein(s1: str, s2: str) -> int:
        """Simple Levenshtein distance."""
        if len(s1) < len(s2):
            return SanctionsScreener._levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row
        return prev_row[-1]

    def screen_ofac(self, name: str, tx: Transaction) -> Optional[RiskAlert]:
        """Screen name against OFAC SDN list (exact + fuzzy)."""
        name_lower = name.lower()
        for entry in OFAC_SDN_LIST:
            sdn_lower = entry["name"].lower()
            if name_lower == sdn_lower:
                return self._make_alert(
                    tx, "OFAC_EXACT_MATCH", 1.0,
                    f"OFAC SDN exact match: '{name}' — program: {entry['program']}, "
                    f"country: {entry['country']}",
                )
            distance = self._levenshtein(name_lower, sdn_lower)
            max_len = max(len(name_lower), len(sdn_lower))
            if max_len > 0 and distance / max_len < 0.25:
                return self._make_alert(
                    tx, "OFAC_FUZZY_MATCH", 0.85,
                    f"OFAC SDN fuzzy match: '{name}' ≈ '{entry['name']}' "
                    f"(distance={distance})",
                )
        return None

    def screen_country(self, country: str, tx: Transaction) -> Optional[RiskAlert]:
        if country in FATF_HIGH_RISK:
            return self._make_alert(
                tx, "FATF_HIGH_RISK_COUNTRY", 0.90,
                f"FATF high-risk jurisdiction: {country}",
            )
        return None

    def screen_pep(self, name: str, tx: Transaction) -> Optional[RiskAlert]:
        if name in PEP_DATABASE:
            pep = PEP_DATABASE[name]
            return self._make_alert(
                tx, "PEP_MATCH", 0.80,
                f"Politically Exposed Person: {name} — {pep['role']}, {pep['country']}",
            )
        return None


class SARFiler:
    """Suspicious Activity Report generator."""

    name = "SARFiler"
    _sar_counter = 0

    def generate_sar(self, subject: str, alerts: List[RiskAlert],
                     total_amount: float) -> SARReport:
        self._sar_counter += 1
        narrative_lines = [
            f"Suspicious Activity Report — {subject}",
            f"Filing Date: {datetime.now().strftime('%Y-%m-%d')}",
            f"Total Suspicious Amount: ${total_amount:,.2f}",
            "",
            "Evidence Summary:",
        ]
        for alert in alerts:
            narrative_lines.append(
                f"  • [{alert.alert_type}] (score={alert.risk_score:.2f}) "
                f"{alert.description}"
            )
        narrative_lines.extend([
            "",
            "This report is filed pursuant to 31 CFR §1020.320.",
            "CONFIDENTIAL — Tipping-off prohibition per 31 USC §5318(g)(2).",
        ])
        return SARReport(
            sar_id=f"SAR-{self._sar_counter:04d}",
            subject=subject,
            alerts=alerts,
            total_amount=total_amount,
            filing_deadline=datetime.now() + timedelta(days=SAR_FILING_DEADLINE_DAYS),
            status="pending_approval",
            narrative="\n".join(narrative_lines),
        )


# ═══════════════════════════════════════════════════════════════════════════
# 8. GOVERNED EXECUTION HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def governed_call(
    integration: AMLIntegration,
    ctx: ExecutionContext,
    interceptor: Any,
    tool_name: str,
    arguments: Dict[str, Any],
) -> Optional[str]:
    """Execute a tool call through the governance layer. Returns result or None."""
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
        print(f"    ✘ BLOCKED  │ tool={tool_name}")
        print(f"               │ reason: {result.reason}")
        return None

    ctx.call_count += 1
    ctx.tool_calls.append({
        "call_id": request.call_id,
        "tool": tool_name,
        "arguments": {k: v for k, v in arguments.items()
                      if not isinstance(v, (list, datetime))},
        "timestamp": datetime.now().isoformat(),
    })

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
        checkpoint_id = f"cp-{ctx.agent_id}-{ctx.call_count}"
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
        print(f"    ○ CHECKPOINT {checkpoint_id}")

    print(f"    ✔ ALLOWED  │ tool={tool_name} "
          f"(call {ctx.call_count}/{ctx.policy.max_tool_calls})")
    return f"mock_result_for_{tool_name}"


# ═══════════════════════════════════════════════════════════════════════════
# 9. PIPELINE RUNNER
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class PipelineResult:
    transaction: Transaction
    alerts: List[RiskAlert] = field(default_factory=list)
    sar: Optional[SARReport] = None
    final_decision: str = "CLEAR"


def run_pipeline(
    tx: Transaction,
    integrations: Dict[str, AMLIntegration],
    contexts: Dict[str, ExecutionContext],
    interceptors: Dict[str, Any],
    agents: Dict[str, Any],
    *,
    last_activity_days: int = 10,
    daily_total: float = 0.0,
    weekly_total: float = 0.0,
    avg_monthly_count: int = 20,
    current_month_count: int = 22,
    extra_txs: Optional[List[Transaction]] = None,
) -> PipelineResult:
    """Run a transaction through the full AML pipeline."""
    result = PipelineResult(transaction=tx)
    monitor: TransactionMonitor = agents["monitor"]
    velocity: VelocityAnalyzer = agents["velocity"]
    screener: SanctionsScreener = agents["screener"]
    filer: SARFiler = agents["filer"]

    # ── Stage 1: Transaction Monitor ──────────────────────────
    print(f"\n  ┌─ Stage 1: {monitor.name}")
    ig = integrations["monitor"]
    ic = interceptors["monitor"]
    cx = contexts["monitor"]

    # Structuring check
    tx_batch = (extra_txs or []) + [tx]
    governed_call(ig, cx, ic, "scan_transaction",
                  {"tx_id": tx.tx_id, "amount": tx.amount, "receiver": tx.receiver})

    structuring = monitor.detect_structuring(tx_batch)
    if structuring:
        governed_call(ig, cx, ic, "flag_structuring",
                      {"alert": structuring.alert_id, "score": structuring.risk_score})
        result.alerts.append(structuring)

    # Round-trip check
    if extra_txs and len(extra_txs) >= 2:
        round_trip = monitor.detect_round_trip(tx_batch)
        if round_trip:
            governed_call(ig, cx, ic, "flag_round_trip",
                          {"alert": round_trip.alert_id, "score": round_trip.risk_score})
            result.alerts.append(round_trip)

    # Dormant account check
    dormant = monitor.detect_dormant_activation(tx, last_activity_days)
    if dormant:
        governed_call(ig, cx, ic, "flag_dormant_activation",
                      {"alert": dormant.alert_id, "days": last_activity_days})
        result.alerts.append(dormant)

    # Geographic risk
    geo = monitor.score_geographic_risk(tx)
    if geo:
        governed_call(ig, cx, ic, "score_geographic_risk",
                      {"country": tx.country, "score": geo.risk_score})
        result.alerts.append(geo)

    # ── Stage 2: Velocity Analyzer ────────────────────────────
    print(f"  ├─ Stage 2: {velocity.name}")
    ig2 = integrations["velocity"]
    ic2 = interceptors["velocity"]
    cx2 = contexts["velocity"]

    governed_call(ig2, cx2, ic2, "check_daily_velocity",
                  {"tx_id": tx.tx_id, "daily_total": daily_total})

    vel_alert = velocity.check_velocity(tx, daily_total, weekly_total)
    if vel_alert:
        governed_call(ig2, cx2, ic2, "detect_activity_spike",
                      {"alert": vel_alert.alert_id, "score": vel_alert.risk_score})
        result.alerts.append(vel_alert)

    spike = velocity.detect_activity_spike(tx, avg_monthly_count, current_month_count)
    if spike:
        governed_call(ig2, cx2, ic2, "detect_activity_spike",
                      {"alert": spike.alert_id, "count": current_month_count})
        result.alerts.append(spike)

    # ── Stage 3: Sanctions Screener ───────────────────────────
    print(f"  ├─ Stage 3: {screener.name}")
    ig3 = integrations["screener"]
    ic3 = interceptors["screener"]
    cx3 = contexts["screener"]

    governed_call(ig3, cx3, ic3, "screen_ofac",
                  {"name": tx.receiver, "tx_id": tx.tx_id})
    ofac = screener.screen_ofac(tx.receiver, tx)
    if ofac:
        result.alerts.append(ofac)

    governed_call(ig3, cx3, ic3, "screen_country",
                  {"country": tx.country, "tx_id": tx.tx_id})
    country_hit = screener.screen_country(tx.country, tx)
    if country_hit:
        result.alerts.append(country_hit)

    governed_call(ig3, cx3, ic3, "screen_pep",
                  {"name": tx.receiver, "tx_id": tx.tx_id})
    pep_hit = screener.screen_pep(tx.receiver, tx)
    if pep_hit:
        result.alerts.append(pep_hit)

    # ── Stage 4: SAR Filing (if needed) ───────────────────────
    sar_required = any(a.requires_sar for a in result.alerts)
    high_risk = any(a.risk_score >= 0.85 for a in result.alerts)

    if result.alerts and (sar_required or high_risk):
        print(f"  └─ Stage 4: {filer.name}")
        ig4 = integrations["filer"]
        ic4 = interceptors["filer"]
        cx4 = contexts["filer"]

        governed_call(ig4, cx4, ic4, "generate_sar",
                      {"subject": tx.receiver, "alert_count": len(result.alerts)})
        sar = filer.generate_sar(tx.receiver, result.alerts, tx.amount)
        result.sar = sar

        # Attempt submission — requires human approval
        governed_call(ig4, cx4, ic4, "submit_sar",
                      {"sar_id": sar.sar_id, "subject": tx.receiver})

        result.final_decision = "SAR_FILED"
    elif result.alerts:
        print(f"  └─ Stage 4: {filer.name} (elevated review, no SAR)")
        result.final_decision = "ELEVATED_REVIEW"
    else:
        print(f"  └─ Stage 4: {filer.name} (no action needed)")
        result.final_decision = "CLEAR"

    return result


# ═══════════════════════════════════════════════════════════════════════════
# 10. DISPLAY HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def print_header(title: str) -> None:
    width = 72
    print()
    print("═" * width)
    print(f"  {title}")
    print("═" * width)


def print_scenario(num: int, title: str) -> None:
    print(f"\n{'─' * 72}")
    print(f"  Scenario {num}: {title}")
    print(f"{'─' * 72}")


def print_result(pr: PipelineResult) -> None:
    tx = pr.transaction
    status_icon = {"CLEAR": "✅", "ELEVATED_REVIEW": "⚠️", "SAR_FILED": "🚨"}.get(
        pr.final_decision, "❓")
    print(f"\n  Result: {status_icon} {pr.final_decision}")
    print(f"  Transaction: {tx.tx_id} │ ${tx.amount:,.2f} │ "
          f"{tx.sender} → {tx.receiver} │ {tx.country}")
    if pr.alerts:
        print(f"  Alerts ({len(pr.alerts)}):")
        for a in pr.alerts:
            print(f"    • [{a.alert_type}] score={a.risk_score:.2f} — {a.description}")
    if pr.sar:
        print(f"  SAR: {pr.sar.sar_id} │ status={pr.sar.status} │ "
              f"deadline={pr.sar.filing_deadline.strftime('%Y-%m-%d') if pr.sar.filing_deadline else 'N/A'}")


# ═══════════════════════════════════════════════════════════════════════════
# 11. DEMO SCENARIOS
# ═══════════════════════════════════════════════════════════════════════════

def create_agents_and_governance():
    """Set up all agents, integrations, contexts, and interceptors."""
    agents = {
        "monitor": TransactionMonitor(),
        "velocity": VelocityAnalyzer(),
        "screener": SanctionsScreener(),
        "filer": SARFiler(),
    }

    integrations = {}
    contexts = {}
    interceptors = {}

    policies = {
        "monitor": monitor_policy,
        "velocity": velocity_policy,
        "screener": screener_policy,
        "filer": sar_policy,
    }

    for key, policy in policies.items():
        ig = AMLIntegration(policy=policy)
        # Wire all event types to audit listener
        for evt in GovernanceEventType:
            ig.on(evt, audit_listener)
        integrations[key] = ig
        contexts[key] = ig.create_context(f"aml-{key}")
        if key == "filer":
            interceptors[key] = SARApprovalInterceptor(policy, contexts[key])
        else:
            interceptors[key] = PolicyInterceptor(policy, contexts[key])

    return agents, integrations, contexts, interceptors


def run_demo() -> None:
    agents, integrations, contexts, interceptors = create_agents_and_governance()

    # -- Print architecture summary ----------------------------------------
    print_header("AML/KYC Fraud Detection Demo — Agent OS")
    print("""
  Architecture:
    TransactionMonitor → VelocityAnalyzer → SanctionsScreener → SARFiler

  Governance per agent:
    ┌────────────────────────┬────────┬──────────┬────────────────────────┐
    │ Agent                  │ Tools  │ Max Call │ Special                │
    ├────────────────────────┼────────┼──────────┼────────────────────────┤
    │ TransactionMonitor     │      5 │       50 │ PII blocking           │
    │ VelocityAnalyzer       │      4 │       30 │ PII blocking           │
    │ SanctionsScreener      │      4 │       30 │ PII blocking           │
    │ SARFiler               │      3 │       20 │ Human approval on file │
    └────────────────────────┴────────┴──────────┴────────────────────────┘

  Blocked patterns: SSN (regex), account numbers (regex), password, secret
  Audit: immutable append-only log with JSON/CSV export
  Compliance: BSA/AML §5318, 31 CFR §1020.320
""")

    tx_counter = [0]

    def make_tx(amount, sender, receiver, country="US", desc=""):
        tx_counter[0] += 1
        return Transaction(
            tx_id=f"TX-{tx_counter[0]:04d}",
            amount=amount, sender=sender, receiver=receiver,
            country=country, description=desc,
        )

    # ── Scenario 1: Normal transaction ────────────────────────
    print_scenario(1, "Normal transaction ($500 transfer)")
    tx1 = make_tx(500.00, "Acme Corp", "Office Supplies Inc", desc="Paper supplies")
    r1 = run_pipeline(tx1, integrations, contexts, interceptors, agents)
    print_result(r1)

    # ── Scenario 2: Structuring attempt ───────────────────────
    print_scenario(2, "Structuring attempt (3×$9,500 same day)")
    struct_txs = [
        make_tx(9_500.00, "John Smith", "Shell Co Alpha", desc="Consulting 1"),
        make_tx(9_500.00, "John Smith", "Shell Co Alpha", desc="Consulting 2"),
    ]
    tx2 = make_tx(9_500.00, "John Smith", "Shell Co Alpha", desc="Consulting 3")
    r2 = run_pipeline(tx2, integrations, contexts, interceptors, agents,
                      extra_txs=struct_txs)
    print_result(r2)

    # ── Scenario 3: OFAC sanctions hit ────────────────────────
    print_scenario(3, "OFAC sanctions hit")
    tx3 = make_tx(25_000.00, "Global Imports", "Viktor Bout",
                  country="Russia", desc="Arms dealer")
    r3 = run_pipeline(tx3, integrations, contexts, interceptors, agents)
    print_result(r3)

    # ── Scenario 4: Dormant account spike ─────────────────────
    print_scenario(4, "Dormant account activation (270 days idle)")
    tx4 = make_tx(45_000.00, "Dormant Holdings LLC", "Offshore Trust",
                  desc="Sudden reactivation")
    r4 = run_pipeline(tx4, integrations, contexts, interceptors, agents,
                      last_activity_days=270, daily_total=0, weekly_total=0,
                      avg_monthly_count=2, current_month_count=15)
    print_result(r4)

    # ── Scenario 5: Round-trip laundering ─────────────────────
    print_scenario(5, "Round-trip laundering (A→B→C→A)")
    rt_txs = [
        make_tx(50_000.00, "Alpha Fund", "Beta Holdings", desc="Investment"),
        make_tx(49_500.00, "Beta Holdings", "Gamma Trust", desc="Transfer"),
        make_tx(49_000.00, "Gamma Trust", "Alpha Fund", desc="Return"),
    ]
    tx5 = make_tx(48_500.00, "Alpha Fund", "Beta Holdings", desc="Reinvestment")
    r5 = run_pipeline(tx5, integrations, contexts, interceptors, agents,
                      extra_txs=rt_txs)
    print_result(r5)

    # ── Scenario 6: PEP transaction ───────────────────────────
    print_scenario(6, "Politically Exposed Person (PEP)")
    tx6 = make_tx(120_000.00, "Swiss Bank AG", "Carlos Mendez",
                  country="Panama", desc="Wealth management")
    r6 = run_pipeline(tx6, integrations, contexts, interceptors, agents)
    print_result(r6)

    # ── Scenario 7: High-risk jurisdiction ────────────────────
    print_scenario(7, "High-risk jurisdiction (Iran)")
    tx7 = make_tx(75_000.00, "Trade Corp", "Tehran Imports",
                  country="Iran", desc="Commercial goods")
    r7 = run_pipeline(tx7, integrations, contexts, interceptors, agents)
    print_result(r7)

    # ── Scenario 8: SAR filing with human approval gate ───────
    print_scenario(8, "SAR filing — human approval required")
    print("\n  (This scenario demonstrates the governance gate on SAR submission)")
    tx8 = make_tx(500_000.00, "Unknown Sender", "Al-Rashid Trading Co",
                  country="Iran", desc="Suspicious large transfer")
    r8 = run_pipeline(tx8, integrations, contexts, interceptors, agents,
                      daily_total=480_000)
    print_result(r8)
    if r8.sar:
        print(f"\n  SAR Narrative:\n")
        for line in r8.sar.narrative.split("\n"):
            print(f"    {line}")

    # ── Audit Trail Summary ───────────────────────────────────
    print_header("Audit Trail Summary")
    blocked = [e for e in audit_log if e.get("decision") == "blocked"]
    allowed = [e for e in audit_log if e.get("decision") == "allowed"]
    checkpoints = [e for e in audit_log if e.get("decision") == "checkpoint"]
    print(f"  Total events:  {len(audit_log)}")
    print(f"  Allowed calls: {len(allowed)}")
    print(f"  Blocked calls: {len(blocked)}")
    print(f"  Checkpoints:   {len(checkpoints)}")

    print(f"\n  Blocked calls detail:")
    for i, entry in enumerate(blocked, 1):
        print(f"    {i}. [{entry.get('agent_id')}] tool={entry.get('tool')} "
              f"— {entry.get('reason', '')[:80]}")

    # ── Agent Context Summary ─────────────────────────────────
    print_header("Agent Context Summary")
    for key in ("monitor", "velocity", "screener", "filer"):
        cx = contexts[key]
        print(f"  {key:<12} │ calls={cx.call_count:>2}/{cx.policy.max_tool_calls:<3} "
              f"│ checkpoints={len(cx.checkpoints)}")

    # ── Export audit trail ────────────────────────────────────
    script_dir = os.path.dirname(os.path.abspath(__file__))
    json_path = os.path.join(script_dir, "aml_audit_trail.json")
    csv_path = os.path.join(script_dir, "aml_audit_trail.csv")
    save_audit_json(json_path)
    save_audit_csv(csv_path)

    print_header("Audit Trail Exported")
    print(f"  JSON: {json_path}")
    print(f"  CSV:  {csv_path}")
    print(f"\n  Immutable record for BSA/AML compliance review.")
    print(f"  Retention: 5 years per 31 USC §5318(g).\n")


# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    run_demo()
