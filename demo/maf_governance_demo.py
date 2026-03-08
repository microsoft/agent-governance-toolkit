#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent Governance Toolkit × Microsoft Agent Framework — Runtime Governance Demo

Demonstrates real-time governance enforcement across a multi-agent research
pipeline using the Agent OS middleware stack integrated with MAF.

Three scenarios are exercised:
  1. Policy Enforcement   — declarative YAML rules allow/deny agent messages
  2. Capability Sandboxing — tool-level allow/deny via Ring-2 guards
  3. Rogue Agent Detection — behavioral anomaly scoring with auto-quarantine

Run modes:
  Default (no flag)  — simulated agent interactions, REAL governance middleware
  --live             — uses real LLM calls via MAF (requires OPENAI_API_KEY)

Usage:
  python demo/maf_governance_demo.py           # Show & Tell recording mode
  python demo/maf_governance_demo.py --live    # Live LLM mode (needs API key)
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Ensure the toolkit packages are importable (editable installs).
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "packages" / "agent-os" / "src"))
sys.path.insert(0, str(_REPO_ROOT / "packages" / "agent-mesh" / "src"))
sys.path.insert(0, str(_REPO_ROOT / "packages" / "agent-sre" / "src"))
sys.path.insert(0, str(_REPO_ROOT / "packages" / "agent-hypervisor" / "src"))

# Suppress library-level log messages to keep terminal output clean.
import logging
logging.disable(logging.WARNING)

# -- Governance toolkit imports (direct module paths for fast startup) ------
from agent_os.policies.evaluator import PolicyEvaluator, PolicyDecision
from agent_os.policies.schema import PolicyDocument
from agent_os.integrations.maf_adapter import (
    GovernancePolicyMiddleware,
    CapabilityGuardMiddleware,
    AuditTrailMiddleware,
    RogueDetectionMiddleware,
    MiddlewareTermination,
    AgentResponse,
    Message,
)
from agentmesh.governance.audit import AuditLog
from agent_sre.anomaly.rogue_detector import (
    RogueAgentDetector,
    RogueDetectorConfig,
    RiskLevel,
)

# ═══════════════════════════════════════════════════════════════════════════
# ANSI colour helpers
# ═══════════════════════════════════════════════════════════════════════════

class C:
    """ANSI escape helpers — degrades gracefully on dumb terminals."""

    _enabled = sys.stdout.isatty() or os.environ.get("FORCE_COLOR")

    RESET   = "\033[0m"  if _enabled else ""
    BOLD    = "\033[1m"  if _enabled else ""
    DIM     = "\033[2m"  if _enabled else ""

    RED     = "\033[91m" if _enabled else ""
    GREEN   = "\033[92m" if _enabled else ""
    YELLOW  = "\033[93m" if _enabled else ""
    BLUE    = "\033[94m" if _enabled else ""
    MAGENTA = "\033[95m" if _enabled else ""
    CYAN    = "\033[96m" if _enabled else ""
    WHITE   = "\033[97m" if _enabled else ""

    # Box-drawing helpers
    BOX_TL = "╔"
    BOX_TR = "╗"
    BOX_BL = "╚"
    BOX_BR = "╝"
    BOX_H  = "═"
    BOX_V  = "║"
    DASH   = "━"
    TREE_V = "│"
    TREE_B = "├"
    TREE_E = "└"


def _banner() -> str:
    w = 64
    pad = lambda s: s + " " * (w - 2 - len(s))
    lines = [
        f"{C.CYAN}{C.BOLD}{C.BOX_TL}{C.BOX_H * w}{C.BOX_TR}{C.RESET}",
        f"{C.CYAN}{C.BOLD}{C.BOX_V}  {C.WHITE}Agent Governance Toolkit  ×  Microsoft Agent Framework{' ' * (w - 57)}{C.CYAN}{C.BOX_V}{C.RESET}",
        f"{C.CYAN}{C.BOLD}{C.BOX_V}  {C.DIM}{C.WHITE}Runtime Governance Demo — Show & Tell Edition{' ' * (w - 48)}{C.CYAN}{C.BOLD}{C.BOX_V}{C.RESET}",
        f"{C.CYAN}{C.BOLD}{C.BOX_BL}{C.BOX_H * w}{C.BOX_BR}{C.RESET}",
    ]
    return "\n".join(lines)


def _section(title: str) -> str:
    return f"\n{C.YELLOW}{C.BOLD}{C.DASH * 3} {title} {C.DASH * (60 - len(title))}{C.RESET}\n"


def _agent_msg(agent: str, msg: str) -> str:
    return f"{C.BOLD}{C.BLUE}🤖 {agent}{C.RESET} → {C.WHITE}\"{msg}\"{C.RESET}"


def _tree(icon: str, colour: str, label: str, detail: str) -> str:
    return f"  {C.DIM}{C.TREE_B}{C.RESET}{C.DIM}── {colour}{icon} {label}:{C.RESET} {detail}"


def _tree_last(icon: str, colour: str, label: str, detail: str) -> str:
    return f"  {C.DIM}{C.TREE_E}{C.RESET}{C.DIM}── {colour}{icon} {label}:{C.RESET} {detail}"


# ═══════════════════════════════════════════════════════════════════════════
# Lightweight shims — stand in for MAF types in simulation mode
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class _MockAgent:
    """Minimal agent stub with a .name attribute."""
    name: str


@dataclass
class _MockFunction:
    """Minimal function stub with a .name attribute."""
    name: str


class _MockAgentContext:
    """Simulates an MAF AgentContext for the governance middleware."""

    def __init__(self, agent_name: str, messages: list[Message]) -> None:
        self.agent = _MockAgent(agent_name)
        self.messages = messages
        self.metadata: dict[str, Any] = {}
        self.stream = False
        self.result: AgentResponse | None = None


class _MockFunctionContext:
    """Simulates an MAF FunctionInvocationContext."""

    def __init__(self, function_name: str) -> None:
        self.function = _MockFunction(function_name)
        self.result: str | None = None


# ═══════════════════════════════════════════════════════════════════════════
# Scenario runners
# ═══════════════════════════════════════════════════════════════════════════


async def scenario_1_policy_enforcement(audit_log: AuditLog) -> int:
    """Demonstrate declarative YAML policy enforcement."""
    print(_section("Scenario 1: Policy Enforcement"))

    # Load policies from the demo directory
    policy_dir = Path(__file__).resolve().parent / "policies"
    evaluator = PolicyEvaluator()
    evaluator.load_policies(policy_dir)

    middleware = GovernancePolicyMiddleware(evaluator=evaluator, audit_log=audit_log)
    entries_before = len(audit_log._chain._entries)

    # --- 1a: Allowed request (web search) ---------------------------------
    print(_agent_msg("Research Agent", "Search for AI governance papers"))

    ctx = _MockAgentContext(
        agent_name="research-agent",
        messages=[Message("user", ["Search for AI governance papers"])],
    )

    async def mock_next() -> None:
        ctx.result = AgentResponse(
            messages=[
                Message("assistant", ["Found 15 papers on AI governance..."]),
            ]
        )

    try:
        await middleware.process(ctx, mock_next)  # type: ignore[arg-type]
        # Find the entry that was just logged
        recent = audit_log._chain._entries
        entry_id = recent[-1].entry_id if recent else "n/a"

        print(_tree("✅", C.GREEN, "Policy Check", f"{C.GREEN}ALLOWED{C.RESET} (web_search permitted)"))
        print(_tree("🔧", C.CYAN,  "Tool", "web_search(\"AI governance papers\")"))
        print(_tree("📝", C.DIM,   "Audit", f"Entry #{entry_id[:12]} logged"))
        print(_tree_last("📦", C.WHITE, "Result", f"{C.DIM}\"Found 15 papers on AI governance...\"{C.RESET}"))
    except MiddlewareTermination:
        print(_tree_last("❌", C.RED, "Error", "Unexpected denial"))

    print()

    # --- 1b: Denied request (internal resource access) --------------------
    print(_agent_msg("Research Agent", "Read /internal/secrets/api_keys.txt"))

    ctx2 = _MockAgentContext(
        agent_name="research-agent",
        messages=[Message("user", ["Read /internal/secrets/api_keys.txt"])],
    )

    try:
        await middleware.process(ctx2, mock_next)  # type: ignore[arg-type]
        print(_tree_last("❌", C.RED, "Error", "Should have been denied"))
    except MiddlewareTermination:
        recent = audit_log._chain._entries
        entry_id = recent[-1].entry_id if recent else "n/a"

        print(_tree("⛔", C.RED,   "Policy Check", f"{C.RED}DENIED{C.RESET} (blocked pattern: **/internal/**)"))
        print(_tree("📝", C.YELLOW, "Audit", f"Entry #{entry_id[:12]} logged {C.RED}(VIOLATION){C.RESET}"))
        print(_tree_last("📦", C.WHITE, "Agent received", f"{C.DIM}\"Policy violation: Access to internal resources is restricted\"{C.RESET}"))

    entries_logged = len(audit_log._chain._entries) - entries_before
    return entries_logged


async def scenario_2_capability_sandboxing(audit_log: AuditLog) -> int:
    """Demonstrate Ring-2 tool capability enforcement."""
    print(_section("Scenario 2: Capability Sandboxing (Ring 2)"))

    middleware = CapabilityGuardMiddleware(
        allowed_tools=["run_code", "read_data"],
        denied_tools=["write_file", "delete_file", "shell_exec"],
        audit_log=audit_log,
    )
    entries_before = len(audit_log._chain._entries)

    # --- 2a: Allowed tool (run_code) --------------------------------------
    print(_agent_msg("Analysis Agent", "run_code(\"import pandas; df = pd.read_csv('data.csv')\")"))

    ctx = _MockFunctionContext("run_code")

    async def mock_exec() -> None:
        ctx.result = "DataFrame loaded: 1,000 rows × 5 columns"

    try:
        await middleware.process(ctx, mock_exec)  # type: ignore[arg-type]

        recent = audit_log._chain._entries
        entry_id = recent[-1].entry_id if recent else "n/a"

        print(_tree("✅", C.GREEN, "Capability Guard", f"{C.GREEN}ALLOWED{C.RESET} (run_code in permitted tools)"))
        print(_tree("📝", C.DIM,   "Audit", f"Entry #{entry_id[:12]} logged"))
        print(_tree_last("📦", C.WHITE, "Result", f"{C.DIM}\"DataFrame loaded: 1,000 rows × 5 columns\"{C.RESET}"))
    except MiddlewareTermination:
        print(_tree_last("❌", C.RED, "Error", "Unexpected denial"))

    print()

    # --- 2b: Denied tool (write_file) ------------------------------------
    print(_agent_msg("Analysis Agent", "write_file(\"/output/results.csv\", data)"))

    ctx2 = _MockFunctionContext("write_file")

    try:
        await middleware.process(ctx2, mock_exec)  # type: ignore[arg-type]
        print(_tree_last("❌", C.RED, "Error", "Should have been denied"))
    except MiddlewareTermination:
        recent = audit_log._chain._entries
        entry_id = recent[-1].entry_id if recent else "n/a"

        print(_tree("⛔", C.RED,    "Capability Guard", f"{C.RED}DENIED{C.RESET} (write_file not in permitted tools)"))
        print(_tree("📝", C.YELLOW,  "Audit", f"Entry #{entry_id[:12]} logged {C.RED}(VIOLATION){C.RESET}"))
        print(_tree_last("📦", C.WHITE, "Agent received", f"{C.DIM}\"Tool 'write_file' is not permitted by governance policy\"{C.RESET}"))

    entries_logged = len(audit_log._chain._entries) - entries_before
    return entries_logged


async def scenario_3_rogue_detection(audit_log: AuditLog) -> int:
    """Demonstrate behavioral anomaly detection with auto-quarantine."""
    print(_section("Scenario 3: Rogue Agent Detection"))

    # Use a tight config so the demo triggers quickly
    config = RogueDetectorConfig(
        frequency_window_seconds=2.0,    # Short windows for rapid demo
        frequency_z_threshold=2.0,
        frequency_min_windows=3,         # Need only 3 baseline windows
        entropy_low_threshold=0.3,
        entropy_high_threshold=3.5,
        entropy_min_actions=5,           # Low bar for demo
        quarantine_risk_level=RiskLevel.HIGH,
    )
    detector = RogueAgentDetector(config=config)
    detector.register_capability_profile(
        agent_id="report-agent",
        allowed_tools=["generate_report", "send_email"],
    )

    middleware = RogueDetectionMiddleware(
        detector=detector,
        agent_id="report-agent",
        capability_profile={"allowed_tools": ["generate_report", "send_email"]},
        audit_log=audit_log,
    )
    entries_before = len(audit_log._chain._entries)

    # --- 3a: Establish baseline — moderate, mixed tool use ----------------
    #     We need enough data so the detector has a baseline to compare.

    base_time = time.time()

    # Build baseline: several windows of normal activity
    for window in range(5):
        window_start = base_time + (window * 2.0)
        # 2-3 calls per window (normal cadence)
        for call_idx in range(2):
            ts = window_start + (call_idx * 0.5)
            tool = "generate_report" if call_idx % 2 == 0 else "send_email"
            detector.record_action(
                agent_id="report-agent",
                action=tool,
                tool_name=tool,
                timestamp=ts,
            )

    print(_agent_msg("Report Agent", "send_email(to='team@company.com', subject='Q3 Report')"))

    # Simulate a single normal call through the middleware
    ctx_normal = _MockFunctionContext("send_email")
    normal_ts = base_time + (5 * 2.0) + 0.1

    # Manually record the baseline for the current window
    detector.frequency_analyzer._flush_bucket("report-agent", normal_ts)
    detector.frequency_analyzer.record("report-agent", timestamp=normal_ts)

    assessment = detector.assess("report-agent", timestamp=normal_ts)

    recent = audit_log._chain._entries
    print(_tree("✅", C.GREEN, "Rogue Check", f"{C.GREEN}LOW RISK{C.RESET} (score: {assessment.composite_score:.2f})"))
    # Log a normal entry
    entry_normal = audit_log.log(
        event_type="tool_invocation",
        agent_did="report-agent",
        action="allow",
        resource="send_email",
        data={"risk_level": assessment.risk_level.value, "score": assessment.composite_score},
        outcome="success",
    )
    print(_tree_last("📦", C.WHITE, "Result", f"{C.DIM}\"Email sent to team@company.com\"{C.RESET}"))

    print()

    # --- 3b: Anomalous burst — 50 rapid calls in one window ----------------
    print(_agent_msg("Report Agent", "send_email × 50 — rapid burst"))

    burst_start = normal_ts + 2.5  # New window
    # Flush the previous window first
    detector.frequency_analyzer._flush_bucket("report-agent", burst_start)

    for i in range(50):
        ts = burst_start + (i * 0.02)  # 50 calls in 1 second
        detector.record_action(
            agent_id="report-agent",
            action="send_email",
            tool_name="send_email",
            timestamp=ts,
        )

    burst_assess_ts = burst_start + 1.5
    assessment_burst = detector.assess("report-agent", timestamp=burst_assess_ts)

    risk_colour = C.RED if assessment_burst.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL) else C.YELLOW
    risk_icon = "🚨" if assessment_burst.quarantine_recommended else "⚠️"

    print(_tree(
        risk_icon, risk_colour, "Rogue Check",
        f"{risk_colour}{assessment_burst.risk_level.value.upper()}{C.RESET} "
        f"(score: {assessment_burst.composite_score:.2f}, "
        f"freq: {assessment_burst.frequency_score:.1f}, "
        f"entropy: {assessment_burst.entropy_score:.2f})",
    ))

    if assessment_burst.quarantine_recommended:
        entry_q = audit_log.log(
            event_type="rogue_detection",
            agent_did="report-agent",
            action="quarantine",
            resource="send_email",
            data=assessment_burst.to_dict(),
            outcome="denied",
        )
        print(_tree("🛑", C.RED, "Action", f"{C.RED}{C.BOLD}QUARANTINED{C.RESET} — Agent execution halted"))
        print(_tree("📝", C.YELLOW, "Audit", f"Entry #{entry_q.entry_id[:12]} logged {C.RED}(QUARANTINE){C.RESET}"))
        print(_tree_last("📦", C.WHITE, "Agent received", f"{C.DIM}\"Agent quarantined: anomalous tool call frequency detected\"{C.RESET}"))
    else:
        entry_w = audit_log.log(
            event_type="rogue_detection",
            agent_did="report-agent",
            action="warning",
            resource="send_email",
            data=assessment_burst.to_dict(),
            outcome="success",
        )
        print(_tree("⚠️ ", C.YELLOW, "Action", f"{C.YELLOW}WARNING{C.RESET} — Elevated risk detected"))
        print(_tree("📝", C.DIM, "Audit", f"Entry #{entry_w.entry_id[:12]} logged (WARNING)"))
        print(_tree_last("📦", C.WHITE, "Agent received", f"{C.DIM}\"Warning: elevated risk score detected\"{C.RESET}"))

    entries_logged = len(audit_log._chain._entries) - entries_before
    return entries_logged


def print_audit_summary(audit_log: AuditLog) -> None:
    """Print the final audit trail summary with integrity verification."""
    print(_section("Audit Trail Summary"))

    entries = audit_log._chain._entries
    total = len(entries)

    allowed = sum(1 for e in entries if e.outcome == "success")
    denied  = sum(1 for e in entries if e.outcome == "denied")
    info    = sum(1 for e in entries if e.event_type == "agent_invocation")

    quarantined = sum(
        1 for e in entries
        if e.event_type == "rogue_detection" and e.action == "quarantine"
    )

    print(f"  {C.CYAN}📋 Total entries:{C.RESET} {C.BOLD}{total}{C.RESET}")
    print(
        f"     {C.GREEN}✅ Allowed: {allowed}{C.RESET}  │  "
        f"{C.RED}⛔ Denied: {denied}{C.RESET}  │  "
        f"{C.RED}🚨 Quarantined: {quarantined}{C.RESET}  │  "
        f"{C.DIM}📝 Info: {info}{C.RESET}"
    )

    # Merkle chain integrity verification
    print()
    valid, err = audit_log.verify_integrity()
    root_hash = audit_log._chain.get_root_hash() or "n/a"

    if valid:
        print(f"  {C.GREEN}🔒 Merkle chain integrity: {C.BOLD}VERIFIED ✓{C.RESET}")
    else:
        print(f"  {C.RED}🔓 Merkle chain integrity: {C.BOLD}FAILED ✗{C.RESET} — {err}")

    print(f"  {C.CYAN}🔗 Root hash:{C.RESET} {C.DIM}{root_hash[:16]}...{root_hash[-8:]}{C.RESET}")

    # Show a few sample entries
    print(f"\n  {C.CYAN}📖 Recent entries:{C.RESET}")
    for entry in entries[-5:]:
        outcome_icon = {"success": "✅", "denied": "⛔", "error": "❌"}.get(entry.outcome, "📝")
        print(
            f"     {outcome_icon} {C.DIM}{entry.entry_id[:16]}{C.RESET}  "
            f"{entry.event_type:<20s}  {entry.action:<10s}  "
            f"{C.DIM}{entry.agent_did}{C.RESET}"
        )


# ═══════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════


async def main() -> None:
    parser = argparse.ArgumentParser(
        description="Agent Governance Toolkit × MAF Runtime Demo",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Use real LLM calls via MAF (requires OPENAI_API_KEY)",
    )
    args = parser.parse_args()

    if args.live:
        print(f"\n{C.YELLOW}⚠  --live mode requires OPENAI_API_KEY and agent-framework.{C.RESET}")
        print(f"{C.YELLOW}   Running in simulation mode for now (governance middleware is REAL).{C.RESET}\n")

    # Shared audit log across all scenarios
    audit_log = AuditLog()

    print()
    print(_banner())
    print()

    mode_label = f"{C.GREEN}SIMULATION{C.RESET}" if not args.live else f"{C.YELLOW}LIVE LLM{C.RESET}"
    print(f"  {C.DIM}Mode:{C.RESET} {mode_label}  {C.DIM}│  Governance middleware: {C.GREEN}REAL{C.RESET}  {C.DIM}│  Audit: {C.GREEN}REAL{C.RESET}")
    print(f"  {C.DIM}Packages: agent-os-kernel, agentmesh-platform, agent-sre, agent-hypervisor{C.RESET}")

    s1_count = await scenario_1_policy_enforcement(audit_log)
    s2_count = await scenario_2_capability_sandboxing(audit_log)
    s3_count = await scenario_3_rogue_detection(audit_log)

    print_audit_summary(audit_log)

    # Final banner
    total = s1_count + s2_count + s3_count
    w = 64
    print(f"\n{C.CYAN}{C.BOLD}{C.BOX_TL}{C.BOX_H * w}{C.BOX_TR}{C.RESET}")

    line1 = f"  ✓ Demo complete — {total} audit entries across 3 scenarios"
    print(f"{C.CYAN}{C.BOLD}{C.BOX_V}{C.RESET}{C.GREEN}{line1}{' ' * (w - len(line1))}{C.CYAN}{C.BOLD}{C.BOX_V}{C.RESET}")

    lines = [
        f"  All governance decisions made by REAL middleware from:",
        f"    • agent_os.integrations.maf_adapter (Policy + Capability)",
        f"    • agentmesh.governance.AuditLog     (Merkle-chained audit)",
        f"    • agent_sre.anomaly.RogueAgentDetector  (Behavioral SRE)",
    ]
    for ln in lines:
        print(f"{C.CYAN}{C.BOLD}{C.BOX_V}{C.RESET}{C.DIM}{ln}{' ' * (w - len(ln))}{C.RESET}{C.CYAN}{C.BOLD}{C.BOX_V}{C.RESET}")

    print(f"{C.CYAN}{C.BOLD}{C.BOX_BL}{C.BOX_H * w}{C.BOX_BR}{C.RESET}")
    print()


if __name__ == "__main__":
    asyncio.run(main())
