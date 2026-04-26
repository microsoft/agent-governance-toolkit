#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Execution Rings Workflow Demo — Data Processing Pipeline

Demonstrates the agent-hypervisor execution ring system with four agents
at different privilege levels:

  Ring 0 (Supervisor)  — orchestrates the workflow, can access all resources
  Ring 1 (Data Agent)  — reads databases, writes reports
  Ring 2 (Analysis)    — reads data, computes, but no write access
  Ring 3 (User-facing) — sandboxed, can only return pre-approved responses

Shows ring enforcement, elevation, kill switch, and audit trail.

Run:
    python demo.py
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

# Allow running from the tutorials/execution-rings-workflow directory without
# installing the package by adding the repo src/ to sys.path.
_repo_root = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_repo_root / "src"))

from hypervisor.models import (  # noqa: E402
    ActionDescriptor,
    ExecutionRing,
    ReversibilityLevel,
)
from hypervisor.rings.enforcer import RingEnforcer  # noqa: E402
from hypervisor.security.kill_switch import KillSwitch, KillReason  # noqa: E402

# ── Agent definitions ────────────────────────────────────────────────────────

AGENTS: dict[str, dict] = {
    "supervisor": {
        "ring": ExecutionRing.RING_0_ROOT,
        "eff_score": 1.0,
        "role": "Orchestrator",
    },
    "data-agent": {
        "ring": ExecutionRing.RING_1_PRIVILEGED,
        "eff_score": 0.97,
        "role": "Data Engineer",
    },
    "analysis-agent": {
        "ring": ExecutionRing.RING_2_STANDARD,
        "eff_score": 0.75,
        "role": "Analyst",
    },
    "user-agent": {
        "ring": ExecutionRing.RING_3_SANDBOX,
        "eff_score": 0.40,
        "role": "User-facing",
    },
}

# ── Action definitions ───────────────────────────────────────────────────────
# Each action's required_ring is derived from its properties (is_admin,
# reversibility, is_read_only) via ActionDescriptor.required_ring.

ACTIONS: dict[str, ActionDescriptor] = {
    "configure_system": ActionDescriptor(
        action_id="configure_system",
        name="Configure System",
        execute_api="/system/config",
        is_admin=True,  # → requires Ring 0
    ),
    "write_report": ActionDescriptor(
        action_id="write_report",
        name="Write Report to DB",
        execute_api="/reports/write",
        reversibility=ReversibilityLevel.NONE,  # non-reversible → Ring 1
    ),
    "compute_aggregation": ActionDescriptor(
        action_id="compute_aggregation",
        name="Compute Aggregation",
        execute_api="/analytics/compute",
        undo_api="/analytics/revert",
        reversibility=ReversibilityLevel.FULL,  # reversible → Ring 2
    ),
    "read_dataset": ActionDescriptor(
        action_id="read_dataset",
        name="Read Dataset",
        execute_api="/data/read",
        is_read_only=True,  # read-only → Ring 3
    ),
    "return_response": ActionDescriptor(
        action_id="return_response",
        name="Return Pre-approved Response",
        execute_api="/responses/return",
        is_read_only=True,  # read-only → Ring 3
    ),
}

# ── Audit trail ──────────────────────────────────────────────────────────────

RING_LABELS = {0: "root", 1: "privileged", 2: "standard", 3: "sandbox"}


@dataclass
class AuditEntry:
    """A single audit trail entry."""

    event: str
    agent: str
    details: str


@dataclass
class AuditTrail:
    """Collects audit events for the demo."""

    entries: list[AuditEntry] = field(default_factory=list)

    def log(self, event: str, agent: str, details: str) -> None:
        self.entries.append(AuditEntry(event=event, agent=agent, details=details))

    def print_trail(self) -> None:
        print(f"\n{'━━ Scenario 5: Audit Trail ':━<60}")
        print(f"  {'#':<3} {'Event':<21}{'Agent':<21}{'Details'}")
        for i, entry in enumerate(self.entries, 1):
            print(f"  {i:<3} {entry.event:<21}{entry.agent:<21}{entry.details}")


# ── Display helpers ──────────────────────────────────────────────────────────

SEPARATOR = "═" * 62


def print_header() -> None:
    print(f"\n{SEPARATOR}")
    print("  Execution Rings Workflow Demo — Data Processing Pipeline")
    print(f"{SEPARATOR}")


def print_roster() -> None:
    print(f"\n── Agent Roster {'─' * 46}")
    for name, info in AGENTS.items():
        ring_val = info["ring"].value
        label = RING_LABELS[ring_val]
        print(f"  {name:<20} Ring {ring_val} ({label:<12})  {info['role']}")


def print_scenario(number: int, title: str) -> None:
    print(f"\n{'━━ Scenario ' + str(number) + ': ' + title + ' ':━<60}")


def print_check(agent: str, action_id: str, allowed: bool,
                agent_ring: int, required_ring: int) -> None:
    symbol = "✓" if allowed else "✗"
    status = "ALLOWED" if allowed else "DENIED "
    op = "≤" if allowed else ">"
    print(
        f"  {symbol} {agent:<18} → {action_id:<22}"
        f"{status} (ring {agent_ring} {op} required {required_ring})"
    )


# ── Scenario runners ────────────────────────────────────────────────────────


def run_scenario_1(enforcer: RingEnforcer, audit: AuditTrail) -> None:
    """Normal operation — each agent performs actions within its ring."""
    print_scenario(1, "Normal Operation")

    checks = [
        ("data-agent", "write_report"),
        ("analysis-agent", "read_dataset"),
        ("analysis-agent", "compute_aggregation"),
        ("user-agent", "return_response"),
    ]
    for agent_name, action_id in checks:
        agent_ring = AGENTS[agent_name]["ring"]
        action = ACTIONS[action_id]
        eff = AGENTS[agent_name]["eff_score"]
        result = enforcer.check(agent_ring=agent_ring, action=action, eff_score=eff)
        print_check(agent_name, action_id, result.allowed,
                     agent_ring.value, result.required_ring.value)
        audit.log("access_granted", agent_name, action_id)


def run_scenario_2(enforcer: RingEnforcer, audit: AuditTrail) -> None:
    """Ring enforcement — lower-privileged agents denied higher-ring actions."""
    print_scenario(2, "Ring Enforcement")

    checks = [
        ("user-agent", "write_report"),
        ("user-agent", "compute_aggregation"),
        ("analysis-agent", "write_report"),
    ]
    for agent_name, action_id in checks:
        agent_ring = AGENTS[agent_name]["ring"]
        action = ACTIONS[action_id]
        eff = AGENTS[agent_name]["eff_score"]
        result = enforcer.check(agent_ring=agent_ring, action=action, eff_score=eff)
        print_check(agent_name, action_id, result.allowed,
                     agent_ring.value, result.required_ring.value)
        audit.log("access_denied", agent_name, action_id)


def run_scenario_3(enforcer: RingEnforcer, audit: AuditTrail) -> None:
    """Ring elevation — temporary sudo for emergency access.

    Note: RingElevationManager.request_elevation() raises in public preview,
    so we simulate elevation logic directly to illustrate the concept.
    """
    print_scenario(3, "Ring Elevation")

    agent_name = "analysis-agent"
    original_ring = AGENTS[agent_name]["ring"]
    elevated_ring = ExecutionRing.RING_1_PRIVILEGED
    reason = "emergency data export"

    # Simulate granting elevation
    print(
        f"  ↑ {agent_name:<18} elevated Ring {original_ring.value}"
        f" → Ring {elevated_ring.value} (reason: {reason})"
    )
    audit.log("ring_elevated", agent_name,
              f"Ring {original_ring.value} → Ring {elevated_ring.value}")

    # With elevated ring, the agent can now perform Ring 1 actions
    action = ACTIONS["write_report"]
    eff = AGENTS[agent_name]["eff_score"]
    result = enforcer.check(agent_ring=elevated_ring, action=action, eff_score=eff)
    print_check(agent_name, "write_report", result.allowed,
                 elevated_ring.value, result.required_ring.value)
    audit.log("access_granted", agent_name, "write_report (elevated)")

    # Revoke elevation
    print(
        f"  ↓ {agent_name:<18} elevation revoked"
        f" — back to Ring {original_ring.value}"
    )
    audit.log("ring_revoked", agent_name,
              f"Ring {elevated_ring.value} → Ring {original_ring.value}")


def run_scenario_4(kill_switch: KillSwitch, audit: AuditTrail) -> None:
    """Kill switch — supervisor kills misbehaving agent."""
    print_scenario(4, "Kill Switch")

    agent_name = "user-agent"
    session_id = "demo-session"

    print(f"  ⚠ {agent_name:<18} attempted ring breach — triggering kill switch")

    result = kill_switch.kill(
        agent_did=agent_name,
        session_id=session_id,
        reason=KillReason.RING_BREACH,
        details="Attempted to write to database from Ring 3",
    )

    print(f"  ☠ {agent_name:<18} KILLED (reason: {result.reason.value})")
    print(f"    Kill ID: {result.kill_id}")
    print(f"    Compensation triggered: {result.compensation_triggered}")
    audit.log("kill_executed", agent_name, result.reason.value)


# ── Main demo ────────────────────────────────────────────────────────────────


def run_demo() -> None:
    enforcer = RingEnforcer()
    kill_switch = KillSwitch()
    audit = AuditTrail()

    print_header()
    print_roster()

    # Log initial ring assignments
    for name, info in AGENTS.items():
        ring_val = info["ring"].value
        audit.log("ring_assigned", name, f"→ Ring {ring_val}")

    # Run all scenarios
    run_scenario_1(enforcer, audit)
    run_scenario_2(enforcer, audit)
    run_scenario_3(enforcer, audit)
    run_scenario_4(kill_switch, audit)

    # Scenario 5: Print the audit trail
    audit.print_trail()
    print(SEPARATOR)


def main() -> None:
    run_demo()


if __name__ == "__main__":
    main()
