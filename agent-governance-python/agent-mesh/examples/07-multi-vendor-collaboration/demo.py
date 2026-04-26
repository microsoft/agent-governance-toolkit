#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Multi-Vendor Agent Collaboration Demo
======================================

Demonstrates trust-gated handoffs between agents from different AI vendors
(OpenAI, Anthropic, Google) orchestrated through AgentMesh governance.

No API keys required — all vendor agents are mocked.

Usage:
    python demo.py
"""

from __future__ import annotations

import json
import random
import textwrap
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MIN_TRUST_SCORE = 700
INITIAL_TRUST_SCORE = 850
MAX_TRUST_SCORE = 1000

TRUST_REWARD_SUCCESS = 50
TRUST_PENALTY_SLOW = -30
TRUST_PENALTY_POOR_QUALITY = -300
TRUST_PENALTY_POLICY_VIOLATION = -200


# ---------------------------------------------------------------------------
# Domain types
# ---------------------------------------------------------------------------

class Vendor(Enum):
    OPENAI = "OpenAI"
    ANTHROPIC = "Anthropic"
    GOOGLE = "Google"


class HandoffStatus(Enum):
    APPROVED = "APPROVED"
    DENIED = "DENIED"


class TaskOutcome(Enum):
    SUCCESS = "success"
    SLOW = "slow"
    POOR_QUALITY = "poor_quality"
    POLICY_VIOLATION = "policy_violation"


@dataclass
class AuditEntry:
    timestamp: str
    event: str
    source: str
    target: Optional[str]
    trust_score: int
    status: str
    detail: str


@dataclass
class AgentIdentity:
    """Represents a vendor-specific agent registered in AgentMesh."""

    agent_id: str
    name: str
    vendor: Vendor
    capabilities: list[str]
    trust_score: int = INITIAL_TRUST_SCORE

    def summary(self) -> str:
        return f"{self.name} ({self.vendor.value}) trust={self.trust_score}"


# ---------------------------------------------------------------------------
# Trust engine
# ---------------------------------------------------------------------------

class TrustEngine:
    """Manages trust scores and trust-gated handoff decisions."""

    def __init__(self, min_score: int = MIN_TRUST_SCORE) -> None:
        self.min_score = min_score

    def verify(self, agent: AgentIdentity) -> bool:
        return agent.trust_score >= self.min_score

    @staticmethod
    def update(agent: AgentIdentity, outcome: TaskOutcome) -> int:
        deltas = {
            TaskOutcome.SUCCESS: TRUST_REWARD_SUCCESS,
            TaskOutcome.SLOW: TRUST_PENALTY_SLOW,
            TaskOutcome.POOR_QUALITY: TRUST_PENALTY_POOR_QUALITY,
            TaskOutcome.POLICY_VIOLATION: TRUST_PENALTY_POLICY_VIOLATION,
        }
        delta = deltas[outcome]
        agent.trust_score = max(0, min(MAX_TRUST_SCORE, agent.trust_score + delta))
        return delta


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

class AuditLog:
    """Cross-vendor audit trail for all handoffs and task outcomes."""

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    def record_handoff(
        self,
        source: AgentIdentity,
        target: AgentIdentity,
        status: HandoffStatus,
        detail: str = "",
    ) -> None:
        self._entries.append(
            AuditEntry(
                timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                event="HANDOFF",
                source=source.agent_id,
                target=target.agent_id,
                trust_score=target.trust_score,
                status=status.value,
                detail=detail,
            )
        )

    def record_task(
        self,
        agent: AgentIdentity,
        outcome: TaskOutcome,
        trust_delta: int,
        detail: str = "",
    ) -> None:
        self._entries.append(
            AuditEntry(
                timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                event="TASK_COMPLETE",
                source=agent.agent_id,
                target=None,
                trust_score=agent.trust_score,
                status=outcome.value,
                detail=f"trust_delta={trust_delta:+d} {detail}".strip(),
            )
        )

    def print_trail(self) -> None:
        print("\n" + "=" * 80)
        print("CROSS-VENDOR AUDIT TRAIL")
        print("=" * 80)
        for e in self._entries:
            target = f" → {e.target}" if e.target else ""
            print(
                f"[{e.timestamp}] {e.event:<14} {e.source}{target} "
                f"| trust: {e.trust_score} | status: {e.status}"
            )
            if e.detail:
                print(f"{'':>20} detail: {e.detail}")
        print("=" * 80)


# ---------------------------------------------------------------------------
# Mock vendor agents
# ---------------------------------------------------------------------------

class MockVendorAgent:
    """Simulates a vendor-specific LLM agent with configurable behaviour."""

    def __init__(self, identity: AgentIdentity) -> None:
        self.identity = identity
        self._force_outcome: Optional[TaskOutcome] = None

    def force_outcome(self, outcome: TaskOutcome) -> None:
        self._force_outcome = outcome

    def process(self, task: str) -> tuple[str, TaskOutcome]:
        # Simulate processing delay
        time.sleep(0.05)

        if self._force_outcome is not None:
            outcome = self._force_outcome
            self._force_outcome = None
        else:
            outcome = TaskOutcome.SUCCESS

        responses = {
            TaskOutcome.SUCCESS: f"[{self.identity.vendor.value}] Processed: {task}",
            TaskOutcome.SLOW: f"[{self.identity.vendor.value}] Slow response: {task}",
            TaskOutcome.POOR_QUALITY: f"[{self.identity.vendor.value}] Low-quality output for: {task}",
            TaskOutcome.POLICY_VIOLATION: f"[{self.identity.vendor.value}] Policy violation on: {task}",
        }
        return responses[outcome], outcome


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class MultiVendorOrchestrator:
    """Orchestrates trust-gated handoffs across vendor agents."""

    def __init__(self) -> None:
        self.trust_engine = TrustEngine()
        self.audit = AuditLog()
        self.agents: dict[str, MockVendorAgent] = {}

    def register(self, agent: MockVendorAgent) -> None:
        self.agents[agent.identity.agent_id] = agent
        _info(f"Registered {agent.identity.summary()}")

    def handoff(self, source: MockVendorAgent, target: MockVendorAgent, task: str) -> Optional[str]:
        """Attempt a trust-gated handoff from source to target."""
        trusted = self.trust_engine.verify(target.identity)
        status = HandoffStatus.APPROVED if trusted else HandoffStatus.DENIED

        self.audit.record_handoff(source.identity, target.identity, status)

        if not trusted:
            _warn(
                f"HANDOFF DENIED: {source.identity.name} → {target.identity.name} "
                f"(trust {target.identity.trust_score} < {MIN_TRUST_SCORE})"
            )
            return None

        _ok(
            f"HANDOFF APPROVED: {source.identity.name} → {target.identity.name} "
            f"(trust {target.identity.trust_score})"
        )

        response, outcome = target.process(task)
        delta = TrustEngine.update(target.identity, outcome)
        self.audit.record_task(target.identity, outcome, delta)

        if outcome == TaskOutcome.SUCCESS:
            _ok(f"  Result: {response}  (trust {delta:+d} → {target.identity.trust_score})")
        else:
            _warn(f"  Result: {response}  (trust {delta:+d} → {target.identity.trust_score})")

        return response

    def run_pipeline(self, query: str, pipeline: list[str]) -> Optional[str]:
        """Run a task through an ordered pipeline of agent IDs."""
        result = query
        for i in range(len(pipeline) - 1):
            src = self.agents[pipeline[i]]
            tgt = self.agents[pipeline[i + 1]]
            result = self.handoff(src, tgt, result)
            if result is None:
                return None
        return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _header(text: str) -> None:
    print(f"\n{'─' * 80}")
    print(f"  {text}")
    print(f"{'─' * 80}")


def _ok(text: str) -> None:
    print(f"  ✅ {text}")


def _warn(text: str) -> None:
    print(f"  ⚠️  {text}")


def _info(text: str) -> None:
    print(f"  ℹ️  {text}")


def _scores(agents: list[MockVendorAgent]) -> None:
    print("\n  Trust Scoreboard:")
    for a in agents:
        bar_len = a.identity.trust_score // 20
        bar = "█" * bar_len + "░" * (50 - bar_len)
        status = "TRUSTED" if a.identity.trust_score >= MIN_TRUST_SCORE else "UNTRUSTED"
        print(f"    {a.identity.name:<22} [{bar}] {a.identity.trust_score:>4}  {status}")


# ---------------------------------------------------------------------------
# Main demo
# ---------------------------------------------------------------------------

def main() -> None:
    print("=" * 80)
    print("  AgentMesh — Multi-Vendor Agent Collaboration Demo")
    print("  Trust-gated handoffs between OpenAI, Anthropic & Google agents")
    print("=" * 80)

    # --- Setup agents ---
    _header("SETUP: Registering vendor agents")

    agent_a = MockVendorAgent(
        AgentIdentity(
            agent_id="agent-a-openai",
            name="Agent A (OpenAI)",
            vendor=Vendor.OPENAI,
            capabilities=["customer-queries", "intent-classification"],
        )
    )
    agent_b = MockVendorAgent(
        AgentIdentity(
            agent_id="agent-b-anthropic",
            name="Agent B (Anthropic)",
            vendor=Vendor.ANTHROPIC,
            capabilities=["research", "fact-checking", "analysis"],
        )
    )
    agent_c = MockVendorAgent(
        AgentIdentity(
            agent_id="agent-c-google",
            name="Agent C (Google)",
            vendor=Vendor.GOOGLE,
            capabilities=["summarization", "report-generation"],
        )
    )

    orch = MultiVendorOrchestrator()
    for agent in [agent_a, agent_b, agent_c]:
        orch.register(agent)

    all_agents = [agent_a, agent_b, agent_c]
    pipeline = ["agent-a-openai", "agent-b-anthropic", "agent-c-google"]

    _scores(all_agents)

    # --- Round 1: All agents trusted ---
    _header("ROUND 1: All agents trusted — full pipeline")
    query = "How does AgentMesh handle cross-vendor trust?"
    _info(f'Customer query: "{query}"')

    result = orch.run_pipeline(query, pipeline)
    if result:
        _ok(f"Pipeline complete. Final output: {result}")
    _scores(all_agents)

    # --- Round 2: Agent C produces poor quality ---
    _header("ROUND 2: Agent C (Google) returns poor-quality results")
    agent_c.force_outcome(TaskOutcome.POOR_QUALITY)

    query2 = "Summarize the latest compliance requirements."
    _info(f'Customer query: "{query2}"')

    result = orch.run_pipeline(query2, pipeline)
    _scores(all_agents)

    # --- Round 3: Agent C's trust has dropped — handoff should be denied ---
    _header("ROUND 3: Agent C trust below threshold — handoff denied")
    _info(
        f"Agent C trust ({agent_c.identity.trust_score}) is below "
        f"minimum ({MIN_TRUST_SCORE}). Handoff will be denied."
    )

    query3 = "Generate a risk assessment report."
    _info(f'Customer query: "{query3}"')

    result = orch.run_pipeline(query3, pipeline)
    if result is None:
        _warn("Pipeline interrupted — activating fallback.")
        _info("Fallback: Agent B (Anthropic) handles summarization directly.")
        fallback_result = orch.handoff(agent_b, agent_b, query3)
        if fallback_result:
            _ok(f"Fallback complete. Final output: {fallback_result}")

    _scores(all_agents)

    # --- Audit trail ---
    orch.audit.print_trail()

    # --- Summary ---
    _header("DEMO COMPLETE")
    print(
        textwrap.dedent("""\
        Key takeaways:
          1. Trust scores adapt based on agent performance across vendors
          2. Handoffs are denied when trust drops below the governance threshold
          3. Fallback mechanisms ensure pipeline resilience
          4. Every cross-vendor interaction is recorded in an immutable audit trail
        """)
    )


if __name__ == "__main__":
    main()
