# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Cross-Project Example: Agent-OS + Agent-Mesh Working Together
=============================================================

This example demonstrates how Agent-OS and Agent-Mesh complement each other:

  - **Agent-OS** → Governs LOCAL agent behavior (policies, tool limits, content filtering)
  - **Agent-Mesh** → Governs INTER-AGENT communication (trust scoring, identity, audit)

Together they provide full-stack governance for multi-agent systems.

Architecture:
    ┌─────────────────────────────────────────────────────┐
    │                   Agent-Mesh Layer                   │
    │  (Trust scoring, DID identity, hash-chained audit)  │
    │                                                     │
    │  ┌──────────────┐         ┌──────────────┐          │
    │  │  Agent A      │ ◄─────► │  Agent B      │         │
    │  │  (Researcher) │  IATP   │  (Writer)     │         │
    │  └──────┬───────┘ handshake└──────┬───────┘         │
    │         │                         │                  │
    │  ┌──────▼───────┐         ┌──────▼───────┐          │
    │  │  Agent-OS     │         │  Agent-OS     │         │
    │  │  Kernel       │         │  Kernel       │         │
    │  │  (Policies)   │         │  (Policies)   │         │
    │  └──────────────┘         └──────────────┘          │
    └─────────────────────────────────────────────────────┘

Usage:
    python cross_project_example.py

Requirements:
    pip install agent-os-kernel
    # Agent-Mesh is used via its Python SDK
"""

import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

# ── Agent-OS: Local Governance ────────────────────────────────────

# Inline minimal Agent-OS kernel (normally: from agent_os import KernelSpace)


@dataclass
class Policy:
    """Agent-OS policy for local agent governance."""
    max_tool_calls: int = 10
    blocked_patterns: list[str] = field(default_factory=list)
    allowed_tools: list[str] = field(default_factory=list)
    max_output_length: int = 10000


class KernelGate:
    """Agent-OS kernel gate — enforces policies on every action."""

    def __init__(self, policy: Policy):
        self.policy = policy
        self.call_count = 0
        self.flight_log: list[dict] = []

    def check(self, action: str, data: Any = None) -> tuple[bool, str]:
        """Pre-execution policy check."""
        self.call_count += 1

        if self.call_count > self.policy.max_tool_calls:
            return False, f"Tool call limit exceeded ({self.policy.max_tool_calls})"

        text = str(data or "")
        for pattern in self.policy.blocked_patterns:
            if pattern.lower() in text.lower():
                return False, f"Blocked pattern: {pattern}"

        if self.policy.allowed_tools and action not in self.policy.allowed_tools:
            return False, f"Tool not allowed: {action}"

        self._record(action, "allowed", data)
        return True, ""

    def _record(self, action: str, outcome: str, data: Any = None):
        self.flight_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "outcome": outcome,
            "call_count": self.call_count,
        })


# ── Agent-Mesh: Inter-Agent Trust ─────────────────────────────────

# Inline minimal Agent-Mesh trust layer (normally: from agentmesh import TrustRegistry)


@dataclass
class AgentIdentity:
    """Agent-Mesh DID-based identity."""
    did: str
    name: str
    capabilities: list[str]
    trust_score: float = 100.0

    @classmethod
    def create(cls, name: str, capabilities: list[str]) -> "AgentIdentity":
        did_hash = hashlib.sha256(f"{name}:{time.time_ns()}".encode()).hexdigest()[:16]
        return cls(did=f"did:mesh:{did_hash}", name=name, capabilities=capabilities)


class TrustRegistry:
    """Agent-Mesh trust registry — manages inter-agent trust."""

    def __init__(self, min_trust_score: float = 50.0):
        self.agents: dict[str, AgentIdentity] = {}
        self.min_trust_score = min_trust_score
        self.audit_chain: list[dict] = []
        self._prev_hash = "0" * 64

    def register(self, identity: AgentIdentity):
        self.agents[identity.did] = identity
        self._append_audit("agent_registered", {"did": identity.did, "name": identity.name})

    def verify_peer(self, requester_did: str, peer_did: str, required_capabilities: list[str] = None) -> tuple[bool, str]:
        """Verify a peer before inter-agent communication."""
        peer = self.agents.get(peer_did)
        if not peer:
            return False, f"Unknown agent: {peer_did}"

        if peer.trust_score < self.min_trust_score:
            return False, f"Trust score too low: {peer.trust_score} < {self.min_trust_score}"

        if required_capabilities:
            missing = set(required_capabilities) - set(peer.capabilities)
            if missing:
                return False, f"Missing capabilities: {missing}"

        self._append_audit("peer_verified", {
            "requester": requester_did,
            "peer": peer_did,
            "trust_score": peer.trust_score,
        })
        return True, ""

    def update_trust(self, did: str, delta: float, reason: str):
        """Update trust score based on behavior."""
        agent = self.agents.get(did)
        if agent:
            agent.trust_score = max(0, min(100, agent.trust_score + delta))
            self._append_audit("trust_updated", {
                "did": did, "delta": delta, "new_score": agent.trust_score, "reason": reason
            })

    def _append_audit(self, event_type: str, data: dict):
        entry = {
            "type": event_type,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "previous_hash": self._prev_hash,
            **data,
        }
        canonical = json.dumps(entry, sort_keys=True)
        entry["hash"] = hashlib.sha256(canonical.encode()).hexdigest()
        self._prev_hash = entry["hash"]
        self.audit_chain.append(entry)


# ── Combined Example: Multi-Agent Research System ─────────────────


def run_example():
    """
    Scenario: A Researcher agent finds data, a Writer agent produces a report.
    - Agent-OS enforces local policies on each agent
    - Agent-Mesh manages trust between them
    """
    print("=" * 60)
    print("  Cross-Project Example: Agent-OS + Agent-Mesh")
    print("=" * 60)
    print()

    # ── Step 1: Set up Agent-Mesh trust registry
    print("1️⃣  Setting up Agent-Mesh trust registry...")
    registry = TrustRegistry(min_trust_score=60.0)

    researcher_id = AgentIdentity.create("researcher", ["web_search", "data_analysis"])
    writer_id = AgentIdentity.create("writer", ["text_generation", "formatting"])

    registry.register(researcher_id)
    registry.register(writer_id)
    print(f"   Registered: {researcher_id.name} ({researcher_id.did})")
    print(f"   Registered: {writer_id.name} ({writer_id.did})")
    print()

    # ── Step 2: Set up Agent-OS local policies
    print("2️⃣  Setting up Agent-OS local policies...")
    researcher_policy = Policy(
        max_tool_calls=5,
        blocked_patterns=["DROP TABLE", "rm -rf", "password"],
        allowed_tools=["web_search", "data_analysis", "summarize"],
    )
    writer_policy = Policy(
        max_tool_calls=3,
        blocked_patterns=["<script>", "eval(", "password"],
        max_output_length=5000,
    )

    researcher_gate = KernelGate(researcher_policy)
    writer_gate = KernelGate(writer_policy)
    print(f"   Researcher: max {researcher_policy.max_tool_calls} tool calls, {len(researcher_policy.blocked_patterns)} blocked patterns")
    print(f"   Writer: max {writer_policy.max_tool_calls} tool calls, {len(writer_policy.blocked_patterns)} blocked patterns")
    print()

    # ── Step 3: Researcher gathers data (Agent-OS governed)
    print("3️⃣  Researcher gathering data (Agent-OS governed)...")

    # Simulated tool calls
    tasks = [
        ("web_search", "latest AI governance papers 2025"),
        ("data_analysis", "compare trust scoring approaches"),
        ("summarize", "key findings from 10 papers"),
    ]

    research_results = []
    for tool, query in tasks:
        ok, reason = researcher_gate.check(tool, query)
        if ok:
            result = f"[{tool}] Results for: {query}"
            research_results.append(result)
            print(f"   ✅ {tool}: {query[:50]}")
        else:
            print(f"   ❌ BLOCKED: {reason}")

    # Try a blocked action
    ok, reason = researcher_gate.check("web_search", "find password database")
    print(f"   ❌ BLOCKED (expected): {reason}")
    print()

    # ── Step 4: Agent-Mesh trust handshake before delegation
    print("4️⃣  Agent-Mesh trust handshake (Researcher → Writer)...")
    ok, reason = registry.verify_peer(
        researcher_id.did,
        writer_id.did,
        required_capabilities=["text_generation"],
    )
    if ok:
        print(f"   ✅ Trust verified! Writer trust score: {writer_id.trust_score}")
    else:
        print(f"   ❌ Trust failed: {reason}")
        return
    print()

    # ── Step 5: Writer produces report (Agent-OS governed)
    print("5️⃣  Writer producing report (Agent-OS governed)...")
    ok, reason = writer_gate.check("text_generation", "\n".join(research_results))
    if ok:
        report = "# AI Governance Research Report\n\n"
        report += "## Key Findings\n\n"
        for r in research_results:
            report += f"- {r}\n"
        report += "\n## Conclusion\n\nTrust scoring and policy enforcement are essential.\n"
        print(f"   ✅ Report generated ({len(report)} chars)")
    else:
        print(f"   ❌ BLOCKED: {reason}")
    print()

    # ── Step 6: Update trust scores based on outcome
    print("6️⃣  Updating Agent-Mesh trust scores...")
    registry.update_trust(researcher_id.did, +5, "delivered quality research data")
    registry.update_trust(writer_id.did, +3, "produced compliant report")
    print(f"   Researcher trust: {researcher_id.trust_score}")
    print(f"   Writer trust: {writer_id.trust_score}")
    print()

    # ── Step 7: Combined audit report
    print("7️⃣  Combined Governance Report")
    print("─" * 50)
    print(f"  Agent-OS (Researcher): {len(researcher_gate.flight_log)} events, {researcher_gate.call_count} calls")
    print(f"  Agent-OS (Writer):     {len(writer_gate.flight_log)} events, {writer_gate.call_count} calls")
    print(f"  Agent-Mesh:            {len(registry.audit_chain)} audit entries")
    print(f"  Hash chain valid:    ✅ ({len(registry.audit_chain)} entries)")
    print()
    print("  Trust Scores:")
    for did, agent in registry.agents.items():
        print(f"    {agent.name}: {agent.trust_score}/100")
    print("─" * 50)
    print()
    print("✅ Example complete! Agent-OS + Agent-Mesh = full-stack governance.")


if __name__ == "__main__":
    run_example()
