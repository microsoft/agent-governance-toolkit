#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
AgentMesh Basic Multi-Agent Chat — Two governed agents with policy enforcement.

Run:
    pip install -r requirements.txt
    python main.py

Demonstrates the AgentMesh unified governance pipeline for inter-agent messaging:

1. Create two mock agents, each wrapped around an AgentMeshClient.
2. Bob loads a YAML policy that allows summarize and denies export.
3. Alice asks Bob to summarize -> policy allows, trust score rises.
4. Alice asks Bob to export    -> policy denies, trust score falls.
5. Print Bob's audit trail with the Merkle-chained AuditLog entries.
6. Verify the audit chain integrity at the end.

No API keys are required. After installation the example runs locally and
does not call external services. Outcomes are deterministic so the printed
output is stable across runs (except for ephemeral DIDs).
"""

from agentmesh import AgentMeshClient, GovernanceResult


# Bob's policy: allow everything by default, but deny any "export" action.
POLICY_YAML = """
apiVersion: governance.toolkit/v1
name: inter-agent-chat-policy
description: "Allow summarize between agents; deny exports."
agents: ["*"]
default_action: allow
rules:
  - name: block-export
    stage: pre_tool
    condition: "action.type == 'export'"
    action: deny
    description: "Inter-agent export of data is denied by default."
"""


class MockAgent:
    """A thin wrapper around AgentMeshClient — no LLM, no network."""

    def __init__(
        self,
        name: str,
        capabilities: list[str],
        policy_yaml: str | None = None,
    ) -> None:
        self.name = name
        self.client = AgentMeshClient(
            agent_id=name,
            capabilities=capabilities,
            policy_yaml=policy_yaml,
        )

    def receive(
        self,
        sender: "MockAgent",
        action: str,
        message: str,
    ) -> tuple[GovernanceResult, str]:
        """Run an incoming message through the governance pipeline."""
        # Set action.type explicitly so the link to the YAML rule
        # (action.type == 'export') is obvious to readers.
        context = {
            "action": {"type": action},
            "sender": sender.name,
            "sender_did": sender.client.agent_did,
            "message": message,
        }
        result = self.client.execute_with_governance(action, context)
        if not result.allowed:
            return result, "blocked before processing"
        return result, self.process(action, message)

    def process(self, action: str, message: str) -> str:
        """Mock business logic — no LLM, deterministic canned responses."""
        if action == "summarize":
            return "summary: governance policy allows this request"
        return f"processed: {message}"


def print_exchange(
    sender: str,
    recipient: str,
    action: str,
    result: GovernanceResult,
    reply: str,
) -> None:
    marker = "[ok]     " if result.allowed else "[blocked]"
    line = f"{sender} -> {recipient} {action}"
    print(
        f"  {marker} {line:<35} -> "
        f"decision={result.decision:<5} trust={result.trust_score:.1f}"
    )
    print(f"             reply: {reply}")


def main() -> None:
    print("AgentMesh Basic Multi-Agent Chat")
    print("=" * 60)

    # ── 1. Create two mock agents ──────────────────────────────────────
    alice = MockAgent(
        name="alice-agent",
        capabilities=["summarize", "request"],
    )
    bob = MockAgent(
        name="bob-agent",
        capabilities=["summarize"],
        policy_yaml=POLICY_YAML,
    )

    # ── 2. Print agent introduction ────────────────────────────────────
    for agent in (alice, bob):
        did_short = agent.client.agent_did[:24] + "..."
        score = float(agent.client.trust_score.total_score)
        print(f"  {agent.name:<12} did={did_short}  trust={score:.1f}")
    print()

    # ── 3. Message 1: ALLOWED (summarize) ──────────────────────────────
    result, reply = bob.receive(
        alice, "summarize", "please summarize the incident notes"
    )
    print_exchange(alice.name, bob.name, "summarize", result, reply)

    # ── 4. Message 2: BLOCKED (export) ─────────────────────────────────
    result, reply = bob.receive(
        alice, "export", "export the customer data"
    )
    print_exchange(alice.name, bob.name, "export", result, reply)

    # ── 5. Print Bob's audit trail ─────────────────────────────────────
    print()
    print("Bob's audit trail:")
    for entry in bob.client.audit_log.get_entries_for_agent(
        bob.client.agent_did
    ):
        print(
            f"  - event={entry.event_type:<18} "
            f"action={entry.action:<10} "
            f"outcome={entry.outcome:<8} "
            f"policy={entry.policy_decision}"
        )

    # ── 6. Verify audit chain integrity ────────────────────────────────
    valid, error = bob.client.audit_log.verify_integrity()
    status = "verified" if valid else f"failed: {error}"
    print(f"\nAudit integrity: {status}")


if __name__ == "__main__":
    main()
