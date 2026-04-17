# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Lab 2 — Multi-Agent Trust
=========================
Introduction to AI Agent Governance Workshop

Goal: Create two agents, run a trust handshake, build trust through positive
behaviour, revoke credentials, and observe how the trust layer responds at
each stage.

Instructions:
1. Read through this file completely before making changes.
2. Fill in each section marked with TODO.
3. Run the script:   python lab2_multi_agent_trust.py
4. Compare your output to the expected flow in lab-guide.md.

Prerequisites:
    pip install agentmesh-platform
"""

from agentmesh import AgentIdentity, RiskScorer
from agentmesh.trust import TrustHandshake

# ---------------------------------------------------------------------------
# Step 1 — Create two agents
# ---------------------------------------------------------------------------

def create_agents() -> tuple:
    """
    TODO: Create two AgentIdentity objects.

    - orchestrator: capabilities ["orchestrate:agents", "read:data"]
                    sponsor "alice@example.com"
    - worker:       capabilities ["read:data", "write:reports"]
                    sponsor "bob@example.com"

    Return (orchestrator, worker).
    """
    # Replace these stubs with real AgentIdentity.create() calls.
    orchestrator = None  # TODO
    worker = None        # TODO
    return orchestrator, worker


# ---------------------------------------------------------------------------
# Step 2 — Attempt a trust handshake (expected: fail)
# ---------------------------------------------------------------------------

def attempt_handshake(initiator, responder, min_trust_score: int) -> bool:
    """
    TODO: Create a TrustHandshake from initiator → responder and execute it.

    Print:
        [OK]   Handshake succeeded — session_token: <token>
      or
        [FAIL] Handshake failed — <reason>

    Return True if the handshake succeeded, False otherwise.
    """
    # result = TrustHandshake(
    #     initiator=initiator,
    #     responder_did=str(responder.did),
    #     required_capabilities=["read:data"],
    #     min_trust_score=min_trust_score,
    # ).execute()

    # TODO: print result and return result.trusted
    return False  # replace this


# ---------------------------------------------------------------------------
# Step 3 — Build trust through positive behaviour
# ---------------------------------------------------------------------------

def build_trust(agent, num_events: int = 10) -> int:
    """
    TODO: Use RiskScorer to record `num_events` "policy_compliant_action"
    events for the given agent.

    After recording, fetch the updated score and print it.
    Return the total_score integer.
    """
    scorer = RiskScorer()

    # TODO: loop and call scorer.record_event() for each event
    # scorer.record_event(
    #     agent_did=str(agent.did),
    #     event_type="policy_compliant_action",
    #     details=f"Completed task {i + 1}",
    # )

    score = scorer.get_score(str(agent.did))
    print(f"[INFO]  Trust score after {num_events} events: {score.total_score}")
    return score.total_score


# ---------------------------------------------------------------------------
# Step 4 — Revoke credentials and confirm block
# ---------------------------------------------------------------------------

def revoke_and_verify(initiator, responder) -> None:
    """
    TODO: Revoke the initiator's credentials and then attempt a handshake.
    Confirm that the handshake fails with a "credentials revoked" reason.
    """
    print("[INFO]  Revoking initiator credentials...")
    # initiator.revoke()
    # attempt_handshake(initiator, responder, min_trust_score=400)
    pass  # TODO: remove this line when implemented


# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------

def run_lab() -> None:
    print("=" * 60)
    print("Lab 2 — Multi-Agent Trust")
    print("=" * 60)

    # Step 1
    orchestrator, worker = create_agents()
    if orchestrator is None or worker is None:
        print("[ERROR] create_agents() returned None — complete the TODO in Step 1.")
        return

    print(f"[INFO]  Orchestrator DID: {orchestrator.did}")
    print(f"[INFO]  Worker DID:       {worker.did}")
    print()

    # Step 2 — first handshake (should fail: score 500 < 700)
    print("--- Step 2: Initial handshake (min_trust_score=700) ---")
    attempt_handshake(orchestrator, worker, min_trust_score=700)
    print()

    # Step 3 — build trust
    print("--- Step 3: Building trust (10 positive events) ---")
    score = build_trust(orchestrator, num_events=10)
    print()

    # Step 4a — retry handshake with lower threshold
    threshold = 540
    print(f"--- Step 4a: Retry handshake (min_trust_score={threshold}) ---")
    success = attempt_handshake(orchestrator, worker, min_trust_score=threshold)
    print()

    if not success:
        print("[HINT]  Handshake still failing. Try more events or lower threshold.")
    else:
        # Step 4b — revoke and confirm block
        print("--- Step 4b: Revoke credentials and confirm block ---")
        revoke_and_verify(orchestrator, worker)

    print()
    print("Lab 2 complete.")


if __name__ == "__main__":
    run_lab()
