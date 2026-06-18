#!/usr/bin/env python3
"""Basic continuity verification example."""

from src.models import ContinuityWitness
from src.ccv_engine import CCVEngine

def main():
    # Create a chain of witnesses (simulating an agent's execution steps)
    engine = CCVEngine()

    # Step 0: Genesis
    w0 = ContinuityWitness(
        index=0,
        previous_witness_hash="0" * 64,
        agent_id="alice",
        session_id="session1",
        constitution_hash="constitution_v1",
        observer_hash="observer_alice_1",
        reference_frame_hash="ref_v1",
        action_hash="action_genesis"
    )
    engine.chain.add_witness(w0)

    # Step 1: Stable
    w1 = ContinuityWitness(
        index=1,
        previous_witness_hash=engine.chain.get_latest_witness().witness_hash,
        agent_id="alice",
        session_id="session1",
        constitution_hash="constitution_v1",
        observer_hash="observer_alice_1",
        reference_frame_hash="ref_v1",
        action_hash="action_read"
    )
    engine.chain.add_witness(w1)

    # Step 2: Drift! (policy change)
    w2 = ContinuityWitness(
        index=2,
        previous_witness_hash=engine.chain.get_latest_witness().witness_hash,
        agent_id="alice",
        session_id="session1",
        constitution_hash="constitution_v2",  # Changed!
        observer_hash="observer_alice_1",
        reference_frame_hash="ref_v2",        # Changed!
        action_hash="action_write"
    )
    engine.chain.add_witness(w2)

    # Verify continuity
    result = engine.verify_continuity(engine.chain.witnesses)

    print("\n📊 Continuity Verification Result")
    print(f"Continuity Score: {result.continuity_score:.4f}")
    print(f"Status: {result.verification_status}")
    print(f"Identity Preserved: {result.identity_preserved}")
    print(f"Constitution Preserved: {result.constitution_preserved}")
    print(f"Delegation Drift: {result.delegation_drift:.4f}")
    print(f"Observer Drift: {result.observer_drift:.4f}")
    if result.break_reason:
        print(f"Break Reason: {result.break_reason}")

if __name__ == "__main__":
    main()