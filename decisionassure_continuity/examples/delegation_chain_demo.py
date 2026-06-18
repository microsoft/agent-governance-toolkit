#!/usr/bin/env python3
"""Demonstrate continuity across a delegation chain."""

from src.models import ContinuityWitness
from src.ccv_engine import CCVEngine

def main():
    engine = CCVEngine()

    # Agent Alice starts
    alice_genesis = ContinuityWitness(
        index=0,
        previous_witness_hash="0" * 64,
        agent_id="alice",
        session_id="session1",
        constitution_hash="constitution_v1",
        observer_hash="observer_alice",
        reference_frame_hash="ref_v1",
        action_hash="alice_start"
    )
    engine.chain.add_witness(alice_genesis)

    # Alice delegates to Bob
    bob_genesis = ContinuityWitness(
        index=1,
        previous_witness_hash=engine.chain.get_latest_witness().witness_hash,
        agent_id="bob",
        session_id="session1",
        constitution_hash="constitution_v1",
        observer_hash="observer_bob",
        reference_frame_hash="ref_v1",
        action_hash="bob_receive_delegation"
    )
    engine.chain.add_witness(bob_genesis)

    # Bob acts
    bob_action = ContinuityWitness(
        index=2,
        previous_witness_hash=engine.chain.get_latest_witness().witness_hash,
        agent_id="bob",
        session_id="session1",
        constitution_hash="constitution_v1",
        observer_hash="observer_bob",
        reference_frame_hash="ref_v1",
        action_hash="bob_write"
    )
    engine.chain.add_witness(bob_action)

    # Verify continuity
    result = engine.verify_continuity(engine.chain.witnesses)

    print("\n🔗 Delegation Chain Continuity")
    print(f"Continuity Score: {result.continuity_score:.4f}")
    print(f"Status: {result.verification_status}")
    print(f"Witness count: {result.witness_count}")

if __name__ == "__main__":
    main()