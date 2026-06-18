import pytest
from src.models import ContinuityWitness
from src.witness_chain import WitnessChain

def test_add_witness():
    chain = WitnessChain()
    w1 = ContinuityWitness(
        index=0, previous_witness_hash="0"*64,
        agent_id="alice", session_id="s1",
        constitution_hash="hash1", observer_hash="hash1",
        reference_frame_hash="hash1", action_hash="action1"
    )
    chain.add_witness(w1)
    assert len(chain.witnesses) == 1
    assert chain.witnesses[0].witness_hash is not None

def test_verify_chain():
    chain = WitnessChain()
    w1 = ContinuityWitness(
        index=0, previous_witness_hash="0"*64,
        agent_id="alice", session_id="s1",
        constitution_hash="hash1", observer_hash="hash1",
        reference_frame_hash="hash1", action_hash="action1"
    )
    w2 = ContinuityWitness(
        index=1, previous_witness_hash="",
        agent_id="alice", session_id="s1",
        constitution_hash="hash1", observer_hash="hash1",
        reference_frame_hash="hash1", action_hash="action2"
    )
    chain.add_witness(w1)
    chain.add_witness(w2)
    assert chain.verify_chain() is True