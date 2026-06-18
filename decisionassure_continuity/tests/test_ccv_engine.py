import pytest
from src.models import ContinuityWitness
from src.ccv_engine import CCVEngine

def test_basic_continuity():
    engine = CCVEngine()
    w1 = ContinuityWitness(
        index=0, previous_witness_hash="0"*64,
        agent_id="alice", session_id="s1",
        constitution_hash="hash1", observer_hash="hash1",
        reference_frame_hash="hash1", action_hash="action1"
    )
    # Compute hash for w1 before using it as previous
    w1.witness_hash = w1.compute_hash()
    w2 = ContinuityWitness(
        index=1, previous_witness_hash=w1.witness_hash,
        agent_id="alice", session_id="s1",
        constitution_hash="hash1", observer_hash="hash1",
        reference_frame_hash="hash1", action_hash="action2"
    )
    result = engine.verify_continuity([w1, w2])
    assert result.continuity_score > 0.8
    assert result.verification_status == "PASS"

def test_drift_detection():
    engine = CCVEngine()
    w1 = ContinuityWitness(
        index=0, previous_witness_hash="0"*64,
        agent_id="alice", session_id="s1",
        constitution_hash="hash1", observer_hash="hash1",
        reference_frame_hash="hash1", action_hash="action1"
    )
    w1.witness_hash = w1.compute_hash()
    w2 = ContinuityWitness(
        index=1, previous_witness_hash=w1.witness_hash,
        agent_id="alice", session_id="s1",
        constitution_hash="hash1", observer_hash="hash2",  # Drift
        reference_frame_hash="hash1", action_hash="action2"
    )
    result = engine.verify_continuity([w1, w2])
    assert result.observer_drift > 0.1
    assert result.verification_status != "PASS"