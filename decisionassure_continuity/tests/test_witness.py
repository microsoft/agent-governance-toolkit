import pytest
from src.models import AgentAction
from src.capability_witness import CapabilityWitnessEngine

def test_witness_generation():
    engine = CapabilityWitnessEngine()
    actions = [
        AgentAction(agent_id="alice", action_type="read_database"),
        AgentAction(agent_id="bob", action_type="read_credentials"),
        AgentAction(agent_id="charlie", action_type="export_data")
    ]
    witness = engine.generate_witness(actions)
    assert witness is not None
    assert witness.capability_id == "credential_exfiltration"
    assert len(witness.required_actions) == 3
    assert witness.witness_hash is not None

def test_witness_counterfactual():
    engine = CapabilityWitnessEngine()
    actions = [
        AgentAction(agent_id="alice", action_type="read_database"),
        AgentAction(agent_id="bob", action_type="read_credentials"),
        AgentAction(agent_id="charlie", action_type="export_data")
    ]
    witness = engine.generate_witness(actions)
    cf = witness.counterfactual
    assert cf["removed_agent"] in ["alice", "bob", "charlie"]
    # Removing any single agent should break the capability because all three are required
    assert cf["capability_still_exists"] is False

def test_no_witness():
    engine = CapabilityWitnessEngine()
    actions = [
        AgentAction(agent_id="alice", action_type="read_database"),
        AgentAction(agent_id="bob", action_type="read_database")
    ]
    witness = engine.generate_witness(actions)
    assert witness is None