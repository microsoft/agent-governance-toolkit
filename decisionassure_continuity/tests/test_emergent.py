import pytest
from src.models import AgentAction
from src.emergent_detector import EmergentDetector

def test_emergent_detection():
    detector = EmergentDetector()
    actions = [
        AgentAction(agent_id="alice", action_type="read_database", tool="sql"),
        AgentAction(agent_id="bob", action_type="read_credentials", tool="vault"),
        AgentAction(agent_id="charlie", action_type="export_data", tool="s3")
    ]
    results = detector.detect(actions)
    detected = [r for r in results if r.capability_detected]
    assert len(detected) == 1
    assert detected[0].capability.name == "Credential Exfiltration"
    assert set(detected[0].contributing_agents) == {"alice", "bob", "charlie"}
def test_lineage_generation():
    detector = EmergentDetector()
    actions = [
        AgentAction(agent_id="alice", action_type="read_database", tool="sql"),
        AgentAction(agent_id="bob", action_type="read_credentials", tool="vault"),
        AgentAction(agent_id="charlie", action_type="export_data", tool="s3")
    ]
    results = detector.detect(actions)
    detected = [r for r in results if r.capability_detected]
    assert len(detected) == 1
    res = detected[0]
    assert res.lineage is not None
    assert len(res.lineage.contributions) == 3
    # Check contribution types
    contrib_types = [c.contribution_type for c in res.lineage.contributions]
    assert "discovery" in contrib_types
    assert "aggregation" in contrib_types
    assert "export" in contrib_types
def test_no_emergent():
    detector = EmergentDetector()
    actions = [
        AgentAction(agent_id="alice", action_type="read_database", tool="sql"),
        AgentAction(agent_id="bob", action_type="read_database", tool="sql")
    ]
    results = detector.detect(actions)
    detected = [r for r in results if r.capability_detected]
    assert len(detected) == 0