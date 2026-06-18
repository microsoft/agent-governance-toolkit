import pytest
from src.models import AgentAction
from src.capability_discovery import CapabilityDiscovery

def test_discovery_basic():
    # Create synthetic traces
    traces = []
    # Pattern 1: 5 traces
    for _ in range(5):
        traces.append([
            AgentAction(agent_id="a", action_type="read"),
            AgentAction(agent_id="b", action_type="write")
        ])
    # Pattern 2: 3 traces
    for _ in range(3):
        traces.append([
            AgentAction(agent_id="c", action_type="delete"),
            AgentAction(agent_id="d", action_type="export")
        ])
    # Noise: 2 traces
    for _ in range(2):
        traces.append([
            AgentAction(agent_id="e", action_type="view")
        ])
    
    discovery = CapabilityDiscovery(min_samples=3, eps=0.5)
    results = discovery.discover(traces)
    
    assert len(results) == 2
    # Check that both patterns were discovered
    pattern_actions = [set((a["agent"], a["action"]) for a in cap["required_actions"]) for cap in results]
    assert {("a", "read"), ("b", "write")} in pattern_actions
    assert {("c", "delete"), ("d", "export")} in pattern_actions

def test_discovery_min_samples():
    traces = []
    for _ in range(2):  # Only 2 traces, below min_samples
        traces.append([
            AgentAction(agent_id="a", action_type="read"),
            AgentAction(agent_id="b", action_type="write")
        ])
    
    discovery = CapabilityDiscovery(min_samples=3, eps=0.5)
    results = discovery.discover(traces)
    assert len(results) == 0