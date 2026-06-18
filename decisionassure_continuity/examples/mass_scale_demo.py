#!/usr/bin/env python3
"""
Mass-Scale Capability Discovery Demo – 100,000 synthetic traces.
Demonstrates discovery at scale.
"""

import random
from src.models import AgentAction
from src.capability_discovery import CapabilityDiscovery

def generate_traces(num_traces: int = 100000):
    """Generate synthetic traces with known patterns."""
    traces = []
    patterns = [
        {
            "name": "credential_exfiltration",
            "agents": ["alice", "bob", "charlie"],
            "actions": ["read_database", "read_credentials", "export_data"],
            "weight": 0.4
        },
        {
            "name": "privilege_escalation",
            "agents": ["david", "eve", "frank"],
            "actions": ["grant_permission", "write_config", "delete_logs"],
            "weight": 0.3
        },
        {
            "name": "data_manipulation",
            "agents": ["grace", "heidi", "ivan"],
            "actions": ["read_database", "write_database", "delete_records"],
            "weight": 0.2
        },
        {
            "name": "noise",
            "agents": ["jack", "karen"],
            "actions": ["read_database", "read_database"],
            "weight": 0.1
        }
    ]

    for _ in range(num_traces):
        # Select a pattern based on weight
        selected = random.choices(patterns, weights=[p["weight"] for p in patterns])[0]
        trace = []
        for agent, action in zip(selected["agents"], selected["actions"]):
            trace.append(AgentAction(agent_id=agent, action_type=action))
        traces.append(trace)

    return traces

def main():
    print("📊 Generating 100,000 synthetic traces...")
    traces = generate_traces(100000)

    print("🔍 Discovering emergent capabilities...")
    discovery = CapabilityDiscovery(min_samples=50, eps=0.5)
    discovered = discovery.discover(traces)

    print(f"\n✅ Found {len(discovered)} capabilities.")
    for i, cap in enumerate(discovered, 1):
        print(f"\nCapability {i}: {cap['capability_name']}")
        print(f"  Classification: {cap['classification']}")
        print(f"  Severity: {cap['severity']}")
        print(f"  Confidence: {cap['confidence']:.4f}")
        print(f"  Occurrences: {cap['occurrence_count']}")
        print(f"  Required Actions: {len(cap['required_actions'])} actions")
        print(f"  Match Confidence: {cap['match_confidence']:.4f}")

if __name__ == "__main__":
    main()