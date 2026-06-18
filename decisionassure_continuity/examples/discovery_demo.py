#!/usr/bin/env python3
"""Capability Discovery Demo with Classification."""

from src.models import AgentAction
from src.capability_discovery import CapabilityDiscovery

def main():
    # Synthetic traces
    traces = []

    # Pattern 1: Credential Exfiltration (5 traces)
    for _ in range(5):
        traces.append([
            AgentAction(agent_id="alice", action_type="read_database"),
            AgentAction(agent_id="bob", action_type="read_credentials"),
            AgentAction(agent_id="charlie", action_type="export_data")
        ])

    # Pattern 2: Privilege Escalation (3 traces)
    for _ in range(3):
        traces.append([
            AgentAction(agent_id="david", action_type="grant_permission"),
            AgentAction(agent_id="eve", action_type="write_config"),
            AgentAction(agent_id="frank", action_type="delete_logs")
        ])

    # Pattern 3: Frequent but weak pattern (10 traces)
    for _ in range(10):
        traces.append([
            AgentAction(agent_id="grace", action_type="read_database"),
            AgentAction(agent_id="heidi", action_type="read_database")
        ])

    discovery = CapabilityDiscovery(min_samples=3, eps=0.5)
    results = discovery.discover(traces)

    print("\n🧩 Capability Discovery Results")
    print(f"Total capabilities discovered: {len(results)}")

    for i, cap in enumerate(results, 1):
        classification = cap.get('classification', {})
        cap_name = classification.get('name', cap['capability_name'])
        severity = classification.get('severity', 'unknown')
        print(f"\nCapability {i}: {cap_name} (severity: {severity})")
        print(f"  Classification: {classification.get('classification', 'unknown')}")
        print(f"  Confidence: {cap['confidence']:.4f}")
        print(f"  Occurrences: {cap['occurrence_count']}")
        print("  Required Actions:")
        for act in cap['required_actions']:
            print(f"    {act['agent']} -> {act['action']}")
        if cap.get('counterfactual_proof'):
            cf = cap['counterfactual_proof'][0]
            print(f"  Counterfactual (remove {cf['removed_agent']}):")
            print(f"    Capability still exists: {cf['capability_still_exists']}")
        print(f"  Witness Hash: {cap['witness']['witness_hash']}")

if __name__ == "__main__":
    main()