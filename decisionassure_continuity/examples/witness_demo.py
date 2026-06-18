#!/usr/bin/env python3
"""Capability Witness Demo."""

from src.models import AgentAction
from src.capability_witness import CapabilityWitnessEngine

def main():
    actions = [
        AgentAction(agent_id="alice", action_type="read_database", tool="sql"),
        AgentAction(agent_id="bob", action_type="read_credentials", tool="vault"),
        AgentAction(agent_id="charlie", action_type="export_data", tool="s3")
    ]

    engine = CapabilityWitnessEngine()
    witness = engine.generate_witness(actions)

    if witness:
        print("\n🔐 Capability Witness")
        print(f"Capability: {witness.capability_name}")
        print(f"Witness Hash: {witness.witness_hash}")
        print("Required Actions:")
        for act in witness.required_actions:
            print(f"  {act['agent']} -> {act['action']}")
        if witness.counterfactual:
            print(f"\nCounterfactual (remove {witness.counterfactual['removed_agent']}):")
            print(f"  Capability still exists: {witness.counterfactual['capability_still_exists']}")
    else:
        print("No emergent capability detected.")

if __name__ == "__main__":
    main()