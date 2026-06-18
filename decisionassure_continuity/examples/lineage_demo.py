#!/usr/bin/env python3
"""Capability Lineage Demo."""

from src.models import AgentAction
from src.emergent_detector import EmergentDetector

def main():
    actions = [
        AgentAction(agent_id="alice", action_type="read_database", tool="sql", params={"table": "users"}),
        AgentAction(agent_id="bob", action_type="read_credentials", tool="vault", params={"path": "secrets"}),
        AgentAction(agent_id="charlie", action_type="export_data", tool="s3", params={"bucket": "exports"})
    ]

    detector = EmergentDetector()
    results = detector.detect(actions)
    detected = [r for r in results if r.capability_detected]

    if detected:
        res = detected[0]
        print("\n🧩 Capability Lineage:")
        print(f"Capability: {res.capability.name}")
        print(f"Confidence: {res.confidence:.4f}")
        print("\nContributions:")
        for contrib in res.lineage.contributions:
            print(f"  Agent: {contrib.agent}")
            print(f"    Role: {contrib.contribution_type}")
            print(f"    Action: {contrib.action}")
        print(f"\nLineage Hash: {res.lineage.lineage_hash}")
    else:
        print("No emergent capability detected.")

if __name__ == "__main__":
    main()