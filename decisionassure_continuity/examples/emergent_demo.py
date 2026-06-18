#!/usr/bin/env python3
"""Emergent Capability Detection Demo."""

from src.models import AgentAction
from src.emergent_detector import EmergentDetector

def main():
    actions = [
        AgentAction(agent_id="alice", action_type="read_database", tool="sql"),
        AgentAction(agent_id="bob", action_type="read_credentials", tool="vault"),
        AgentAction(agent_id="charlie", action_type="export_data", tool="s3")
    ]

    detector = EmergentDetector()
    results = detector.detect(actions)

    print("\n🧩 Emergent Capability Detection")
    for res in results:
        if res.capability_detected:
            print(f"🚨 Detected: {res.capability.name}")
            print(f"   Confidence: {res.confidence:.4f}")
            print(f"   Agents: {', '.join(res.contributing_agents)}")
        else:
            print("✅ No emergent capability detected.")

if __name__ == "__main__":
    main()