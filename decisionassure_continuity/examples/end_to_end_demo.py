#!/usr/bin/env python3
"""End‑to‑End Capability Pipeline: Discovery → Classification → Witness → Counterfactual → Replay"""

from src.models import AgentAction
from src.capability_discovery import CapabilityDiscovery
from src.capability_replay import CapabilityReplay

def main():
    # 1. Generate synthetic traces (100 traces with repeating patterns)
    traces = []
    # Pattern A: Credential Exfiltration (50 traces)
    for _ in range(50):
        traces.append([
            AgentAction(agent_id="alice", action_type="read_database"),
            AgentAction(agent_id="bob", action_type="read_credentials"),
            AgentAction(agent_id="charlie", action_type="export_data")
        ])
    # Pattern B: Privilege Escalation (30 traces)
    for _ in range(30):
        traces.append([
            AgentAction(agent_id="david", action_type="grant_permission"),
            AgentAction(agent_id="eve", action_type="write_config"),
            AgentAction(agent_id="frank", action_type="delete_logs")
        ])
    # Pattern C: Noise (20 traces)
    for _ in range(20):
        traces.append([
            AgentAction(agent_id="grace", action_type="read_database"),
            AgentAction(agent_id="heidi", action_type="read_database")
        ])

    print("📊 Step 1: Discovery")
    discovery = CapabilityDiscovery(min_samples=5, eps=0.5)
    discovered = discovery.discover(traces)
    print(f"   Found {len(discovered)} capabilities.")

    # 2. Pick the first discovered capability for replay
    if discovered:
        cap = discovered[0]
        print("\n📋 Step 2: Classification")
        print(f"   Capability: {cap['capability_name']}")
        print(f"   Classification: {cap['classification']}")
        print(f"   Severity: {cap['severity']}")
        print(f"   Match Confidence: {cap['match_confidence']:.4f}")

        # 3. Replay
        print("\n🔁 Step 3: Replay Verification")
        # Convert required actions to the format expected by replay
        replay_actions = [{"agent": a["agent"], "action": a["action"]} for a in cap["required_actions"]]
        replay = CapabilityReplay()
        result = replay.replay(replay_actions)
        if result["verification"] == "verified":
            print("   ✅ Replay: VERIFIED")
            print(f"   Witness Hash: {result['witness']['witness_hash']}")
            for cf in result["counterfactual"]:
                print(f"   Counterfactual (remove {cf['removed_agent']}): exists={cf['capability_still_exists']}")
        else:
            print("   ❌ Replay: NOT VERIFIED")
    else:
        print("   No capabilities discovered.")

if __name__ == "__main__":
    main()