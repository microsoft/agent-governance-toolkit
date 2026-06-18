#!/usr/bin/env python3
"""
Context-Aware Capability Detection Demo.
Demonstrates how context distinguishes malicious vs legitimate.
"""

from src.capability_replay import CapabilityReplay

def main():
    replay = CapabilityReplay()

    # Scenario 1: Malicious exfiltration
    print("🔴 Scenario 1: Malicious (no context)")
    malicious_actions = [
        {"agent": "alice", "action": "read_database"},
        {"agent": "bob", "action": "read_credentials"},
        {"agent": "charlie", "action": "export_data"}
    ]
    result1 = replay.replay(malicious_actions)
    print(f"  Capability: Credential Exfiltration")
    print(f"  Intent: {result1['intent']}")
    print(f"  Severity: {result1['severity']}")
    print(f"  Decision: {result1['decision']}")
    print(f"  Verified: {result1['verification']}")

    # Scenario 2: Legitimate backup workflow
    print("\n🟢 Scenario 2: Legitimate backup workflow")
    legitimate_actions = [
        {"agent": "backup_service", "action": "read_database"},
        {"agent": "backup_service", "action": "read_credentials"},
        {"agent": "backup_service", "action": "export_data"}
    ]
    context = {"workflow_type": "backup", "authorization": "approved", "schedule": "daily"}
    result2 = replay.replay(legitimate_actions, context)
    print(f"  Capability: Credential Exfiltration Pattern")
    print(f"  Intent: {result2['intent']}")
    print(f"  Severity: {result2['severity']}")
    print(f"  Decision: {result2['decision']}")
    print(f"  Verified: {result2['verification']}")

    print("\n📌 Final distinction:")
    print("   Scenario 1 → Capability: Credential Exfiltration, Intent: Malicious, Decision: DENY")
    print("   Scenario 2 → Capability: Credential Exfiltration Pattern, Intent: Legitimate, Decision: MONITOR")

if __name__ == "__main__":
    main()