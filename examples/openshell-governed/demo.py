# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Governed AI Agent in OpenShell Sandbox — Demo.

Demonstrates the Agent Governance Toolkit providing policy enforcement,
trust scoring, and audit logging inside an NVIDIA OpenShell sandbox.

Usage:
    pip install agentmesh-platform   # optional, works without it too
    python demo.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Add the skill package to path for standalone use
_skill_dir = Path(__file__).resolve().parent.parent.parent / "packages" / "agentmesh-integrations" / "openshell-skill"
if _skill_dir.exists():
    sys.path.insert(0, str(_skill_dir))

from openshell_agentmesh.skill import GovernanceSkill


def main() -> None:
    print("=" * 60)
    print("   Governed AI Agent in OpenShell Sandbox")
    print("=" * 60)

    # Load policies
    policy_dir = Path(__file__).parent / "policies"
    skill = GovernanceSkill(policy_dir=policy_dir)
    print(f"\n📜 Loaded {len(skill._rules)} governance rules from {policy_dir}")

    agent_did = "did:mesh:sandbox-agent-001"
    print(f"🆔 Agent: {agent_did}  (trust: {skill.get_trust_score(agent_did):.2f})")

    # Simulate agent actions
    actions = [
        ("file:read:/workspace/main.py", "Read source file"),
        ("shell:python", "Run Python tests"),
        ("shell:git", "Git commit"),
        ("shell:rm -rf /tmp/data", "Delete temp data"),
        ("http:GET:169.254.169.254/metadata", "Access cloud metadata"),
        ("file:write:/etc/shadow", "Write to /etc/shadow"),
    ]

    print(f"\n{'─' * 60}")
    print("   Simulating 6 agent actions through governance layer")
    print(f"{'─' * 60}\n")

    for action, description in actions:
        decision = skill.check_policy(action, context={"agent_did": agent_did})

        if decision.allowed:
            icon = "✅"
        else:
            icon = "❌"
            skill.adjust_trust(agent_did, -0.15)

        trust = skill.get_trust_score(agent_did)
        print(f"  {icon} {description:<30} [{action}]")
        print(f"     {'ALLOWED' if decision.allowed else 'DENIED ':>7} — {decision.reason}")
        print(f"     Trust: {trust:.2f}  |  Rule: {decision.policy_name or 'default'}")
        print()

    # Summary
    trust_final = skill.get_trust_score(agent_did)
    log = skill.get_audit_log()
    allowed = sum(1 for e in log if e["decision"] == "allow")
    denied = len(log) - allowed

    print(f"{'─' * 60}")
    print("   📋 Audit Trail Summary")
    print(f"{'─' * 60}")
    print(f"   Total actions:  {len(log)}")
    print(f"   Allowed:        {allowed}")
    print(f"   Denied:         {denied}")
    print(f"   Final trust:    {trust_final:.2f} (started at 1.00)")
    print()

    print("   Recent audit entries:")
    for entry in log:
        icon = "✅" if entry["decision"] == "allow" else "❌"
        print(f"   {icon} {entry['timestamp'][:19]}  {entry['action'][:40]}")

    print(f"\n{'=' * 60}")
    print("   OpenShell provides the sandbox walls.")
    print("   AGT provides the governance brain.")
    print("   Together: defense-in-depth for AI agents.")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
