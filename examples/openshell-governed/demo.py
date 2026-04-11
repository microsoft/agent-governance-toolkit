# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Governed AI Agent in OpenShell Sandbox - Demo."""
from __future__ import annotations
import sys
from pathlib import Path

_skill_dir = Path(__file__).resolve().parent.parent.parent / "packages" / "agentmesh-integrations" / "openshell-skill"
if _skill_dir.exists():
    sys.path.insert(0, str(_skill_dir))

from openshell_agentmesh.skill import GovernanceSkill

def main():
    print("=" * 60)
    print("   Governed AI Agent in OpenShell Sandbox")
    print("=" * 60)
    policy_dir = Path(__file__).parent / "policies"
    skill = GovernanceSkill(policy_dir=policy_dir)
    print(f"\n  Loaded {len(skill._rules)} governance rules")
    agent_did = "did:mesh:sandbox-agent-001"
    print(f"  Agent: {agent_did}  (trust: {skill.get_trust_score(agent_did):.2f})")
    actions = [
        ("file:read:/workspace/main.py", "Read source file"),
        ("shell:python", "Run Python tests"),
        ("shell:git", "Git commit"),
        ("shell:rm -rf /tmp/data", "Delete temp data"),
        ("http:GET:169.254.169.254/metadata", "Access cloud metadata"),
        ("file:write:/etc/shadow", "Write to /etc/shadow"),
    ]
    print(f"\n{'-' * 60}")
    for action, desc in actions:
        d = skill.check_policy(action, context={"agent_did": agent_did})
        icon = "ALLOW" if d.allowed else "DENY "
        if not d.allowed:
            skill.adjust_trust(agent_did, -0.15)
        trust = skill.get_trust_score(agent_did)
        print(f"  {'[OK]' if d.allowed else '[XX]'} {desc:<28} trust={trust:.2f}  {d.reason}")
    log = skill.get_audit_log()
    allowed = sum(1 for e in log if e["decision"] == "allow")
    print(f"\n  Audit: {allowed} allowed, {len(log)-allowed} denied, trust={skill.get_trust_score(agent_did):.2f}")
    print("=" * 60)

if __name__ == "__main__":
    main()