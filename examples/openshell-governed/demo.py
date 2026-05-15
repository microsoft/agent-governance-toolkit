# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Demo: AGT policy enforcement inside an OpenShell sandbox.

Run with:
    pip install openshell-agentmesh
    python examples/openshell-governed/demo.py
"""
from pathlib import Path

from openshell_agentmesh.skill import GovernanceSkill


SCENARIOS = [
    ("file:read:/workspace/main.py", "Read source file"),
    ("shell:python", "Run Python"),
    ("shell:git", "Git commit"),
    ("shell:rm -rf /tmp", "Delete temp data"),
    ("http:GET:169.254.169.254/metadata", "Cloud metadata"),
    ("file:write:/etc/shadow", "Write /etc/shadow"),
]


def main():
    print("=" * 60)
    print("   Governed AI Agent in OpenShell Sandbox")
    print("=" * 60)

    skill = GovernanceSkill(policy_dir=Path(__file__).parent / "policies")
    agent = "did:mesh:sandbox-agent-001"

    print(f"\n  Loaded {len(skill._rules)} rules | Agent: {agent} (trust: {skill.get_trust_score(agent):.2f})")
    print("-" * 60)

    for action, desc in SCENARIOS:
        d = skill.check_policy(action, context={"agent_did": agent})
        if not d.allowed:
            skill.adjust_trust(agent, -0.15)
        icon = "[OK]" if d.allowed else "[XX]"
        print(f"  {icon} {desc:<28} trust={skill.get_trust_score(agent):.2f}  {d.reason}")

    log = skill.get_audit_log()
    allowed_count = sum(1 for e in log if e["decision"] == "allow")
    print(f"\n  Audit: {allowed_count} allowed, {len(log) - allowed_count} denied | Final trust: {skill.get_trust_score(agent):.2f}")
    print("=" * 60)


if __name__ == "__main__":
    main()
