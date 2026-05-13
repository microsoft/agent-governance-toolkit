# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "agent-governance-python" / "agentmesh-integrations" / "openshell-skill"))
from openshell_agentmesh.skill import GovernanceSkill

def main():
    print("=" * 60)
    print("   Governed AI Agent in OpenShell Sandbox")
    print("=" * 60)
    skill = GovernanceSkill(policy_dir=Path(__file__).parent / "policies")
    agent = "did:mesh:sandbox-agent-001"
    print(f"\n  Loaded {len(skill._rules)} rules | Agent: {agent} (trust: {skill.get_trust_score(agent):.2f})")
    print("-" * 60)
    for action, desc in [("file:read:/workspace/main.py","Read source file"),("shell:python","Run Python"),("shell:git","Git commit"),("shell:rm -rf /tmp","Delete temp data"),("http:GET:169.254.169.254/metadata","Cloud metadata"),("file:write:/etc/shadow","Write /etc/shadow")]:
        d = skill.check_policy(action, context={"agent_did": agent})
        if not d.allowed: skill.adjust_trust(agent, -0.15)
        icon = "[OK]" if d.allowed else "[XX]"
        print(f"  {icon} {desc:<28} trust={skill.get_trust_score(agent):.2f}  {d.reason}")
    log = skill.get_audit_log()
    a = sum(1 for e in log if e["decision"] == "allow")
    print(f"\n  Audit: {a} allowed, {len(log)-a} denied | Final trust: {skill.get_trust_score(agent):.2f}")
    print("=" * 60)

if __name__ == "__main__": main()
