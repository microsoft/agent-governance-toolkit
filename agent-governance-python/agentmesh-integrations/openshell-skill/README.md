# OpenShell + AgentMesh Governance Skill

**Public Preview** - Governance skill for NVIDIA OpenShell sandboxes.
OpenShell = walls (Landlock, seccomp, OPA). This skill = brain (policy, trust, audit).

## Install

```bash
pip install openshell-agentmesh
```

## Quick Start

```python
import subprocess

from openshell_agentmesh import GovernanceSkill, governed_shell

skill = GovernanceSkill(policy_dir="./policies")
decision = skill.check_policy("shell:python test.py")
print(decision.allowed)  # True

with governed_shell(skill):
    subprocess.run(["python", "test.py"], check=True)
```

`governed_shell()` is opt-in and scoped. While active, `subprocess.run`,
`subprocess.Popen`, `os.system`, and `os.popen` are checked against policy before
execution. Denied commands raise `ShellPolicyViolation` and are not executed.

For persistent audit records, pass a JSONL path:

```python
skill = GovernanceSkill(policy_dir="./policies", audit_path="./audit/openshell.jsonl")
```

## Related

- [OpenShell Integration Guide](../../../docs/integrations/openshell.md)
- [Runnable Example](../../../examples/openshell-governed/)
- [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell)
