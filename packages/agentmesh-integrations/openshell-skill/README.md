# OpenShell + AgentMesh Governance Skill

**Public Preview** - Governance skill bringing AGT capabilities into NVIDIA OpenShell sandboxes.

OpenShell provides the **walls** (Landlock, seccomp, OPA proxy). This skill provides the **brain** (policy, trust, audit).

## Install

```bash
pip install openshell-agentmesh
```

## Quick Start

```python
from openshell_agentmesh import GovernanceSkill

skill = GovernanceSkill(policy_dir="./policies")
decision = skill.check_policy("shell:python test.py")
print(decision.allowed)  # True

decision = skill.check_policy("shell:rm -rf /tmp")
print(decision.allowed)  # False
```

## Related

- [OpenShell Integration Guide](../../docs/integrations/openshell.md)
- [Runnable Example](../../examples/openshell-governed/)
- [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell)
