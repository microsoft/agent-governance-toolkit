# OpenShell + AgentMesh Governance Skill

**Public Preview** - Governance skill for NVIDIA OpenShell sandboxes.
OpenShell = walls (Landlock, seccomp, OPA). This skill = brain (policy, trust, audit).

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
```

## Related

- [OpenShell Integration Guide](../../../docs/integrations/openshell.md)
- [Runnable Example](../../../examples/openshell-governed/)
- [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell)
