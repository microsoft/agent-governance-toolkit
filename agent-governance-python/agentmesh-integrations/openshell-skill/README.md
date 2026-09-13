# openshell-agentmesh

This compatibility package is deprecated. The OpenShell governance skill
(`GovernanceSkill`, `ShellPolicyViolation`, `governed_shell`) was removed in
the v5 ACS migration and has no OpenShell-specific replacement: importing
`openshell_agentmesh` now only emits a `DeprecationWarning`.

To govern an OpenShell-hosted agent, build an `AgentControl` from an ACS
manifest and evaluate intervention points in the host:

```python
from agent_control_specification import AgentControl

control = AgentControl.from_path("policies/agt-manifest.yaml")
```

See
[BREAKING_CHANGES.md](../../../BREAKING_CHANGES.md)
for the removed-symbols record and migration guidance.
