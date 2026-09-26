---
title: OpenShell integration
last_reviewed: 2026-09-23
owner: docs-team
---

# OpenShell integration

> **Status:** The v5 ACS migration retired the OpenShell-specific
> `GovernanceSkill` library, and the adapter is currently absent. This page
> preserves the migration guidance and the former documentation route for
> existing integrations.

## Govern an OpenShell-hosted agent

Use the Agent Control Specification (ACS) runtime to load a manifest and
evaluate intervention points in the application that hosts the OpenShell
sandbox.

```bash
pip install agent-control-specification
```

```python
from agent_control_specification import AgentControl

control = AgentControl.from_path("policies/agt-manifest.yaml")
```

See the [Agent Control Specification package guide](../packages/agent-control-specification.md)
for the current runtime and policy-authoring guidance.

## Migrating from the retired governance skill

### Option A: Governance Skill Inside the Sandbox (Python Library)

The v5 `openshell-agentmesh` package is retained only for compatibility.
Importing `openshell_agentmesh` emits a `DeprecationWarning`; the v5 package
does not provide the `GovernanceSkill`, `ShellPolicyViolation`, or
`governed_shell` APIs. [Pull request #3728](https://github.com/microsoft/agent-governance-toolkit/pull/3728)
proposes restoring the adapter and remains under review. Until that change
merges, replace the integration with an ACS manifest and host-level
intervention-point evaluation.

The ACS runtime is the v5 migration path for applying governance to an agent
hosted in an OpenShell sandbox.

## Related guidance

- [V4 policy language removal and migration guidance](../v4-removal.md)
- [Agent Control Specification package guide](../packages/agent-control-specification.md)
