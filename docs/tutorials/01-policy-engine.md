---
title: Your First ACS Policy
last_reviewed: 2026-07-11
owner: docs-team
---

# Your First ACS Policy

Create a native ACS manifest with a policy, an intervention-point binding, and
the tools the host exposes. Load it through the SDK for your language.

Python hosts use `AgtRuntime.from_manifest(...)`. Node and Rust hosts use
`AgentControl.fromPath(...)` and `AgentControl::from_path(...)`.

Continue with [Agent Control Specification](55-agent-control-specification.md)
for a complete example.
