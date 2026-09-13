---
title: Portable agent skills
last_reviewed: 2026-07-14
owner: docs-team
---

# Portable agent skills

AGT portable skills are Markdown instruction artifacts that can be copied into the skill or
instruction location supported by an agent. They are intentionally host-neutral: AGT does not
assume that every agent discovers `SKILL.md` files automatically or enforces an AGT policy.

## Available skills

| Skill | Purpose |
| --- | --- |
| [AGT policy authoring](agt-policy-authoring/SKILL.md) | Guides an agent to create and validate a minimal AGT policy for the repository it is working in. |

## Installation

Copy the selected `SKILL.md` into the repository-local or user-level skill location documented by
your agent. Keep the file intact so the agent retains its safety requirements and validation flow.
If the agent has no native skill mechanism, add the instructions to its repository guidance file
or provide them as part of the task prompt.

## Runtime boundary

The policy-authoring skill currently targets the schema used by
[`@microsoft/agent-governance-copilot-cli`](../packages/copilot-cli-governance.md). It produces a
repository policy file, but the Copilot CLI runtime does not automatically discover that file. A
user must explicitly validate it and opt in through `AGT_COPILOT_POLICY_PATH` or the policy apply
command. Other agent runtimes need a compatible AGT integration before they can enforce the output.
