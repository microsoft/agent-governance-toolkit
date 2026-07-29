---
title: Workshop Facilitator Notes
last_reviewed: 2026-07-12
owner: docs-team
---

# Workshop Facilitator Notes

## Timing

| Segment | Time |
|---------|------|
| Governance and ACS concepts | 20 minutes |
| Lab 1 native policy | 25 minutes |
| Identity and trust | 15 minutes |
| Lab 2 multi-agent trust | 25 minutes |
| Wrap-up | 5 minutes |

## Before the session

1. Run both lab scripts in the workshop environment.
2. Verify OPA and the native ACS Python SDK are available.
3. Share `prerequisites.md` at least 48 hours before the session.
4. Keep `lab-guide.md` open beside the slides.

## Lab 1

Emphasize the separation between the manifest, Rego policy, runtime, and
session. Ask participants to explain why the tool call is represented as input
to an intervention point rather than as an inline rule object.

Common issues:

- OPA is not on `PATH`.
- The native ACS package is not installed.
- The manifest bundle path was changed without moving the Rego file.

## Lab 2

Emphasize that AgentMesh trust is not policy evaluation. Trust decides who the
peer is and what relationship exists. ACS decides whether the current action is
allowed under the bound policy.

Common issues:

- Participants forget to record reputation events.
- The trust threshold remains above the updated score.
- Revocation is not tested after a successful handshake.

## Closing questions

- Which controls belong in `SandboxConfig`?
- Which state belongs in `AdapterRuntimeSession`?
- Which failures must deny rather than fall back?
- Which audit data may be shown publicly?
