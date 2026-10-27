---
title: Governable Autonomy Three-Minute Demo Script
last_reviewed: 2026-10-15
owner: agt-maintainers
---

# Governable autonomy: 2 minute 45 second demo

Prepare the environment using the [README](README.md). Increase terminal font
size and run `python examples/humanoid-action-governed/demo.py --clear` from the
repository root with the virtual environment active. Six Enter presses advance
through seven beats. Each screen waits for you; there are no automatic animations.

| Time | Screen / action | Say |
|------|-----------------|-----|
| 0:00–0:15 | Initial mission | "This humanoid has one job: deliver a parts tray to inspection. The robot and planner are simulated. AGT policy, approvals and cryptographic checks run live on this laptop." |
| 0:15–0:40 | Enter: motion-only baseline | "A poisoned job card redirects the tray to visitor pickup. The route, speed and empty work zone pass this simulated motion-safety gate. The wrong delivery happens. Mechanically admissible does not mean authorized." |
| 0:40–1:05 | Enter: identical request through AGT | "Now the same agent proposes the same action through AGT. Its signature is valid. But identity does not grant unlimited authority. AGT denies the unauthorized destination before the controller is called." |
| 1:05–1:25 | Enter: legitimate request | "Return to the assigned task. The policy requires human approval. Pending approval means no dispatch. The next Enter is my explicit approval using a local demo identity." |
| 1:25–1:50 | Enter: approve, then substitute | "I approve inspection. Now change the destination after approval. AGT checks the exact action digest and rejects the substitution. The approval cannot be redirected." |
| 1:50–2:15 | Enter: execute, then replay | "The original action passes governance and the independent motion gate. One delivery to inspection. Reuse the approval: rejected. One approval cannot produce a second move." |
| 2:15–2:45 | Enter: verify evidence | "The signed records verify. Alter a copy of the recorded controller result: verification fails. This proves what trusted demo software recorded, not a real physical outcome. Motion safety constrains movement; agent governance constrains authority, preserves oversight and makes decisions inspectable." |

The main message: **AGT adds control over what an autonomous agent is allowed to
do, beyond the motion constraints represented in the baseline.** The example
does not suggest that policy approval establishes physical safety or that all
existing robot safety systems lack authorization features.

If interrupted, skip the parameter-substitution explanation and proceed to the
authorized move and verification. Keep the first comparison: it establishes why
agent governance adds a distinct control.

For rehearsal, use `--all` without `--clear`. For an exported transcript of the
actual run, redirect that output to a file under `artifacts/`; the signed JSON
export is separate. If a test or evidence check fails, stop and investigate
rather than describing the run as successful.
