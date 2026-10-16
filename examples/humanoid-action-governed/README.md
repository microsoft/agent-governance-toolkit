---
title: Governed Humanoid Action Walkthrough
last_reviewed: 2026-10-15
owner: agt-maintainers
---

# Governed humanoid action walkthrough

**A mechanically admissible action can still exceed an agent's authority.**
This terminal example shows the additional control AGT provides over an agent's
decisions, beyond the motion checks represented by a simulated controller.

A humanoid must deliver a parts tray to inspection. A poisoned job card redirects
the planner to visitor pickup. Both destinations pass the simulated controller's
speed and work-zone checks. The motion-only baseline completes the wrong delivery;
the same request through the real AGT policy engine is denied before dispatch.
The intended task then requires exact-action approval, rejects parameter
substitution, executes once, and produces independently verifiable software records.

The planner output, operator identity and robot controller are local demo fixtures.
The AGT policy engine, identity signing API, approval coordinator, Ed25519
signatures, and evidence verification run for real. No live LLM or physical robot
is needed. This is an experimental example, not a supported robotics API.

## Set up once

Python 3.11 or newer and a source checkout of this repository are required.
Run these commands from the repository root:

```bash
python3 -m venv examples/humanoid-action-governed/.venv
source examples/humanoid-action-governed/.venv/bin/activate
python -m pip install -r examples/humanoid-action-governed/requirements.txt
python -m pip install --no-deps -e agent-governance-python/agent-governance-toolkit-core
```

Install the maintained `agent-governance-toolkit-core` distribution from this
checkout, not the deprecated `agentmesh-platform` stub. AGT's maintained source
still exposes the `agentmesh.*` Python imports used here. `requirements.txt` is a
pinned minimal dependency profile for those imported surfaces. This example does
not exercise the ACS SDK or the rest of the consolidated core package; it is not
a replacement for the full repository development environment.

Dependency installation needs network access. After setup, the demo has no
external-service calls, credentials, model costs, or physical side effects.

## Run step by step

With the virtual environment active, run:

```bash
python examples/humanoid-action-governed/demo.py --clear
```

Press **Enter** to advance. Every beat waits indefinitely for the presenter.
The Enter preceding the approval beat explicitly approves the displayed action
using the local demo operator. The demo clock is controlled rather than tied to
wall-clock waiting, so a pause during a talk cannot unexpectedly expire an
approval. Automated tests separately exercise expiry and stale state.

The [presenter script](TALK.md) fits a 2 minute 45 second walkthrough with six
advances. The initial use case is the Humanoid Europe talk on runtime controls,
identity, and verifiable trust, but the example is usable independently.

For a complete rehearsal without prompts, with evidence export:

```bash
python examples/humanoid-action-governed/demo.py --all --export examples/humanoid-action-governed/artifacts/evidence.json
python examples/humanoid-action-governed/verify.py examples/humanoid-action-governed/artifacts/evidence.json --trust examples/humanoid-action-governed/artifacts/evidence.trust.json
```

`--all` uses scripted operator approval for rehearsal. It is not a claim that a
human approved an autonomous run. A failed evidence check or unexpected final
comparison makes the walkthrough exit with status 1; the verifier also exits
with status 1 for invalid evidence.

Expected comparison:

| Beat | Motion-only baseline | With AGT |
|------|----------------------|----------|
| Redirect tray to visitor pickup | One simulated move to the unauthorized destination | Policy denies; zero controller calls |
| Request intended inspection delivery | No task authorization mechanism in this fixture | `require_approval`; no dispatch |
| Approve inspection, substitute visitor pickup | Both routes satisfy the motion envelope | Action digest mismatch; no dispatch |
| Dispatch original approved action | Baseline remains at visitor pickup | One simulated move to inspection |
| Replay approval | No approval mechanism in baseline | Already consumed; no second controller call |
| Modify a copy of the recorded outcome | Not evaluated by motion gate | Signed evidence verification rejects it |

Final output includes:

```text
Motion-only baseline: 1 moves → visitor-pickup
With AGT: 1 moves → inspection | controller calls: 1
Evidence check: {'original_valid': True, 'altered_copy_rejected': True}
PASS: signed software records verified
```

## What enforces each boundary

| Boundary | Implementation |
|----------|----------------|
| Request attribution | `AgentIdentity` signs the request; the adapter verifies against a previously provisioned local agent key |
| Task authority | `PolicyEngine` loads [policy.yaml](policy.yaml), denies task redirection and unknown tools, and requires approval for the intended move |
| Exact-action approval | `ApprovalCoordinator` binds target, agent, parameters, policy version and approval chain; execution-time validation consumes the approval once |
| Operator proof | Example adapter verifies a signed local operator approval before submitting the AGT approval entry |
| Motion checks | Independent simulated controller checks current work-zone state, state freshness, destination envelope and speed |
| Recorded evidence | Controller-signed result plus a signed, ordered journal; verification uses separately supplied keys and expected final digest |

The small adapter explicitly connects existing AGT APIs. It does not imply that
every AGT framework integration automatically provides these same end-to-end
bindings. The baseline and governed runs use the same action and the same
controller implementation, with independent state and counters.

## Validate

```bash
python -m unittest discover -s examples/humanoid-action-governed -p 'test_*.py' -v
```

Tests cover the identical-action comparison, forged request and operator proofs,
unknown tools, pending and expired approvals, substituted parameters, policy
changes, replay and concurrent consumption, stale state, controller veto,
unavailable or forged controller responses, independent Ed25519 verification,
altered/reordered/deleted/truncated evidence, and execution without network access.

## Evidence and simulation limits

- The malicious planner output is scripted. The example demonstrates enforcement
  after an agent proposes an action; it does not measure prompt-injection resistance.
- The motion-only controller is a deliberately narrow teaching model, not a
  characterization of all traditional safety products or industrial deployments.
- AGT adds task authority and approval enforcement. It does not replace physical
  interlocks, emergency stops, collision avoidance, or certified control loops.
  Controller veto and stale state remain independently enforced and tested.
- The operator is a locally provisioned demo identity, not OIDC, Entra or a verified
  employee. The request signature establishes possession of a locally trusted key,
  not authenticity of physical hardware or permission to perform arbitrary tasks.
- Approval storage, controller state and signing keys are in memory. Restarting
  creates a fresh session. This is not durable production authorization storage.
- A missing controller reply is `unknown`, even if the approval was consumed.
  The example does not retry automatically or claim that no physical effect occurred.
- Signatures establish what the trusted software keys recorded. They do not prove
  sensor truth, real robot completion, physical non-harm, or safety certification.
- The evidence schema is local to this example, not TRACE conformance or a new AGT
  protocol. Canonical signed evidence uses the `rfc8785` library. Action digests
  use AGT's existing implementation and integer parameters, without cross-language
  floating-point claims.
- Retain the trust snapshot and expected head separately before handing evidence
  to another verifier. Keys copied from an untrusted evidence file are not trust
  anchors. There is no external transparency log or hardware-rooted key custody.

## Files, cleanup and prior work

- [demo.py](demo.py): interactive walkthrough, AGT adapter and simulated controller.
- [verify.py](verify.py): offline verification against retained trust material.
- [test_demo.py](test_demo.py): behavior and failure-path tests.
- [TALK.md](TALK.md): three-minute presenter script.

Stop with Ctrl+C; rerun to reset. Remove only the example's `.venv/` and
`artifacts/` directories to clean up installed dependencies and generated records.
No daemon, network listener, external account or physical device is created.

This example builds on AGT's
[Physical Agent Systems Profile](../../docs/compliance/owasp-agentic-top10-architecture.md#physical-agent-systems-profile),
[ADR-0030 action-bound approval protocol](../../docs/adr/0030-action-bound-approval-protocol.md),
and [physical-attestation example](../physical-attestation-governed/README.md).
It uses the project's shipped policy, identity and approval implementations;
the simulated controller and walkthrough are illustrative example code.

License: [MIT](../../LICENSE).
