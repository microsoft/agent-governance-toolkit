# External ACS Guardian falsification with SCQOS

This example shows how to test an external **Agent Control Standard (ACS) Guardian** beside Microsoft Agent Governance Toolkit (AGT) without asking anyone to simply trust a product claim.

## The idea in plain English

An AI agent asks to do something.

A Guardian decides whether that exact action should be allowed, denied, deferred, modified, or sent for approval.

A serious test should not stop at **"the Guardian returned the right answer."** It should also verify whether the real bounded action actually happened, whether a blocked action stayed blocked, whether replay was rejected, and whether another engineer can reproduce the evidence.

The testing circuit is:

```text
same ACS request
      |
      +--> AGT / reference Guardian
      |
      +--> external Guardian
                |
                v
       compare each result to
       the pinned ACS requirement
                |
                v
       inspect the real effect
                |
                v
       preserve reproducible evidence
```

The **ACS requirement is the oracle**. One Guardian is not treated as correct merely because it disagrees with another.

## Why falsification matters

A weak test can accidentally reward a system that always allows, always denies, ignores signatures, ignores replay, skips tests, or simply reports "success."

A stronger test deliberately introduces those broken behaviors and proves the harness catches them.

That changes the question from:

> Can this implementation produce a green demo?

to:

> Can another engineer reproduce the same inputs, attack the same assumptions, inspect the same side effects, and still obtain the same result?

## Public worked example: SCQOS

The public **SCQOS ACS Falsification Lab** is one independently implemented example of this pattern:

https://github.com/KnowledgeeKZA3224/scqos-acs-falsification-lab

Its published initial run records:

- **20/20 SCQOS laboratory probes passed** against the live SCQOS decision substrate.
- **All 6 deliberately broken harness conditions were detected**: allow-everything, deny-everything, signature-blind, replay-blind, fake-success, and skipped-test execution.
- A controlled cloud-to-terminal consequence proof verified that:
  - an authorized write occurred;
  - a wrong-authority write did not occur;
  - the first valid replay-target execution occurred once;
  - the duplicate request was rejected;
  - the target SHA-256 remained unchanged after the rejected replay.

Those statements describe the **published pinned run only**.

They are **not** a Microsoft certification, an OWASP certification, or a claim that either implementation is defect-free.

## Reproduce the external run

```bash
git clone https://github.com/KnowledgeeKZA3224/scqos-acs-falsification-lab.git
cd scqos-acs-falsification-lab
./scripts/bootstrap.sh
./scripts/verify-everything.sh
```

The lab writes machine-readable evidence under `run-evidence/`.

## How to read a result

A green result means the exact pinned implementation, exact pinned ACS revision, exact probes, and exact recorded environment behaved as documented for that run.

A green result does **not** mean:

- universally secure;
- automatically correct for future ACS revisions;
- certified by Microsoft or OWASP;
- correct merely because another Guardian disagreed.

The useful output is the evidence itself: inputs, decisions, side effects, failures, hashes, and enough information for another engineer to challenge the result.

## Scope

This contribution is documentation/example material only. It does not change AGT runtime behavior, security defaults, public APIs, package dependencies, or production code.

## Prior art and related projects

- Microsoft Agent Governance Toolkit: https://github.com/microsoft/agent-governance-toolkit
- OWASP / GenAI Security Project Agent Control Standard: https://github.com/GenAI-Security-Project/agent-control-standard
- SCQOS reference implementation: https://github.com/KnowledgeeKZA3224/scqos-reference-implementation
- SCQOS ACS Falsification Lab: https://github.com/KnowledgeeKZA3224/scqos-acs-falsification-lab

SCQOS is an independent external project. This example does not make it a Microsoft-supported component and does not add SCQOS as an AGT dependency.
