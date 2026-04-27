<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# External Operation-Accountability Profiles

This note describes a documentation-only interoperability pattern for
referencing Agent Governance Toolkit runtime evidence from an external
operation-accountability profile.

It is not an AGT runtime feature, plugin, evidence schema, or verifier
replacement.

## Purpose

AGT provides runtime governance for agent actions, including policy enforcement,
identity, sandboxing, audit material, and runtime evidence verification.

Some downstream environments may need to reference runtime evidence from an
external accountability object. For example, evidence may be exchanged across
organizations, attached to a data-space transaction, or included in a larger
evidence package.

In that setting, AGT runtime evidence can be treated as upstream evidence
material for a downstream accountability statement.

## Scope

This pattern is documentation-only.

AGT remains responsible for runtime governance. AGT evidence verification
remains available through AGT mechanisms. The external profile does not change
AGT runtime behavior.

AGT evidence, receipts, audit records, or decision records are referenced as
evidence artifacts.

## Non-goals

- changes to AGT runtime governance
- changes to AGT policy enforcement
- changes to AGT identity mechanisms
- changes to AGT sandboxing
- replacement of `agt verify --evidence`
- a required dependency on an external validator
- an official AGT evidence schema change
- a new AGT runtime contract

## Relationship to AGT Evidence Verification

AGT evidence verification and external operation-accountability validation
answer different questions.

AGT evidence verification checks AGT governance evidence within the AGT
runtime-governance model.

An external operation-accountability profile checks whether a downstream
accountability statement is structurally complete and independently reviewable.
Such a statement may reference AGT runtime evidence as supporting material, but
it does not replace AGT evidence verification.

## Security and Responsibility Boundaries

External operation-accountability profiles are not AGT runtime features and are
not AGT evidence-verification mechanisms.

Before AGT runtime evidence is referenced from an external accountability
statement, users should verify the authenticity and integrity of that evidence
using the appropriate AGT verification mechanisms, where applicable. External
profile validation should not be used as a substitute for AGT evidence
verification.

External mapping adapters, validators, storage systems, and downstream
registries are outside the AGT runtime trust boundary. Users are responsible
for securing those components, including their signing keys, dependency chain,
transport path, and validation environment.

Third-party reference implementations should be treated as examples only. Users
should audit any external implementation and its dependencies before using it in
production or compliance-sensitive environments.

For AGT-specific receipt and evidence-verification concepts, see
[Tutorial 33 — Offline-Verifiable Decision Receipts](../tutorials/33-offline-verifiable-receipts.md).

## Mapping Concept

| AGT-side concept | External accountability concept |
|---|---|
| Agent identity | Actor |
| Governed action or tool call | Operation |
| Resource or object acted on | Subject |
| Policy decision | Policy / constraints |
| Runtime evidence, audit material, receipt, or decision record | Evidence artifact |
| Input/output resources | Evidence references |
| AGT runtime context | Provenance context |
| External validator output | Validation report |

## Example Pipeline

```text
AGT runtime evidence
-> external mapping adapter
-> operation-accountability statement
-> independent profile validation
-> validation report
```

This pipeline is intended for interoperability and downstream accountability.
It is not part of the AGT runtime path.

## Example Reference Implementation

- Repository: https://github.com/joy7758/agent-evidence
- Prototype path: https://github.com/joy7758/agent-evidence/tree/v0.1-agt-interop-examples/demos/integrations/agt
- Cookbook: https://github.com/joy7758/agent-evidence/blob/v0.1-agt-interop-examples/demos/docs/cookbooks/agt_to_eeoap_v0_1.md
- Related issue: https://github.com/microsoft/agent-governance-toolkit/issues/1314

The prototype uses a synthetic AGT-like fixture. It is not an official AGT
evidence schema.

## Review Note

This note is intended as an interoperability discussion starter. It does not
require AGT maintainers to adopt the external profile, and it does not create a
compatibility commitment.
