---
title: Specification Change Process
last_reviewed: 2026-06-05
owner: spec-maintainers
---

# Specification change process

AGT specifications define normative behavior for policy evaluation, identity,
trust, audit, MCP governance, framework adapters, and runtime controls. They are
not ordinary documentation pages.

Use this process for changes that alter observable behavior, interoperability,
wire formats, policy decision semantics, conformance requirements, or security
contracts.

## When a spec change is required

Open a spec change when a pull request:

- adds, removes, or changes a `MUST`, `MUST NOT`, `SHOULD`, or `SHOULD NOT`;
- changes policy input, verdict, audit, receipt, identity, trust, or MCP
  governance schemas;
- changes cross-SDK behavior or conformance expectations;
- introduces a breaking change or migration requirement;
- changes security boundaries, fail-closed behavior, or authorization semantics.

Use a normal pull request for typo fixes, examples, non-normative explanations,
or editorial clarification that does not change behavior.

## Required sections

Normative spec changes must include:

| Section | Required content |
|---|---|
| Motivation | Why the current spec is insufficient. |
| Specification | Exact behavior, schema, or contract change. |
| Backward compatibility | Whether existing users or SDKs break. |
| Security implications | New risks, mitigations, and trust-boundary effects. |
| Reference implementation | Code path or PR that implements the behavior. |
| Conformance plan | Tests or fixtures proving implementations match the spec. |
| Alternatives rejected | Named alternatives and why they were not chosen. |

## Review and ownership

Spec changes require review from a Spec Maintainer listed in
[`OWNERS.md`](../../OWNERS.md). CODEOWNERS protects `docs/specs/`, `docs/adr/`,
and policy-engine spec paths so normative changes receive explicit review.

## Conformance requirement

If a spec change alters observable behavior, it must add or update conformance
coverage before the spec is considered final. The conformance update should map
normative statements to checks or explicitly document why a statement is not
machine-testable.

Examples of observable behavior:

- policy verdict normalization;
- fail-closed runtime errors;
- MCP tool governance decisions;
- identity proof-of-possession checks;
- audit event shape or hash-chain behavior;
- SDK parity requirements.

## Status labels

Use these statuses in spec PRs and related ADRs:

| Status | Meaning |
|---|---|
| Proposed | Design is under review and not a shipped guarantee. |
| Accepted | Maintainers approved the design; implementation or conformance may still be pending. |
| Final | Implementation and required conformance coverage are merged. |
| Superseded | Replaced by a newer spec or ADR. |
| Deprecated | Still present for compatibility but no longer recommended. |

## Relationship to ADRs

ADRs record design decisions and tradeoffs. Specs define stable behavior. A
large change may need both:

1. ADR for the decision and alternatives.
2. Spec update for the normative contract.
3. Conformance update for observable behavior.

Small normative changes can update a spec directly if the motivation,
compatibility, security, and conformance sections are included in the pull
request.
