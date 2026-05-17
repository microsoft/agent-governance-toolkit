# Copyright (c) Microsoft Corporation. Licensed under the MIT License.

# RFC Process

This document describes how major changes to the Agent Governance Toolkit
are proposed, reviewed, and accepted.

## When is an RFC required?

An RFC is required for any change that:

- Adds or removes a public API surface (new classes, method signatures)
- Introduces a new package or framework integration
- Changes the security model, trust boundaries, or cryptographic choices
- Modifies the policy engine, privilege rings, or delegation chains
- Affects backward compatibility or requires a migration path

An RFC is **not** required for:

- Bug fixes
- Documentation improvements
- Test additions
- Dependency updates
- Internal refactoring that preserves the public API

## Lifecycle

```
Draft → Under Review → Accepted / Rejected → Implemented → Closed
```

| Stage | Description |
|-------|-------------|
| **Draft** | Author opens an RFC issue using the template. |
| **Under Review** | Maintainers add the `rfc:review` label. Community discussion happens on the issue. Minimum review period is 7 days. |
| **Accepted** | Maintainers add `rfc:accepted`. An ADR is created to record the decision. Implementation work begins. |
| **Rejected** | Maintainers add `rfc:rejected` with a rationale comment. Issue is closed. |
| **Implemented** | Implementation PRs reference the RFC. Once merged, the RFC issue is closed. |

## How to write a good RFC

1. **Start with the problem.** Explain what is broken or missing today.
2. **Show the API.** Include concrete code examples, type signatures, and
   data models.
3. **Address security.** AGT is a governance framework. Every RFC must
   consider how it affects the trust model and attack surface.
4. **Consider alternatives.** Show what else you evaluated and why you
   chose this approach.
5. **Plan the migration.** If this is a breaking change, describe the
   deprecation path.

## Relationship to ADRs

RFCs capture the proposal and discussion. Once accepted, the decision is
recorded as an [Architecture Decision Record](../adr/index.md) (ADR) for
long-term reference. The ADR links back to the RFC issue.

## Review expectations

- Maintainers aim to provide initial feedback within 5 business days.
- RFCs with security implications require sign-off from at least two
  maintainers.
- Community members are encouraged to comment, ask questions, and
  propose amendments.
