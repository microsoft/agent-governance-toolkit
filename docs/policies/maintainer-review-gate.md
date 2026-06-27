# Maintainer review gate

The maintainer review gate is a policy signal for pull requests that still need an approving review from a maintainer. It exists because PRs #357 and #362 reintroduced security issues when they were auto-merged without human maintainer review.

## Who counts as a maintainer

A maintainer is resolved from native repository RBAC: any collaborator whose effective permission is `Maintain` or `Admin`. There is no hardcoded name list — granting or revoking the `Maintain` role is the single source of truth, and it is read live by the workflow on each run.

## When the gate fires

The gate fires when a PR does not yet have an `APPROVED` review from a maintainer. The review must come from a human collaborator (`type === 'User'`) who is not the PR author. AI-only approvals, bot/service-account approvals, and the author's own approval do not satisfy the gate.

## Why this is not a CI failure

A red result from this workflow means the PR is awaiting policy review. It is not a test, build, lint, or dependency failure. The workflow is intentionally labeled as a policy gate so contributors know the next action is review, not debugging CI.

## How to satisfy it

Request a review from a maintainer. Once a maintainer with the `Maintain` (or `Admin`) role submits an approving review, the workflow re-runs on the review event and reports success.

## Merge-blocking enforcement

Merge-blocking enforcement comes from the repository branch-protection ruleset, which requires a pull request with an approving review and restricts who may merge or bypass. This workflow adds the maintainer-specific signal on top of that native requirement.
