# Maintainer review gate

The maintainer review gate is a policy signal for pull requests that still need an approving review from a named maintainer. It exists because PRs #357 and #362 reintroduced security issues when they were auto-merged without human maintainer review.

## When the gate fires

For PRs where this workflow applies, the gate fires when the PR does not yet have an `APPROVED` review from a named maintainer listed in the workflow and aligned with CODEOWNERS ownership. The workflow currently applies to PRs whose author association is not `MEMBER` or `OWNER`, so this can include internal contributors who are not classified as members. AI-only approvals and bot approvals do not satisfy the gate.

## Why this is not a CI failure

A red result from this workflow means the PR is awaiting policy review. It is not a test, build, lint, or dependency failure. The workflow is intentionally labeled as a policy gate so contributors know the next action is review, not debugging CI.

## How to satisfy it

Request review from a CODEOWNER for the files changed by the PR. The CODEOWNERS file is at [`../../.github/CODEOWNERS`](../../.github/CODEOWNERS). If a named maintainer list is added at `.github/MAINTAINERS`, use that list as well.

Once a named maintainer approves, rerun or update the PR so the workflow can observe the approval and report success.

## Merge-blocking enforcement

This workflow is a UX signal. The actual merge-blocking enforcement comes from the repository branch-protection `pull_request` ruleset, which requires code-owner review. The required-check snapshot from P0 does not include this workflow as a required check.
