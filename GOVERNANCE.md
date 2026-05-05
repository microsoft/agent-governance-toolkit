# Governance

This document describes the governance model for the Agent Governance Toolkit project.

## Principles

- **Open participation**: Anyone can contribute, report issues, or propose changes.
- **Transparent decision-making**: Architectural decisions are discussed publicly via GitHub Issues and Discussions.
- **Merit-based advancement**: Maintainer roles are earned through sustained, high-quality contributions.
- **Vendor neutrality goal**: The project is working toward multi-organization maintainership to ensure no single vendor controls the project's direction.

## Roles

### Contributor

Anyone who submits a pull request, files an issue, or participates in discussions. Contributors agree to the project's [Code of Conduct](CODE_OF_CONDUCT.md) and sign the [Contributor License Agreement](https://cla.opensource.microsoft.com).

### Reviewer

Contributors who have demonstrated familiarity with a specific area of the codebase and consistently provide constructive reviews. Reviewers can approve PRs in their area but cannot merge without maintainer approval.

**Path to Reviewer**: 3+ merged PRs in a specific package or area, active participation in issue triage or code review over 1+ months.

### Maintainer

Maintainers have write access to the repository, can merge PRs, and participate in architectural decisions. Maintainers are responsible for the project's technical direction, release management, and community health.

**Path to Maintainer**: Sustained contribution over 2+ months, including 5+ merged PRs, active issue triage, and demonstrated understanding of the project's architecture and governance scope. Nomination by an existing maintainer, confirmed by consensus among current maintainers.

### Project Lead

The project lead sets overall technical direction, resolves disputes when consensus cannot be reached, and represents the project in external standards bodies and foundation interactions.

## Current Maintainers

| Name | Organization | GitHub | Role |
|------|-------------|--------|------|
| Imran Siddique | Microsoft | [@imran-siddique](https://github.com/imran-siddique) | Project lead, creator |
| Jack Batzner | Microsoft | [@jackbatzner](https://github.com/jackbatzner) | Maintainer |
| Elton Carr | Microsoft | [@eltoncarr-ms](https://github.com/eltoncarr-ms) | Maintainer |

We are actively working to grow the maintainer group to include contributors from other organizations. If you are interested in becoming a maintainer, start by contributing and engaging with the project.

## Decision-Making

### Day-to-day decisions

Pull requests require approval from at least one maintainer before merge. Maintainers use their judgment on routine changes (bug fixes, documentation, test additions).

### Significant changes

Changes that affect the project's architecture, public API surface, security model, or governance scope are discussed publicly via GitHub Issues before implementation. Any maintainer or contributor can raise a concern. The goal is rough consensus among maintainers.

### Disputes

If maintainers cannot reach consensus, the project lead makes the final decision after considering all perspectives. The rationale is documented in the relevant GitHub Issue.

## Releases

Releases follow [Semantic Versioning](https://semver.org/). Any maintainer can propose a release. The release process is automated via GitHub Actions with trusted publishing and SLSA build provenance.

## Code of Conduct

All participants are expected to follow the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). Violations can be reported to [opencode@microsoft.com](mailto:opencode@microsoft.com).

## Security

Security vulnerabilities should be reported via [SECURITY.md](SECURITY.md), not through public issues.

## Changes to Governance

Changes to this document require a pull request with approval from at least two maintainers. Significant governance changes (e.g., adding new roles, changing decision processes) should be discussed in a GitHub Issue first.
