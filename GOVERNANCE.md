# Governance

This document describes the governance model for the Agent Governance Toolkit project.

## Principles

- **Open participation**: Anyone can contribute, report issues, or propose changes.
- **Transparent decision-making**: Architectural decisions are discussed publicly via GitHub Issues and Discussions.
- **Merit-based advancement**: Maintainer roles are earned through sustained, high-quality contributions.
- **Vendor neutrality goal**: The project is working toward multi-organization maintainership to ensure no single vendor controls the project's direction.

## Roles

### Contributor

Anyone who submits a pull request, files an issue, or participates in discussions. Contributors agree to the project's [Code of Conduct](CODE_OF_CONDUCT.md) and follow the contribution requirements in [CONTRIBUTING.md](CONTRIBUTING.md).

AGT is proposed for AAIF hosting in `aaif/project-proposals#19`. Until the
contribution agreement is executed, the existing Microsoft CLA check may remain
part of the contribution workflow. After transfer, the LF/AAIF contribution
process supersedes the Microsoft CLA. DCO sign-off remains required unless the
foundation process explicitly replaces it.

### Reviewer

Contributors who have demonstrated familiarity with a specific area of the codebase and consistently provide constructive reviews. Reviewers can approve PRs in their area but cannot merge without maintainer approval.

**Path to Reviewer**: 3+ merged PRs in a specific package or area, active participation in issue triage or code review over 1+ months.

### Maintainer

Maintainers have write access to the repository, can merge PRs, and participate in architectural decisions. Maintainers are responsible for the project's technical direction, release management, and community health.

**Path to Maintainer**: Sustained contribution over 2+ months, including 5+ merged PRs, active issue triage, and demonstrated understanding of the project's architecture and governance scope. Nomination by an existing maintainer, confirmed by consensus among current maintainers.

### Project Lead

The project lead sets overall technical direction, resolves disputes when consensus cannot be reached, and represents the project in external standards bodies and foundation interactions.

## Current Maintainers

See [MAINTAINERS.md](MAINTAINERS.md) for the current maintainer roster and
[OWNERS.md](OWNERS.md) for operational authority, area ownership, release
management, security response, and spec review responsibility.

We are actively working to grow maintainer authority across organizations. If you
are interested in becoming a maintainer, start by contributing and engaging with
the project. Code ownership areas are defined in [CODEOWNERS](.github/CODEOWNERS)
and explained in [OWNERS.md](OWNERS.md).

## Decision-Making

### Day-to-day decisions

Pull requests require approval from at least one maintainer before merge. Maintainers use their judgment on routine changes (bug fixes, documentation, test additions).

### Significant changes

Changes that affect the project's architecture, public API surface, security model, or governance scope are discussed publicly via GitHub Issues before implementation. Any maintainer or contributor can raise a concern. The goal is rough consensus among maintainers.

### Disputes

If maintainers cannot reach consensus, the project lead makes the final decision after considering all perspectives. The rationale is documented in the relevant GitHub Issue.

### Succession Planning

Continuity of maintainership is essential for a foundation-hosted project.

- **Project lead vacancy**: If the project lead steps down or becomes inactive for
  60+ days, the Core Maintainers elect a new project lead by supermajority (2/3)
  vote within 30 days. Until a new lead is confirmed, the longest-serving Core
  Maintainer serves as acting lead.
- **Maintainer vacancy**: If the number of Core Maintainers drops below three,
  remaining maintainers must nominate and confirm a replacement within 30 days.
  No architecture or governance decisions may be made until the minimum of three
  is restored.
- **Emeritus**: Maintainers inactive for 3+ months are moved to Emeritus status
  in [MAINTAINERS.md](MAINTAINERS.md) and lose merge privileges. Emeritus
  maintainers can be reinstated by consensus of current maintainers.
- **Deadlock**: If a supermajority vote on project lead succession results in a
  tie after two rounds of voting, the decision is escalated to the governing
  foundation (if applicable) or resolved by the longest-serving Core Maintainer.

### Conflict of Interest

Maintainers must disclose any financial or employment relationship that could
influence their decisions on project direction, dependency choices, or vendor
integrations. A maintainer with a conflict of interest on a specific decision
must recuse themselves from voting on that decision. Disclosures are noted in
the relevant GitHub Issue or PR.

### Voting Thresholds

| Decision type | Required votes | Quorum |
|--------------|---------------|--------|
| Routine PR merge | 1 maintainer approval | N/A |
| Architecture / API change | Rough consensus among maintainers | 50% of maintainers |
| New maintainer nomination | Consensus among current maintainers | 50% of maintainers |
| Governance document change | 2 maintainer approvals | N/A |
| Project lead succession | Supermajority (2/3) of maintainers | 75% of maintainers |

## Releases

Releases follow [Semantic Versioning](https://semver.org/). Any maintainer can
propose a release. Canonical releases are approved by release managers listed in
[OWNERS.md](OWNERS.md) and executed through the public release process documented
in [RELEASE.md](docs/RELEASE.md). Microsoft ESRP is not a canonical AGT release
path.

## Project Charter

The project operates under the [Technical Charter](CHARTER.md), which defines the TSC structure, IP policy, and amendment process for foundation governance.

## Code of Conduct

All participants are expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
During AAIF contribution finalization, the project is aligning its reporting path
with LF/AAIF project policy.

## Security

Security vulnerabilities should be reported via [SECURITY.md](SECURITY.md), not through public issues.

## Competition Law

All participants must comply with applicable competition (antitrust) laws. See [ANTITRUST.md](ANTITRUST.md) for guidelines on appropriate discussion topics.

## Changes to Governance

Changes to this document require a pull request with approval from at least two maintainers. Significant governance changes (e.g., adding new roles, changing decision processes) should be discussed in a GitHub Issue first.
