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

Maintainers are trusted community members responsible for one or more project
areas. They review contributions, guide contributors, drive improvements, and
maintain technical and community health within their areas. They escalate
cross-cutting architectural, security, or governance decisions to the Core
Maintainers.

Maintainers may receive repository permissions appropriate to their
responsibilities, but they follow the normal pull-request and code-owner review
process and do not receive bypass privileges by virtue of the role.

**Path to Maintainer**: Sustained contribution over 2+ months, including 5+
merged PRs, active issue triage or review, and demonstrated understanding of the
owned area. Any Maintainer or Core Maintainer may nominate a candidate. A
majority of Core Maintainers confirms the appointment.

### Core Maintainer

Core Maintainers have broad technical understanding of the project and are
responsible for its overall direction, technical consistency, security posture,
and long-term health. They resolve decisions escalated by Maintainers, appoint
and remove Maintainers, and serve as the repository code owners listed in
[`.github/CODEOWNERS`](.github/CODEOWNERS).

The project aims to maintain at least three Core Maintainers and requires at
least two for non-emergency governance decisions.

Core Maintainers use the standard contribution workflow even when their
repository permissions allow administrative actions. At least one Core
Maintainer approval is required before a pull request can merge.

**Path to Core Maintainer**: A candidate must meet the Maintainer expectations,
demonstrate project-wide technical judgment and sustained leadership, and commit
to the project's long-term health. An existing Core Maintainer nominates the
candidate, and a two-thirds supermajority of Core Maintainers confirms the
appointment.

### Project Lead

The Project Lead is a Core Maintainer designated to coordinate overall technical
direction, serve as the tie-breaker for eligible deadlocked decisions, and
represent the project in external standards bodies and foundation interactions.
The Project Lead and Core Maintainers form the Technical Steering Committee
defined in the [Technical Charter](CHARTER.md).
The Project Lead remains subject to the normal contribution workflow. Any
configured bypass privilege is reserved for documented emergencies and does not
waive an explicit voting threshold in this document or the
[Technical Charter](CHARTER.md).

## Current Maintainers

See [MAINTAINERS.md](MAINTAINERS.md) for the current Core Maintainers and
Maintainers, their areas of ownership, and affiliation details.

We are actively working to grow the maintainer group to include contributors
from other organizations. If you are interested in becoming a maintainer, start
by contributing and engaging with the project. Core Maintainers are the code
owners listed in [`.github/CODEOWNERS`](.github/CODEOWNERS); a Core Maintainer
code-owner approval is required on every pull request before merge.

## Decision-Making

### Day-to-day decisions

Maintainers use their judgment on routine changes within their areas, including
bug fixes, documentation, and tests. Pull requests require approval from at
least one Core Maintainer before merge, as enforced by the repository's
code-owner rules.

### Significant changes

Changes that affect the project's architecture, public API surface, security
model, or governance scope are discussed publicly via GitHub Issues before
implementation. Any contributor may raise a concern. Core Maintainers seek
rough consensus and record approval from a majority of Core Maintainers before
the change is merged.

### Disputes

Disagreements that Maintainers cannot resolve are escalated to the Core
Maintainers. Core Maintainers seek consensus and may hold a simple-majority vote
when needed. If an eligible vote is tied, the Project Lead decides after
considering the recorded perspectives. The decision and rationale are documented
in the relevant GitHub Issue. A tie-break does not waive an explicit approval or
supermajority requirement.

### Succession Planning

Continuity of maintainership is essential for a public open-source project.

- **Project lead vacancy**: If the project lead steps down or becomes inactive for
  60+ days, the Core Maintainers elect a new project lead by supermajority (2/3)
  vote within 30 days. Until a new lead is confirmed, the Core Maintainers
  designate an acting lead by majority vote.
- **Core Maintainer vacancy**: The project maintains at least two Core
  Maintainers. If the number drops below two, the remaining Core Maintainer must
  begin a documented replacement or mentorship process within 30 days. No
  non-emergency architecture or governance decision may be finalized until the
  minimum is restored. Security response and operational-continuity decisions
  may proceed but must be documented.
- **Inactivity**: A Maintainer or Core Maintainer who has not participated for
  3+ months may be removed from the active roster by a majority vote of the Core
  Maintainers. Participation includes code or documentation contributions,
  reviews, issue triage, releases, security response, and governance work. The
  affected person does not vote on their removal. Merge, administrative, and
  publishing privileges are revoked promptly when the removal takes effect.
- **Deadlock**: If Project Lead succession remains deadlocked after two rounds,
  or the Project Lead is recused from another tied decision, the decision is
  escalated to the governing foundation when applicable. Otherwise, the Core
  Maintainers document and engage a mutually agreed independent mediator.

### Conflict of Interest

Maintainers and Core Maintainers must disclose any financial or employment
relationship that could influence their decisions on project direction,
dependency choices, or vendor integrations. A person with a conflict of interest
on a specific decision must recuse themselves from voting on that decision.
Disclosures are noted in the relevant GitHub Issue or pull request.

### Voting Thresholds

Unless a rule states otherwise, votes count eligible, non-recused Core
Maintainers. A majority is more than half of the eligible voters; a two-thirds
threshold is rounded up to the next whole vote.

| Decision type | Required votes | Quorum |
|--------------|---------------|--------|
| Routine PR merge | 1 Core Maintainer approval | N/A |
| Architecture, public API, or security-model change | Majority of Core Maintainers | Majority of Core Maintainers |
| New Maintainer appointment | Majority of Core Maintainers | Majority of Core Maintainers |
| New Core Maintainer appointment | Supermajority (2/3) of Core Maintainers | All Core Maintainers |
| Governance document change | 2 Core Maintainer approvals | N/A |
| Project Lead succession | Supermajority (2/3) of Core Maintainers | All Core Maintainers |

## Releases

Releases follow [Semantic Versioning](https://semver.org/). Any maintainer can propose a release. The release process is documented in [RELEASE.md](docs/RELEASE.md) and automated via GitHub Actions with trusted publishing and SLSA build provenance.

## Project Charter

The project operates under the [Technical Charter](CHARTER.md), which defines the TSC structure, IP policy, and amendment process for foundation governance.

## Code of Conduct

All participants are expected to follow the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). Violations can be reported to [opencode@microsoft.com](mailto:opencode@microsoft.com).

## Security

Security vulnerabilities should be reported via [SECURITY.md](SECURITY.md), not through public issues.

## Competition Law

All participants must comply with applicable competition (antitrust) laws. See [ANTITRUST.md](ANTITRUST.md) for guidelines on appropriate discussion topics.

## Changes to Governance

Changes to this document require a pull request with approval from at least two
Core Maintainers. Significant governance changes, including adding roles or
changing decision processes, must be discussed in a GitHub Issue first.
