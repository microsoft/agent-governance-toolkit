# Maintainers

This file lists the current maintainers of the Agent Governance Toolkit.
For governance rules, decision-making process, and how to become a maintainer,
see [GOVERNANCE.md](GOVERNANCE.md).

**Last updated:** October 2026

## Project Lead

| Name | Organization | GitHub | Role | Since |
|------|-------------|--------|------|-------|
| Mohammad Abuomar | Microsoft | [@MohammadHaroonAbuomar](https://github.com/MohammadHaroonAbuomar) | Project lead | Jun 2026 |

## Core Maintainers

Core maintainers are the code owners in [.github/CODEOWNERS](.github/CODEOWNERS).
Every pull request needs an approving review from one of them before it can merge.

| Name | Organization | GitHub | Area | Since |
|------|-------------|--------|------|-------|
| Mohammad Abuomar | Microsoft | [@MohammadHaroonAbuomar](https://github.com/MohammadHaroonAbuomar) | Project lead; review and release process, security, policy engine | Jun 2026 |
| Liam Crumm | Microsoft | [@liamcrumm](https://github.com/liamcrumm) | Python SDK, Agent OS, architecture | Jul 2026 |
| Prayag Upadhyay | Microsoft | [@prayagupa](https://github.com/prayagupa) | Python SDK, Agent Control Specification compatibility | Sep 2026 |

## Maintainers

Maintainers hold the maintain role on the repository and review in their area.
They are not code owners.

| Name | Organization | GitHub | Area | Since |
|------|-------------|--------|------|-------|
| Ricky Gummadi | Microsoft | [@Ricky-G](https://github.com/Ricky-G) | AGT Studio, CI workflows, dependency hygiene | Mar 2026 |

## Package Publishing

Packages are published by the release workflow in
[.github/workflows/publish.yml](.github/workflows/publish.yml), not by
individuals. PyPI packages use trusted publishing (OpenID Connect). npm packages
are published with provenance and NuGet packages with a registry key; both
credentials are repository secrets. The code owners manage registry access and
run releases.

## Becoming a Maintainer

Maintainer nominations follow the process in [GOVERNANCE.md](GOVERNANCE.md):

1. **Contributor** — submit PRs, file issues, participate in discussions
2. **Reviewer** — 3+ merged PRs in a specific area, 1+ months of activity
3. **Maintainer** — 5+ merged PRs, 2+ months sustained contribution, nomination by existing maintainer

We especially welcome maintainers from non-Microsoft organizations to strengthen
the project's vendor-neutral governance. If you are interested, start by
contributing and reach out in [GitHub Discussions](https://github.com/microsoft/agent-governance-toolkit/discussions).
