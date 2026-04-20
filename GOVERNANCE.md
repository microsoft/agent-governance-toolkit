# Governance

This document describes the governance model for the Agent Governance Toolkit (AGT).

## Project Scope

The Agent Governance Toolkit provides runtime governance for autonomous AI agents:
deterministic policy enforcement, zero-trust identity, execution sandboxing, and
reliability engineering.

## Roles

### Maintainers

Maintainers have merge authority and are responsible for the project's technical
direction, security posture, and release management. See [MAINTAINERS.md](MAINTAINERS.md)
for the current list.

**Responsibilities:**
- Review and merge pull requests
- Triage security vulnerabilities (MSRC coordination)
- Manage releases and signing (ESRP)
- Enforce contribution policies

### Contributors

Anyone who submits a pull request, files an issue, or participates in discussions.
See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Community Extension Authors

External contributors who build integrations under `packages/agentmesh-integrations/`.
Extensions are community-maintained and clearly separated from core.

## Core vs Community Extension Boundary

| Path | Ownership | Review Policy |
|------|-----------|--------------|
| `packages/agent-os/` | Microsoft maintainers | Maintainer approval required |
| `packages/agent-mesh/src/` | Microsoft maintainers | Maintainer approval required |
| `packages/agent-hypervisor/` | Microsoft maintainers | Maintainer approval required |
| `packages/agent-sre/` | Microsoft maintainers | Maintainer approval required |
| `packages/agent-compliance/` | Microsoft maintainers | Maintainer approval required |
| `packages/agent-runtime/` | Microsoft maintainers | Maintainer approval required |
| `packages/agent-marketplace/` | Microsoft maintainers | Maintainer approval required |
| `packages/agent-governance-dotnet/` | Microsoft maintainers | Maintainer approval required |
| `packages/agentmesh-integrations/` | Community + maintainers | Maintainer review, community may author |
| `docs/integrations/` | Community + maintainers | Maintainer review, community may author |
| `docs/adr/` | Community + maintainers | Maintainer review for proposed ADRs |
| `examples/` | Community + maintainers | Maintainer review |

**Core packages** (agent-os, agent-mesh, agent-hypervisor, agent-sre, agent-compliance,
agent-runtime, agent-marketplace, agent-governance-dotnet) are maintained exclusively
by Microsoft. External contributions to core require a prior discussion in a GitHub Issue
and explicit maintainer approval before a PR is opened.

**Community extensions** under `packages/agentmesh-integrations/` are welcome from any
contributor. Extensions must not modify core packages. Each extension must include its
own README, tests, and license notice.

## Decision Making

- **Technical decisions** are made by maintainers via GitHub Issues and ADRs
  (Architecture Decision Records) in `docs/adr/`.
- **Security decisions** follow the [SECURITY.md](SECURITY.md) process and coordinate
  with MSRC when applicable.
- **Roadmap priorities** are set by the maintainer team with community input via
  GitHub Discussions and Issues.

## Releases

- Releases follow [Semantic Versioning](https://semver.org/).
- All packages are signed via ESRP (Microsoft's approved signing service).
- Python packages are published to PyPI, npm packages to npmjs.com, NuGet packages
  to NuGet.org, Rust crates to crates.io.
- Release notes are published in `RELEASE_NOTES_*.md` and GitHub Releases.

## Code of Conduct

This project follows the [Microsoft Open Source Code of Conduct](CODE_OF_CONDUCT.md).

## License

MIT License. See [LICENSE](LICENSE).

## Amendments

This governance document may be amended by maintainer consensus. Changes are tracked
via pull requests to this file.
