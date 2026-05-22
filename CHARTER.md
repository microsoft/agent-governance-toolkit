# Technical Charter

## Agent Governance Toolkit

Effective: May 2026

### 1. Mission

The Agent Governance Toolkit (AGT) provides open-source, runtime-enforceable
governance for autonomous AI agents. The project delivers deterministic policy
evaluation, identity verification, audit logging, and compliance tooling that
organizations can embed into any agent framework or orchestration platform.

### 2. Technical Steering

The project is led by a Project Lead and governed by a group of Core Maintainers
as defined in [GOVERNANCE.md](GOVERNANCE.md). Together they form the Technical
Steering Committee (TSC).

**TSC responsibilities:**

- Set technical direction and architectural priorities
- Approve or reject significant design changes (via ADR process in `docs/adr/`)
- Manage the release process described in [docs/RELEASE.md](docs/RELEASE.md)
- Maintain the project's security posture and respond to vulnerability reports
- Ensure conformance with the project's formal specifications (`docs/specs/`)
- Onboard new maintainers per the process in [GOVERNANCE.md](GOVERNANCE.md)

**TSC composition:**

The TSC consists of all individuals listed in [MAINTAINERS.md](MAINTAINERS.md)
under "Project Lead" and "Core Maintainers." The project actively seeks
maintainers from multiple organizations to avoid single-vendor control.

**Meetings:**

TSC decisions are made asynchronously via GitHub Issues and Pull Requests.
Synchronous meetings may be scheduled as needed and announced in GitHub
Discussions. Meeting notes are posted publicly.

### 3. Intellectual Property Policy

**License:** All code and documentation in this repository is licensed under the
[MIT License](LICENSE).

**Contributions:** All contributors must agree to the
[Microsoft CLA](https://cla.opensource.microsoft.com) before their first
contribution can be merged. The CLA grants a perpetual, worldwide, non-exclusive,
royalty-free license for the contribution.

**Inbound = Outbound:** Contributions are accepted under the same license as the
project (MIT). No contributor may submit code under a more restrictive license.

**Third-party dependencies:** New dependencies must use licenses compatible with
MIT. The CI pipeline (`dependency-review.yml`) automatically rejects dependencies
with copyleft or unknown licenses.

### 4. Specifications and Conformance

The project maintains formal specifications in `docs/specs/` using RFC 2119
keywords. Specifications are versioned independently from the code and require
TSC approval for changes.

Conformance tests in `tests/spec_conformance/` validate that implementations
match the specifications. All SDK implementations (Python, TypeScript, .NET,
Rust, Go) must pass conformance tests before release.

### 5. Trademark

"Agent Governance Toolkit" and "AGT" are trademarks of Microsoft Corporation.
Use of these marks in derivative works requires compliance with the
[Microsoft Trademark Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks).

### 6. Amendments

Changes to this charter require a pull request with approval from at least two
Core Maintainers and a one-week public comment period announced in GitHub
Discussions. The voting thresholds in [GOVERNANCE.md](GOVERNANCE.md) apply.

### 7. Foundation Transition

If the project is accepted into a foundation (e.g., the AI Alliance, Linux
Foundation, or similar), this charter will be superseded by the foundation's
technical charter template. The TSC will work with the foundation to ensure
continuity of governance, maintainer rights, and contributor agreements during
the transition.
