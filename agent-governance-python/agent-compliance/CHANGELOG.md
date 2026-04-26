# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Security Scan GitHub Action** (`action/security-scan`) - Automated security validation for AI agent code
  - Hardcoded secret detection using detect-secrets
  - Dependency vulnerability scanning (pip-audit, npm audit)
  - Dangerous code pattern detection using bandit
  - Markdown code block scanning for embedded executable code
  - Exemption system via `.security-exemptions.json` with justification tracking and expiration dates
  - Severity-based blocking (Critical/High blocks merge, Medium/Low warns)
  
- **Governance Attestation GitHub Action** (`action/governance-attestation`) - PR governance checklist validation
  - Validates exactly one checkbox marked per required section
  - Enforces governance attestation template usage
  - Configurable required sections for organizational compliance
  
- **Test coverage** - 42 comprehensive tests with 100% coverage for new security and governance modules
- **Documentation updates** - Added GitHub Actions integration examples to README.md and CONTRIBUTING.md
- **AGENTS.md** - Developer guidance for agent-compliance package

## [1.1.0] - 2026-03-15

### Changed

- **Package renamed** from `ai-agent-compliance` to `agent-governance` for better discoverability
  by the intended audience (platform engineers, security architects).
  The old name `ai-agent-compliance` is deprecated and will act as a thin redirect for 6 months.
- Updated PyPI description to reflect the package's actual function: runtime policy enforcement
  for AI agents.
- Added `agent-governance` CLI entry point; `agent-compliance` remains as a backward-compatible alias.

## [1.0.0] - 2026-02-04

### Added

- Unified meta-package installing the complete Agent Governance Ecosystem
- Core dependencies: `agent-os-kernel>=1.0.0`, `agentmesh-platform>=1.0.0`
- Optional extras: `[runtime]`, `[sre]`, `[full]`
- Re-exports of `StatelessKernel`, `ExecutionContext`, `TrustManager` for convenience
- Multi-version CI testing (Python 3.9–3.12)
- SECURITY.md with responsible disclosure policy
- Documentation: reference architecture, Kubernetes deployment, scaling guide, security hardening
- Framework-specific install examples (LangChain, CrewAI, AutoGen)

### Components (bundled versions)

| Component | Package | Version |
|-----------|---------|---------|
| Agent OS | `agent-os-kernel` | ≥1.0.0 |
| AgentMesh | `agentmesh-platform` | ≥1.0.0 |
| Agent Runtime | `agent-runtime` | ≥2.0.0 (optional) |
| Agent SRE | `agent-sre` | ≥1.0.0 (optional) |

[1.0.0]: https://github.com/microsoft/agent-governance-toolkit/releases/tag/v1.0.0
