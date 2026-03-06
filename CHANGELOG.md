# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.1] - 2026-03-06

### Changed
- **Microsoft org release** — First publish from `microsoft/agent-governance-toolkit`
- Added MIT license headers to 1,159 source files
- Migrated all 215 documentation URLs from personal repos to Microsoft org
- Replaced personal email references with team alias (`agt@microsoft.com`)
- Enhanced README with CI badge, navigation links, CLA/Code of Conduct sections

### Fixed
- Fixed `agentmesh` PyPI link → `agentmesh-platform` (correct package name)
- Removed internal feed reference from providers.py

### Security
- Passed full pre-launch security audit (secret scan, pip-audit, Azure ID check)
- All 43 OSV vulnerabilities from v1.0.0 confirmed resolved

### Repository
- Archived 5 personal repos with deprecation banners and migration notices
- Closed 83 open issues and annotated 596 closed items with migration links
- Posted migration announcements to 89 stargazers
- Enabled GitHub Discussions, 12 topic tags, OpenSSF Scorecard

## [1.0.0] - 2026-03-04

### Added

- **Agent OS Kernel** (`agent-os-kernel`) — Policy-as-code enforcement engine with
  syscall-style interception, OWASP ASI 2026 compliance, and Microsoft Agent Framework
  (MAF) native middleware adapter.
- **AgentMesh** (`agentmesh`) — Zero-trust inter-agent identity mesh with SPIFFE-based
  identity, DID-linked credentials, Microsoft Entra Agent ID adapter, and AI-BOM v2.0
  supply-chain provenance.
- **Agent Hypervisor** (`agent-hypervisor`) — Runtime sandboxing with capability-based
  isolation, resource quotas, and Docker/Firecracker execution environments.
- **Agent SRE** (`agent-sre`) — Observability toolkit with chaos-engineering probes,
  canary deployment framework, and automated incident response.
- **Agent Compliance** (`ai-agent-compliance`) — Unified compliance installer mapping
  OWASP ASI 2026 (10/10), NIST AI RMF, EU AI Act, and CSA Agentic Trust Framework.
- Mono-repo CI/CD: lint (ruff) × 5 packages, test matrix (3 Python versions × 4 packages),
  security scanning (safety), CodeQL SAST (Python + JavaScript).
- Dependabot configuration for 8 ecosystems.
- OpenSSF Best Practices badge and Scorecard integration.
- Comprehensive governance proposal documents for standards bodies (OWASP, CoSAI, LF AI & Data).

### Security

- **CVE-2025-27520** — Bumped `python-multipart` to ≥0.0.20 (arbitrary file write).
- **CVE-2024-53981** — Bumped `python-multipart` to ≥0.0.20 (DoS via malformed boundary).
- **CVE-2024-47874** — Bumped `python-multipart` to ≥0.0.20 (Content-Type ReDoS).
- **CVE-2024-5206** — Bumped `scikit-learn` to ≥1.6.1 (sensitive data leakage).
- **CVE-2023-36464** — Replaced deprecated `PyPDF2` with `pypdf` ≥4.0.0 (infinite loop).
- Removed exception details from HTTP error responses (CWE-209).
- Redacted PII (patient IDs, SSNs) from example log output (CWE-532).
- Fixed ReDoS patterns in policy library regex (CWE-1333).
- Fixed incomplete URL validation in Chrome extension (CWE-20).
- Pinned all GitHub Actions by SHA hash.
- Pinned all Docker base images by SHA256 digest.
- Removed `gradle-wrapper.jar` binary artifact.

[1.0.0]: https://github.com/microsoft/agent-governance-toolkit/releases/tag/v1.0.0
