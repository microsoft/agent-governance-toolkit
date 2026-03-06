# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-02-04

### Added

- Unified meta-package installing the complete Agent Governance Ecosystem
- Core dependencies: `agent-os-kernel>=1.0.0`, `agentmesh-platform>=1.0.0`
- Optional extras: `[hypervisor]`, `[sre]`, `[full]`
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
| Agent Hypervisor | `agent-hypervisor` | ≥2.0.0 (optional) |
| Agent SRE | `agent-sre` | ≥1.0.0 (optional) |

[1.0.0]: https://github.com/microsoft/agent-governance-toolkit/releases/tag/v1.0.0
