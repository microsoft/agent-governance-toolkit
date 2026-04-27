# Agent Governance Toolkit v3.1.0

> [!IMPORTANT]
> **Public Preview** — All packages published from this repository are
> **Microsoft-signed public preview releases**. They are production-quality but
> may have breaking changes before GA. For feedback, open an issue or contact
> agentgovtoolkit@microsoft.com.

## What's New in v3.1.0

Version 3.1.0 brings **unified CLI tooling**, **real-time governance dashboards**,
**quantum-safe cryptography**, and **full agent lifecycle management** — giving
enterprises end-to-end visibility and control over their AI agent fleets.

### Highlights

- **Unified `agt` CLI** — single entry point for all governance operations with
  plugin discovery and built-in `doctor` diagnostics (#924)
- **Governance Dashboard** — real-time agent fleet visibility with health, trust,
  and compliance metrics (#925)
- **Agent Lifecycle Management** — complete provisioning-to-decommission workflow
  for governed agents (#923)
- **Shadow AI Discovery** — new `agent-discovery` package finds unregistered agents
  and builds a centralized inventory (#921)
- **Quantum-Safe Signing** — ML-DSA-65 (FIPS 204) alongside Ed25519 for
  post-quantum readiness (#927)
- **OWASP ASI 2026 Taxonomy** — migrated to the latest Agentic Security taxonomy
  with reference architecture
- **Vendor Independence** — enforced across all core packages, ensuring no
  single-vendor lock-in
- **PromptDefenseEvaluator** — 12-vector prompt injection audit for agent
  compliance checks (#854)

### Security Fixes

- Patched dependency verification bypass and trust handshake DID forgery (#920)
- Hardened CLI error handling to prevent internal information disclosure (CWE-209)
- Audit log key-whitelisting to prevent leakage of sensitive agent state
- Regex-based validation for agent identifiers to prevent injection attacks

## Breaking Changes

**None.** This is a backwards-compatible minor release. All existing v3.0.x
configurations, policies, and integrations work without modification.

## Upgrading

```bash
pip install --upgrade agent-governance-toolkit==3.1.0
```

For individual packages:

```bash
pip install --upgrade agent-os-kernel==3.1.0
pip install --upgrade agentmesh-platform==3.1.0
pip install --upgrade agent-hypervisor==3.1.0
pip install --upgrade agent-sre==3.1.0
```

No configuration changes are required. The `agt` CLI is available automatically
after upgrading the `agentmesh-platform` package.

## Packages

**Python (PyPI) — core packages @ v3.1.0:**

| Package | PyPI Name | Version | Status |
|---------|-----------|---------|--------|
| Agent OS Kernel | [`agent-os-kernel`](https://pypi.org/project/agent-os-kernel/) | 3.1.0 | Public Preview |
| AgentMesh Platform | [`agentmesh-platform`](https://pypi.org/project/agentmesh-platform/) | 3.1.0 | Public Preview |
| Agent Hypervisor | [`agent-hypervisor`](https://pypi.org/project/agent-governance-python/agent-hypervisor/) | 3.1.0 | Public Preview |
| Agent SRE | [`agent-sre`](https://pypi.org/project/agent-governance-python/agent-sre/) | 3.1.0 | Public Preview |
| Agent Compliance | [`agent-compliance`](https://pypi.org/project/agent-governance-python/agent-compliance/) | 3.1.0 | Public Preview |
| AgentMesh Runtime | [`agentmesh-runtime`](https://pypi.org/project/agentmesh-runtime/) | 3.1.0 | Public Preview |
| AgentMesh Lightning | [`agentmesh-lightning`](https://pypi.org/project/agentmesh-lightning/) | 3.1.0 | Public Preview |

**New packages (independent versioning):**

| Package | Version | Status |
|---------|---------|--------|
| Agent Discovery | 0.1.0 | Public Preview |
| Agent MCP Governance | 0.1.0 | Public Preview |
| APS AgentMesh | 0.1.0 | Public Preview |

**npm — packages under `@microsoft` scope**

**.NET — NuGet package**

**Rust — crates.io crate**

**Go — Go module**

## Full Changelog

See [CHANGELOG.md](CHANGELOG.md) for the complete list of changes since v3.0.2.
