<div align="center">

# Agent Marketplace

**Plugin lifecycle management for the Agent Governance Toolkit — discover, install, verify, and sign plugins**

*Part of the [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)*

[![CI](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](../../LICENSE)
[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://python.org)
[![PyPI](https://img.shields.io/pypi/v/agentmesh-marketplace)](https://pypi.org/project/agentmesh-marketplace/)

</div>

---

> **Note:** This package was extracted from `agentmesh.marketplace`. The old import path still works
> via a backward-compatibility shim but new code should import from `agent_marketplace` directly.

## What is Agent Marketplace?

Agent Marketplace provides **governed plugin lifecycle management** for AI agent ecosystems:

- **Plugin Discovery** — Browse and search registered plugins by capability, trust level, or framework
- **Verified Installation** — Install plugins with cryptographic integrity verification (SHA-256 + Ed25519)
- **Plugin Signing** — Sign plugin manifests with Ed25519 keys for supply-chain security
- **Manifest Validation** — Declarative plugin manifests with schema validation (capabilities, permissions, dependencies)
- **Registry Management** — Register, update, and deprecate plugins with version tracking

## Quick Start

```bash
pip install agentmesh-marketplace
```

```python
from agent_marketplace import PluginRegistry, PluginInstaller, PluginManifest

# Create a registry
registry = PluginRegistry()

# Register a plugin
manifest = PluginManifest(
    name="web-search",
    version="1.0.0",
    capabilities=["search", "browse"],
    permissions=["network:read"],
)
registry.register(manifest)

# Install with verification
installer = PluginInstaller(registry=registry, verify_signatures=True)
result = installer.install("web-search")
```

## CLI

```bash
# List available plugins
agentmesh-marketplace list

# Install a plugin
agentmesh-marketplace install web-search

# Verify plugin integrity
agentmesh-marketplace verify web-search

# Sign a plugin manifest
agentmesh-marketplace sign manifest.yaml --key signing-key.pem
```

## Ecosystem

Agent Marketplace is one of 7 packages in the Agent Governance Toolkit:

| Package | Role |
|---------|------|
| **Agent OS** | Policy engine — deterministic action evaluation |
| **AgentMesh** | Trust infrastructure — identity, credentials, protocol bridges |
| **Agent Runtime** | Execution supervisor — rings, sessions, sagas |
| **Agent SRE** | Reliability — SLOs, circuit breakers, chaos testing |
| **Agent Compliance** | Regulatory compliance — GDPR, HIPAA, SOX frameworks |
| **Agent Marketplace** | Plugin lifecycle — discover, install, verify, sign *(this package)* |
| **Agent Lightning** | RL training governance — governed runners, policy rewards |

## License

MIT — see [LICENSE](../../LICENSE).
