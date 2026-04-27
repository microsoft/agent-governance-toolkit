# Agent Governance Toolkit v3.0.0

> [!IMPORTANT]
> **Public Preview** — All packages published from this repository are
> **Microsoft-signed public preview releases**. They are production-quality but
> may have breaking changes before GA. For feedback, open an issue or contact
> agentgovtoolkit@microsoft.com.

## What's New in v3.0.0

### Microsoft-Signed Public Preview

This is the first **officially Microsoft-signed release** of the Agent Governance
Toolkit. All Python packages are published to PyPI via ESRP Release through
Azure DevOps pipelines with full provenance attestation.

Key milestone changes:

- **ESRP Release publishing** — all packages signed and published via Microsoft's
  approved OSS publishing path
- **Version bump to 3.0.0** — signals the transition from community preview to
  official Microsoft-signed releases
- **"Public Preview" branding** — all package descriptions and documentation updated
  to reflect official preview status

### Package Renames (from v2.3.0)

| Old Name | New Name | Reason |
|----------|----------|--------|
| `agent-runtime` | `agentmesh-runtime` | Name collision with AutoGen |
| `agent-marketplace` | `agentmesh-marketplace` | Namespace consistency |
| `agent-lightning` | `agentmesh-lightning` | PyPI name collision |

### Infrastructure Improvements

- ESRP pipeline secrets updated to use `ESRP_CERT_IDENTIFIER`
- Service connection hardcoded for ADO compile-time requirement
- Pipeline YAML syntax fixes for `each` directive in Verify stages
- License format migrated to SPDX string (fixes setuptools deprecation)
- All personal author references replaced with `Microsoft Corporation`
- Contact email consolidated to `agentgovtoolkit@microsoft.com`

## Packages

**Python (PyPI) — 7 packages @ v3.0.0:**

| Package | PyPI Name | Status |
|---------|-----------|--------|
| Agent OS Kernel | [`agent-os-kernel`](https://pypi.org/project/agent-os-kernel/) | Public Preview |
| AgentMesh Platform | [`agentmesh-platform`](https://pypi.org/project/agentmesh-platform/) | Public Preview |
| Agent Hypervisor | [`agent-hypervisor`](https://pypi.org/project/agent-governance-python/agent-hypervisor/) | Public Preview |
| Agent SRE | [`agent-sre`](https://pypi.org/project/agent-governance-python/agent-sre/) | Public Preview |
| Agent Governance Toolkit | [`agent-governance-toolkit`](https://pypi.org/project/agent-governance-toolkit/) | Public Preview |
| AgentMesh Runtime | [`agentmesh-runtime`](https://pypi.org/project/agentmesh-runtime/) | Public Preview |
| AgentMesh Lightning | [`agentmesh-lightning`](https://pypi.org/project/agentmesh-lightning/) | Public Preview |

**npm — 7 packages (under `@microsoft` scope)**

**.NET — 1 NuGet package**

## Upgrading

```bash
pip install --upgrade agent-governance-toolkit==3.0.0
```

> **Migration note:** If you previously used `agent-runtime`, `agent-lightning`,
> or `agent-marketplace`, update your dependencies to `agentmesh-runtime`,
> `agentmesh-lightning`, and `agentmesh-marketplace` respectively.

## Full Changelog

See [CHANGELOG.md](CHANGELOG.md) for the complete list of changes since v2.3.0.
