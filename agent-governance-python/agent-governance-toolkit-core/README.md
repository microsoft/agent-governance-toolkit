# agent-governance-toolkit-core

Core runtime, kernel, and trust layer for the
[Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit).

This package consolidates five previously separate distributions into a single
install:

| Old package | What it provides |
|---|---|
| `agent-os-kernel` | Kernel architecture, Nexus Trust Exchange, CMVK, IATP, AMB, ATR, control plane, observability |
| `agentmesh-primitives` | Shared primitive data models (failure types, severity levels, base structures) |
| `agentmesh-runtime` | Execution supervisor with privilege rings, saga orchestration, audit trails |
| `agent-hypervisor` | Runtime supervisor for shared sessions, execution rings, saga compensation, hash-chained audit |
| `agentmesh-platform` | Identity, trust, reward, governance for cloud-native agent ecosystems |

## Install

```bash
pip install agent-governance-toolkit-core
```

With optional extras:

```bash
pip install agent-governance-toolkit-core[full]
pip install agent-governance-toolkit-core[iatp,observability]
```

## Migration from old packages

If you previously installed any of the five packages listed above, replace them
with `agent-governance-toolkit-core` in your requirements file. All import paths
are unchanged:

```python
from agent_os.kernel import GovernanceKernel      # unchanged
from agent_primitives.failures import FailureType  # unchanged
from agent_runtime.supervisor import Supervisor    # unchanged
from hypervisor.session import SharedSession       # unchanged
from agentmesh.identity import AgentIdentity       # unchanged
```

The old package names continue to work as thin redirects but will emit
deprecation warnings. See the
[migration guide](https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/package-consolidation/MIGRATION.md)
for details.
