<div align="center">

# AgentMesh Runtime

**Execution supervisor for multi-agent sessions — privilege rings, saga orchestration, and governance enforcement**

*Part of the [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)*

[![CI](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](../../LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![PyPI](https://img.shields.io/pypi/v/agentmesh-runtime)](https://pypi.org/project/agentmesh-runtime/)

</div>

> [!IMPORTANT]
> **Community Preview** — The `agentmesh-runtime` package on PyPI is a community preview release
> for testing and evaluation only. It is **not** an official Microsoft-signed release.
> Official signed packages will be available in a future release.

---

> **Note:** This package was renamed from `agent-runtime` to `agentmesh-runtime` to avoid a PyPI
> name collision with the AutoGen team's package. The `agent-hypervisor` package remains the
> canonical upstream implementation; `agentmesh-runtime` is a thin re-export wrapper for
> incremental import migration.

## What is Agent Runtime?

Agent Runtime provides **execution-level supervision** for autonomous AI agents. While Agent OS handles
policy decisions and AgentMesh handles trust/identity, Agent Runtime enforces those decisions at the
session level:

- **Execution Rings** — 4-tier privilege model (Ring 0–3) controlling what agents can do at runtime
- **Shared Sessions** — Multi-agent session management with consistency modes (strict, eventual, causal)
- **Saga Orchestration** — Compensating transactions for multi-step agent workflows
- **Kill Switch** — Immediate termination with audit trail and blast radius containment
- **Joint Liability** — Attribution tracking across multi-agent collaborations
- **Audit Trails** — Hash-chained, append-only execution logs

## Quick Start

```bash
pip install agentmesh-runtime
```

```python
from hypervisor import Hypervisor, SessionConfig, ConsistencyMode

# Create the runtime supervisor
hv = Hypervisor()

# Create a governed session
session = await hv.create_session(
    config=SessionConfig(consistency_mode=ConsistencyMode.EVENTUAL)
)

# Execute with privilege enforcement
result = await session.execute(
    agent_id="researcher-1",
    action="tool_call",
    tool="web_search",
    ring=2  # restricted privilege ring
)
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Agent Runtime                                 │
├─────────────┬──────────────────┬──────────────────┬─────────────────┤
│  Execution  │     Session      │      Saga        │    Liability    │
│   Rings     │   Management     │  Orchestration   │    Tracking     │
│             │                  │                  │                 │
│  Ring 0:    │  Create/join     │  Multi-step      │  Attribution    │
│   System    │  Consistency     │  Compensation    │  Vouching       │
│  Ring 1:    │  Checkpoints     │  Rollback        │  Slashing       │
│   Trusted   │  Merge/fork      │  Recovery        │  Quarantine     │
│  Ring 2:    │                  │                  │                 │
│   Standard  │                  │                  │                 │
│  Ring 3:    │                  │                  │                 │
│   Sandboxed │                  │                  │                 │
└─────────────┴──────────────────┴──────────────────┴─────────────────┘
```

## Ecosystem

Agent Runtime is one of 7 packages in the Agent Governance Toolkit:

| Package | Role |
|---------|------|
| **Agent OS** | Policy engine — deterministic action evaluation |
| **AgentMesh** | Trust infrastructure — identity, credentials, protocol bridges |
| **AgentMesh Runtime** | Execution supervisor — rings, sessions, sagas *(this package)* |
| **Agent SRE** | Reliability — SLOs, circuit breakers, chaos testing |
| **Agent Compliance** | Regulatory compliance — GDPR, HIPAA, SOX frameworks |
| **Agent Marketplace** | Plugin lifecycle — discover, install, verify, sign |
| **Agent Lightning** | RL training governance — governed runners, policy rewards |

## License

MIT — see [LICENSE](../../LICENSE).
