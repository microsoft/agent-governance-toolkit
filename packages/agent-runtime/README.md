<div align="center">

# Agent Runtime

**Execution supervisor for multi-agent sessions — privilege rings, saga orchestration, and governance enforcement**

*Part of the [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)*

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)

</div>

---

> **Note:** This package was previously named `agent-hypervisor`. The `agent-hypervisor` package
> is still available for backward compatibility but will redirect to `agent-runtime` in a future release.

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
pip install agent-runtime
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
| **Agent Runtime** | Execution supervisor — rings, sessions, sagas *(this package)* |
| **Agent SRE** | Reliability — SLOs, circuit breakers, chaos testing |
| **Agent Compliance** | Regulatory compliance — GDPR, HIPAA, SOX frameworks |
| **Agent Marketplace** | Plugin lifecycle — discover, install, verify, sign |
| **Agent Lightning** | RL training governance — governed runners, policy rewards |

## License

MIT — see [LICENSE](../../LICENSE).
