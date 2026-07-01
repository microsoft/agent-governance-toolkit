<div align="center">

# Agent Hypervisor Public Preview

**Runtime supervisor for AI agents with execution rings, isolated sessions, saga compensation, audit trails, and safety controls.**

[![CI](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](../../LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)

[Quick start](#quick-start) | [Real features](#real-features) | [Configuration](#configuration) | [REST API](#rest-api) | [Validation](#validation)

</div>

> [!IMPORTANT]
> `agent-hypervisor` is deprecated as a standalone PyPI package. For new work, install `agent-governance-toolkit-core` or the full toolkit. The source in this directory remains tested and documents the runtime features that are implemented here.

## Why Agent Hypervisor

Agent Hypervisor supervises shared multi-agent sessions. It assigns agents to execution rings, isolates session state in a virtual file system, records a tamper-evident delta audit trail, runs compensating sagas, and exposes kill switch, rate limiting, verification, and observability primitives.

## Real features

| Area | Implemented behavior |
|------|----------------------|
| Execution rings | `ExecutionRing`, `RingEnforcer`, `ActionClassifier`, `RingElevationManager`, and `RingBreachDetector` enforce ring requirements and detect boundary violations. |
| Session isolation | `SharedSessionObject` and `SessionVFS` isolate session state, support snapshots, and use `VectorClock` for causal ordering. |
| Reversibility | `ReversibilityRegistry` records execute and undo metadata for actions that can be compensated. |
| Delta audit | `DeltaEngine` records VFS deltas in a hash chain and returns a root hash when a session terminates. |
| Saga orchestration | `SagaOrchestrator`, `SagaState`, and `StepState` run ordered steps, retries, timeout handling, and reverse-order compensation. |
| History verification | `TransactionHistoryVerifier` checks claimed transaction history against known session records. |
| Safety controls | `KillSwitch` terminates agents with optional handoff, and `AgentRateLimiter` enforces per-agent token buckets by ring. |
| Observability | `HypervisorEventBus`, `EventType`, `CausalTraceId`, the Prometheus collector, and the saga span exporter provide runtime telemetry. |

## Quick start

```bash
pip install agent-governance-toolkit-core
```

```python
from hypervisor import Hypervisor, SessionConfig

hv = Hypervisor()

session = await hv.create_session(
    config=SessionConfig(enable_audit=True),
    creator_did="did:mesh:admin",
)

ring = await hv.join_session(
    session.sso.session_id,
    "did:mesh:agent-1",
    sigma_raw=0.85,
)

await hv.activate_session(session.sso.session_id)

saga = session.saga.create_saga(session.sso.session_id)
step = session.saga.add_step(
    saga.saga_id,
    "draft-email",
    "did:mesh:agent-1",
    execute_api="/api/draft",
    undo_api="/api/undo-draft",
    timeout_seconds=30,
    max_retries=2,
)

result = await session.saga.execute_step(
    saga.saga_id,
    step.step_id,
    executor=draft_email,
)

hash_root = await hv.terminate_session(session.sso.session_id)
```

## Configuration

```python
from hypervisor import ConsistencyMode, Hypervisor, SessionConfig

hv = Hypervisor()

config = SessionConfig(
    consistency_mode=ConsistencyMode.EVENTUAL,
    max_participants=10,
    max_duration_seconds=3600,
    min_eff_score=0.60,
    enable_audit=True,
)
```

`Hypervisor` also accepts optional adapters for external trust scoring, behavior checks, and capability manifest parsing:

```python
hv = Hypervisor(nexus=nexus_adapter, policy_check=policy_adapter, iatp=iatp_adapter)
```

## Execution rings

```python
from hypervisor import ActionClassifier, ExecutionRing, ReversibilityLevel, RingEnforcer
from hypervisor.models import ActionDescriptor

ring = ExecutionRing.from_eff_score(0.85)
action = ActionDescriptor(
    action_id="deploy.staging",
    name="Deploy to staging",
    execute_api="/deploy/staging",
    undo_api="/deploy/rollback",
    reversibility=ReversibilityLevel.PARTIAL,
)
classification = ActionClassifier().classify(action)
allowed = RingEnforcer().check(
    agent_ring=ring,
    action=action,
    eff_score=0.85,
)
```

## Saga compensation

```python
from hypervisor import SagaOrchestrator

orchestrator = SagaOrchestrator()
saga = orchestrator.create_saga("session-1")
step = orchestrator.add_step(
    saga.saga_id,
    "provision",
    "did:mesh:worker",
    execute_api="/infra/provision",
    undo_api="/infra/deprovision",
)

await orchestrator.execute_step(saga.saga_id, step.step_id, executor=provision)
await orchestrator.compensate(saga.saga_id, compensator)
```

## REST API

Run the FastAPI server:

```bash
uvicorn hypervisor.api.server:app
```

Implemented endpoint groups:

| Group | Endpoints |
|-------|-----------|
| Health | `GET /health`, `GET /api/v1/stats` |
| Sessions | create, list, inspect, join, activate, terminate |
| Rings | session distribution, agent ring lookup, access check |
| Sagas | create, list, inspect, add step, execute step |
| Events | query events and event statistics |
| Verification | verify history and clear verification cache |

## Examples

```bash
cd agent-governance-python/agent-hypervisor
python examples/demo.py
streamlit run examples/dashboard/app.py
```

The dashboard shows sessions, execution rings, saga compensation, audit and verification signals, and event streams.

## Validation

```bash
cd agent-governance-python/agent-hypervisor
python -m py_compile examples/demo.py examples/dashboard/app.py
pytest tests/ -v
```

## License

MIT, see [LICENSE](../../LICENSE).
