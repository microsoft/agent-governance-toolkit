# Agent Lightning — RL Training Governance

> [!IMPORTANT]
> **Public Preview** — The `agentmesh-lightning` package on PyPI is a Microsoft-signed
> public preview release. APIs may change before GA.

Train AI agents with RL while maintaining **0% policy violations**.

*Part of the [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)*

[![CI](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/microsoft/agent-governance-toolkit/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](../../LICENSE)
[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://python.org)
[![PyPI](https://img.shields.io/pypi/v/agentmesh-lightning)](https://pypi.org/project/agentmesh-lightning/)

## 🎯 Overview

This package provides governed RL training integration:
- **Agent-Lightning** = Training/Optimization (the "brains")
- **Agent-OS** = Governance/Safety (the "guardrails")

**Result**: Agents learn to be smart AND safe from the start.

> **Note:** This package was extracted from `agent_os.integrations.agent_lightning`.
> The old import path still works via a backward-compatibility shim but new code
> should import from `agent_lightning_gov` directly.

## 🚀 Quick Start

```bash
pip install agentmesh-lightning
# Optional: pip install agent-os-kernel  # for kernel integration
```

```python
from agent_lightning_gov import GovernedRunner, PolicyReward
from agent_os import KernelSpace
from agent_os.policies import SQLPolicy, CostControlPolicy

# 1. Create governed kernel
kernel = KernelSpace(policy=[
    SQLPolicy(deny=["DROP", "DELETE"]),
    CostControlPolicy(max_cost_usd=100)
])

# 2. Create governed runner
runner = GovernedRunner(kernel)

# 3. Create policy-aware reward function
def base_accuracy(rollout):
    return rollout.task_output.accuracy if rollout.success else 0.0

reward_fn = PolicyReward(kernel, base_reward_fn=base_accuracy)

# 4. Train with Agent-Lightning
from agentlightning import Trainer
trainer = Trainer(
    runner=runner,
    reward_fn=reward_fn,
    algorithm="GRPO"
)

trainer.train(num_epochs=100)
```

## 📊 Key Benefits

| Metric | Without Agent-OS | With Agent-OS |
|--------|------------------|---------------|
| Policy Violations | 12.3% | **0.0%** |
| Task Accuracy | 76.4% | **79.2%** |
| Training Stability | Variable | Consistent |

## 🔧 Components

### GovernedRunner

Agent-Lightning runner that enforces policies during execution:

```python
from agent_lightning_gov import GovernedRunner

runner = GovernedRunner(
    kernel,
    fail_on_violation=False,   # Continue but penalize
    log_violations=True,        # Log all violations
)

# Execute a task
rollout = await runner.step(task_input)
print(f"Violations: {len(rollout.violations)}")
print(f"Total penalty: {rollout.total_penalty}")
```

### PolicyReward

Converts policy violations to RL penalties:

```python
from agent_lightning_gov import PolicyReward, RewardConfig

config = RewardConfig(
    critical_penalty=-100.0,  # Harsh penalty for critical violations
    high_penalty=-50.0,
    medium_penalty=-10.0,
    low_penalty=-1.0,
    clean_bonus=5.0,          # Bonus for no violations
)

reward_fn = PolicyReward(kernel, config=config)

# Calculate reward
reward = reward_fn(rollout)  # Base reward + policy penalties
```

### GovernedEnvironment

Gym-compatible training environment:

```python
from agent_lightning_gov import GovernedEnvironment

env = GovernedEnvironment(
    kernel,
    config=EnvironmentConfig(
        max_steps=100,
        terminate_on_critical=True,
    )
)

# Standard Gym interface
state, info = env.reset()
while not env.terminated:
    action = agent.get_action(state)
    state, reward, terminated, truncated, info = env.step(action)
```

### FlightRecorderEmitter

Export audit logs to LightningStore:

```python
from agent_os import FlightRecorder
from agent_lightning_gov import FlightRecorderEmitter

recorder = FlightRecorder()
emitter = FlightRecorderEmitter(recorder)

# Export to LightningStore
emitter.emit_to_store(lightning_store)

# Or export to file for analysis
emitter.export_to_file("training_audit.json")

# Get violation summary
summary = emitter.get_violation_summary()
print(f"Violation rate: {summary['violation_rate']:.1%}")
```

## Ecosystem

Agent Lightning is one of 7 packages in the Agent Governance Toolkit:

| Package | Role |
|---------|------|
| **Agent OS** | Policy engine — deterministic action evaluation |
| **AgentMesh** | Trust infrastructure — identity, credentials, protocol bridges |
| **Agent Runtime** | Execution supervisor — rings, sessions, sagas |
| **Agent SRE** | Reliability — SLOs, circuit breakers, chaos testing |
| **Agent Compliance** | Regulatory compliance — GDPR, HIPAA, SOX frameworks |
| **Agent Marketplace** | Plugin lifecycle — discover, install, verify, sign |
| **Agent Lightning** | RL training governance — governed runners, policy rewards *(this package)* |

## 📋 License

MIT — see [LICENSE](../../LICENSE).
