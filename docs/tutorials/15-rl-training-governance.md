# Tutorial 15 — RL Training Governance

> **Package:** `agentmesh-lightning` · **Time:** 25 minutes · **Prerequisites:** Python 3.10+

---

## What You'll Learn

- GovernedRunner for policy-enforced training loops
- PolicyReward for converting violations into reward signals
- Gym-compatible environments with governance constraints

---

Reinforcement-learning agents learn by trial and error — but in production
systems those "errors" can be SQL injections, budget overruns, or
unauthorised data access.The **agent-lightning** package lets you enforce
governance constraints *during* RL training so the agent learns to be safe
and effective from the very first episode.

This tutorial shows you how to wire an Agent OS policy kernel into the
Agent-Lightning training loop, convert policy violations into reward
penalties, run Gym-compatible training environments, and export audit-grade
logs of every training step.

**What you'll learn:**

| Section | Topic |
|---------|-------|
| [Quick Start](#1-quick-start) | Run a governed RL episode in ten lines |
| [GovernedRunner](#2-governedrunner) | Execute tasks with policy enforcement and violation tracking |
| [PolicyReward](#3-policyreward) | Convert violations to RL penalties with reward shaping |
| [RewardConfig](#4-rewardconfig) | Configure penalty levels and clean-execution bonuses |
| [GovernedEnvironment](#5-governedenvironment) | Gym-compatible training environment with governance |
| [FlightRecorderEmitter](#6-flightrecorderemitter) | Export audit logs and violation summaries |
| [Training Loop Example](#7-full-training-loop) | End-to-end RL training loop with governance |
| [Next Steps](#8-next-steps) | Where to go from here |

See also: [Tutorial 01 — Policy Engine](01-policy-engine.md) | [Tutorial 04 — Audit & Compliance](04-audit-and-compliance.md) | [Tutorial 13 — Observability & Tracing](13-observability-and-tracing.md)

---

## Installation

```bash
# Core package — governed runner, policy rewards, environment, emitter
pip install agentmesh-lightning

# You also need the Agent OS kernel for policy enforcement
pip install agent-os-kernel

# Optional: full toolkit for YAML policies, audit, and compliance
pip install agent-os-kernel[full]
```

### Prerequisites

- Python ≥ 3.9
- An understanding of Agent OS policies ([Tutorial 01](01-policy-engine.md))
- Familiarity with RL concepts (episodes, rewards, environments)
- Optional: `gymnasium` for Gym-compatible usage
- Optional: `agentlightning` for the Agent-Lightning trainer

---

## 1. Quick Start

Ten lines to run a governed RL episode:

```python
from agent_os import KernelSpace
from agent_os.policies import SQLPolicy, CostControlPolicy
from agent_lightning_gov import GovernedRunner, PolicyReward

# 1. Build a kernel with two policies
kernel = KernelSpace(policy=[
    SQLPolicy(deny=["DROP", "DELETE"]),
    CostControlPolicy(max_cost_usd=100),
])

# 2. Create a governed runner
runner = GovernedRunner(kernel)

# 3. Create a policy-aware reward function
def accuracy_reward(rollout):
    return rollout.task_output.accuracy if rollout.success else 0.0

reward_fn = PolicyReward(kernel, base_reward_fn=accuracy_reward)

# 4. Execute a task and score it
rollout = await runner.step("SELECT name FROM users WHERE id = 42")
reward = reward_fn(rollout)

print(f"Success:    {rollout.success}")
print(f"Violations: {len(rollout.violations)}")
print(f"Penalty:    {rollout.total_penalty}")
print(f"Reward:     {reward}")
```

If the agent's action is clean — no policy violations — it earns the base
reward **plus** a clean-execution bonus (default `+5.0`). If it tries
`DROP TABLE users`, the `SQLPolicy` catches it and the reward drops by
`-100.0`.

That's the core idea: **policy violations become negative reward signals**
that steer the agent toward safe behaviour during training.

---

## 2. GovernedRunner

`GovernedRunner` is the heart of the integration. It wraps an Agent OS
`KernelSpace` so every agent action passes through the policy engine before
execution, and violations are recorded as structured data on the rollout.

### 2.1 Creating a Runner

```python
from agent_lightning_gov import GovernedRunner

runner = GovernedRunner(
    kernel,                        # KernelSpace with loaded policies
    fail_on_violation=False,       # True → raise exception on blocked action
    log_violations=True,           # Log every violation via Python logging
    violation_callback=my_handler, # Optional per-violation callback
)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `kernel` | `KernelSpace` | *(required)* | Agent OS kernel with loaded policies |
| `fail_on_violation` | `bool` | `False` | Raise `PolicyViolationError` when an action is blocked |
| `log_violations` | `bool` | `True` | Emit a `WARNING`-level log for every violation |
| `violation_callback` | `callable \| None` | `None` | Called with each `PolicyViolation` object |

### 2.2 Runner Lifecycle

`GovernedRunner` follows the Agent-Lightning runner protocol with four
lifecycle hooks:

```python
# Called once during setup
runner.init(agent)

# Called once per worker in distributed training
runner.init_worker(worker_id=0, store=lightning_store)

# --- training happens here (see step / iter below) ---

# Called once per worker at shutdown
runner.teardown_worker(worker_id=0)

# Called once at the end
runner.teardown()
```

### 2.3 Executing a Single Step

The `step` method runs one task through the kernel and returns a
`GovernedRollout`:

```python
rollout = await runner.step(
    input="SELECT * FROM orders WHERE total > 1000",
    mode="train",   # "train" or "eval"
)

print(rollout.success)          # True if execution completed
print(rollout.task_output)      # Agent's output
print(rollout.violations)       # List[PolicyViolation]
print(rollout.signals_sent)     # Kernel signals (SIGSTOP, etc.)
print(rollout.total_penalty)    # Sum of violation penalties
print(rollout.execution_time_ms)
```

### 2.4 GovernedRollout

Every call to `step` returns a `GovernedRollout` dataclass:

```python
@dataclass
class GovernedRollout:
    task_input: Any
    task_output: Any
    success: bool
    violations: list[PolicyViolation]   # all violations during this step
    signals_sent: list[str]             # kernel signals dispatched
    total_penalty: float                # sum of violation penalties
    execution_time_ms: float
```

The `total_penalty` is auto-calculated in `__post_init__` as the sum of
`violation.penalty` for every violation on the rollout.

### 2.5 PolicyViolation and PolicyViolationType

Each violation is a structured record:

```python
from agent_lightning_gov.runner import PolicyViolation, PolicyViolationType

# PolicyViolationType enum
PolicyViolationType.BLOCKED       # Action was blocked entirely
PolicyViolationType.MODIFIED      # Action was modified before execution
PolicyViolationType.WARNED        # Warning issued but action allowed
PolicyViolationType.SIGNAL_SENT   # Kernel signal dispatched (SIGSTOP, etc.)
```

```python
@dataclass
class PolicyViolation:
    violation_type: PolicyViolationType
    policy_name: str         # e.g. "SQLPolicy"
    description: str         # human-readable explanation
    severity: str            # "critical", "high", "medium", "low"
    timestamp: datetime
    action_blocked: bool
    penalty: float           # auto-calculated from severity
```

Severity-to-penalty mapping (set in `__post_init__`):

| Severity | Default Penalty |
|----------|-----------------|
| `critical` | `100.0` |
| `high` | `50.0` |
| `medium` | `10.0` |
| `low` | `1.0` |

### 2.6 Continuous Execution with `iter`

For long-running training, `iter` pulls tasks from the store and submits
rollouts automatically:

```python
import asyncio

# Run until the stop event is set
stop = asyncio.Event()
await runner.iter(event=stop)

# In another coroutine, stop after 1000 episodes:
stop.set()
```

### 2.7 Runner Statistics

Track violation rates across the entire training run:

```python
stats = runner.get_stats()
print(stats)
# {
#     "total_rollouts": 1500,
#     "total_violations": 23,
#     "violation_rate": 0.0153,
# }

# Or just the rate:
rate = runner.get_violation_rate()  # 0.0153
```

### 2.8 Violation Callback Example

Use a callback to collect violations in a custom data structure:

```python
violation_log = []

def on_violation(violation: PolicyViolation):
    violation_log.append({
        "policy": violation.policy_name,
        "severity": violation.severity,
        "blocked": violation.action_blocked,
        "time": violation.timestamp.isoformat(),
    })

runner = GovernedRunner(
    kernel,
    violation_callback=on_violation,
)
```

---

## 3. PolicyReward

`PolicyReward` converts policy violations into RL reward signals. It wraps
any base reward function and adjusts the final score based on governance
outcomes.

### 3.1 Basic Usage

```python
from agent_lightning_gov import PolicyReward

# Define your base task reward
def task_reward(rollout):
    if rollout.success and rollout.task_output:
        return rollout.task_output.accuracy  # 0.0–1.0
    return 0.0

# Wrap it with policy awareness
reward_fn = PolicyReward(kernel, base_reward_fn=task_reward)

# Score a rollout
reward = reward_fn(rollout)
```

The reward calculation follows this flow:

```
base_reward = task_reward(rollout)          # e.g. 0.85
penalty     = sum of violation penalties    # e.g. -50.0
bonus       = clean_bonus if no violations  # e.g. +5.0

final_reward = base_reward + penalty + bonus
final_reward = clamp(final_reward, min_reward, max_reward)
```

### 3.2 Default Base Reward

If you don't provide a `base_reward_fn`, the default returns `1.0` for
success and `0.0` for failure:

```python
# Uses the built-in default: 1.0 if success, else 0.0
reward_fn = PolicyReward(kernel)
```

### 3.3 Multiplicative Mode

Instead of adding penalties, you can multiply the base reward by a factor
when violations occur:

```python
from agent_lightning_gov.reward import RewardConfig

config = RewardConfig(
    multiplicative=True,
    multiplicative_factor=0.5,  # halve reward on any violation
)

reward_fn = PolicyReward(kernel, config=config)

# If base_reward = 0.9 and there's a violation:
# final = 0.9 * 0.5 = 0.45  (instead of 0.9 + penalty)
```

### 3.4 Reward Statistics

Track aggregate reward metrics during training:

```python
stats = reward_fn.get_stats()
print(stats)
# {
#     "total_rewards": 500,
#     "total_penalties": -1240.0,
#     "avg_penalty": -2.48,
#     "violation_rate": 0.032,
#     "clean_rate": 0.968,
# }

# Reset between phases
reward_fn.reset_stats()
```

### 3.5 Standalone Penalty Helper

For quick scripting, `policy_penalty` is a module-level helper that
calculates penalties without the full `PolicyReward` class:

```python
from agent_lightning_gov import policy_penalty

penalty = policy_penalty(
    rollout.violations,
    critical_penalty=-200.0,
    high_penalty=-80.0,
    medium_penalty=-15.0,
    low_penalty=-2.0,
)

final_reward = base_reward + penalty
```

### 3.6 CompositeReward

Combine multiple reward dimensions with weights:

```python
from agent_lightning_gov.reward import CompositeReward

reward = CompositeReward(
    components=[
        (accuracy_reward, 1.0),    # task accuracy (weight 1.0)
        (policy_reward, 0.5),      # governance penalty (weight 0.5)
        (efficiency_reward, 0.3),  # speed bonus (weight 0.3)
    ],
    normalize=False,  # True → weights sum to 1.0
)

score = reward(rollout)  # weighted sum of all components
```

With `normalize=True`, weights are automatically rescaled so they sum to
1.0 — useful when you want to express relative importance without manually
normalising.

### 3.7 Factory Function

`create_policy_reward` provides a convenient one-liner:

```python
from agent_lightning_gov.reward import create_policy_reward

reward_fn = create_policy_reward(
    kernel,
    base_reward_fn=accuracy_reward,
    severity_penalties={
        "critical": -200.0,
        "high": -80.0,
        "medium": -15.0,
        "low": -2.0,
    },
    clean_bonus=10.0,
    multiplicative=False,
)
```

---

## 4. RewardConfig

`RewardConfig` is a dataclass that centralises all reward-shaping
parameters. Pass it to `PolicyReward` to override defaults.

### 4.1 Full Reference

```python
from agent_lightning_gov.reward import RewardConfig

config = RewardConfig(
    # Per-severity penalties (additive mode)
    critical_penalty=-100.0,   # default: -100.0
    high_penalty=-50.0,        # default: -50.0
    medium_penalty=-10.0,      # default: -10.0
    low_penalty=-1.0,          # default: -1.0

    # Clean-execution bonus
    clean_bonus=5.0,           # default: 5.0

    # Multiplicative mode
    multiplicative=False,      # default: False
    multiplicative_factor=0.5, # default: 0.5 — only used when multiplicative=True

    # Reward bounds
    min_reward=-100.0,         # default: -100.0 — floor (None to disable)
    max_reward=100.0,          # default: 100.0  — ceiling (None to disable)
)
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `critical_penalty` | `float` | `-100.0` | Penalty per critical-severity violation |
| `high_penalty` | `float` | `-50.0` | Penalty per high-severity violation |
| `medium_penalty` | `float` | `-10.0` | Penalty per medium-severity violation |
| `low_penalty` | `float` | `-1.0` | Penalty per low-severity violation |
| `clean_bonus` | `float` | `5.0` | Reward added when no violations occur |
| `multiplicative` | `bool` | `False` | Use multiplicative penalty instead of additive |
| `multiplicative_factor` | `float` | `0.5` | Factor to multiply base reward by on violation |
| `min_reward` | `float \| None` | `-100.0` | Minimum reward floor (`None` to disable) |
| `max_reward` | `float \| None` | `100.0` | Maximum reward ceiling (`None` to disable) |

### 4.2 Tuning Guidelines

**Conservative** — use during early training when the agent needs strong
safety signals:

```python
conservative = RewardConfig(
    critical_penalty=-200.0,
    high_penalty=-100.0,
    medium_penalty=-30.0,
    low_penalty=-5.0,
    clean_bonus=10.0,
)
```

**Lenient** — use for fine-tuning when violation rates are already low:

```python
lenient = RewardConfig(
    critical_penalty=-50.0,
    high_penalty=-20.0,
    medium_penalty=-5.0,
    low_penalty=-0.5,
    clean_bonus=2.0,
)
```

**Unbounded** — disable reward clamping for advanced algorithms:

```python
unbounded = RewardConfig(
    min_reward=None,
    max_reward=None,
)
```

---

## 5. GovernedEnvironment

`GovernedEnvironment` wraps the Agent OS kernel as a Gym-compatible
training environment. It follows the standard `reset` / `step` interface
used by OpenAI Gymnasium, Stable Baselines3, and Agent-Lightning trainers.

### 5.1 Creating an Environment

```python
from agent_lightning_gov import GovernedEnvironment
from agent_lightning_gov.environment import EnvironmentConfig

env = GovernedEnvironment(
    kernel,
    task_generator=generate_sql_task,  # returns initial state each episode
    reward_fn=custom_reward,           # (state, action, result) → float
    config=EnvironmentConfig(
        max_steps=100,
        terminate_on_critical=True,
        violation_penalty=-10.0,
        step_penalty=-0.1,
        success_bonus=10.0,
        reset_kernel_state=True,
    ),
)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `kernel` | `KernelSpace` | *(required)* | Agent OS kernel with loaded policies |
| `task_generator` | `Callable[[], T_state] \| None` | `None` | Function that generates an initial state for each episode |
| `reward_fn` | `Callable[[state, action, result], float] \| None` | `None` | Custom reward function; default returns `1.0` if result is not `None` |
| `config` | `EnvironmentConfig \| None` | `None` | Environment configuration (see below) |

### 5.2 EnvironmentConfig

```python
@dataclass
class EnvironmentConfig:
    max_steps: int = 100              # Maximum steps before truncation
    violation_penalty: float = -10.0  # Base penalty per violation
    terminate_on_critical: bool = True # End episode on critical violation
    step_penalty: float = -0.1        # Small per-step cost (encourages efficiency)
    success_bonus: float = 10.0       # Bonus for clean, successful steps
    reset_kernel_state: bool = True   # Reset kernel state on env.reset()
```

The `violation_penalty` is scaled by severity during `step`:
- **critical** → `violation_penalty × 10`
- **high** → `violation_penalty × 5`
- **medium** → `violation_penalty × 1`
- **low** → `violation_penalty × 1`

### 5.3 Episode Loop

```python
state, info = env.reset(seed=42)
print(info)
# {"episode": 1, "kernel_policies": ["SQLPolicy", "CostControlPolicy"]}

while not env.terminated:
    action = agent.get_action(state)
    state, reward, terminated, truncated, info = env.step(action)

    print(f"Step {info['step']:3d}  reward={reward:+.2f}  "
          f"violations={len(info['violations'])}")
```

The five-element return tuple matches the Gymnasium `step` signature:

| Element | Type | Description |
|---------|------|-------------|
| `state` | `T_state` | Next observation (current task) |
| `reward` | `float` | Step reward with penalties applied |
| `terminated` | `bool` | `True` if episode ended by critical violation |
| `truncated` | `bool` | `True` if `max_steps` reached |
| `info` | `dict` | Violations, step count, total reward, success flag |

### 5.4 Termination Conditions

An episode can end for two reasons:

1. **Terminated** — a critical-severity policy violation (when
   `terminate_on_critical=True`). This sends a strong signal that
   certain actions are never acceptable.

2. **Truncated** — the agent reaches `max_steps`. The episode is cut
   short but not considered a failure.

```python
# Example: terminate on critical, allow 50 steps
config = EnvironmentConfig(
    max_steps=50,
    terminate_on_critical=True,
)
```

### 5.5 Custom Task Generator

Provide a callable that returns a fresh task for each episode:

```python
import random

SQL_TEMPLATES = [
    "SELECT name FROM users WHERE id = {id}",
    "UPDATE orders SET status = 'shipped' WHERE order_id = {id}",
    "INSERT INTO logs (message) VALUES ('{msg}')",
]

def generate_sql_task():
    template = random.choice(SQL_TEMPLATES)
    return template.format(id=random.randint(1, 1000), msg="agent action")

env = GovernedEnvironment(kernel, task_generator=generate_sql_task)
```

### 5.6 Environment Metrics

After training, inspect aggregate metrics:

```python
metrics = env.get_metrics()
print(metrics)
# {
#     "total_episodes": 200,
#     "total_steps": 12400,
#     "total_violations": 87,
#     "successful_episodes": 168,
#     "success_rate": 0.84,
#     "violations_per_episode": 0.435,
#     "steps_per_episode": 62.0,
# }
```

### 5.7 Factory Function

For quick setup, use `create_governed_env`:

```python
from agent_lightning_gov.environment import create_governed_env

env = create_governed_env(
    kernel,
    max_steps=200,
    terminate_on_critical=True,
    violation_penalty=-20.0,
)
```

Any keyword argument that matches an `EnvironmentConfig` field is
forwarded automatically.

---

## 6. FlightRecorderEmitter

`FlightRecorderEmitter` bridges the Agent OS Flight Recorder and
Agent-Lightning's span-based telemetry. It converts Flight Recorder entries
(policy checks, signals, tool calls) into `LightningSpan` objects that
can be stored, exported, and analysed.

### 6.1 Creating an Emitter

```python
from agent_os import FlightRecorder
from agent_lightning_gov import FlightRecorderEmitter

recorder = FlightRecorder()

emitter = FlightRecorderEmitter(
    recorder,
    include_policy_checks=True,   # include policy evaluation spans
    include_signals=True,          # include kernel signal spans
    include_tool_calls=True,       # include tool invocation spans
    trace_id_prefix="agentos",     # prefix for generated trace IDs
)
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `flight_recorder` | `FlightRecorder` | *(required)* | Agent OS Flight Recorder instance |
| `include_policy_checks` | `bool` | `True` | Emit spans for policy check events |
| `include_signals` | `bool` | `True` | Emit spans for kernel signal events |
| `include_tool_calls` | `bool` | `True` | Emit spans for tool call events |
| `trace_id_prefix` | `str` | `"agentos"` | Prefix for generated trace IDs |

### 6.2 LightningSpan

Each Flight Recorder entry is converted to a `LightningSpan`:

```python
from agent_lightning_gov.emitter import LightningSpan

span = LightningSpan(
    span_id="entry-001",
    trace_id="agentos-agent-42",
    name="agent_os.policy_check",
    start_time=datetime.now(timezone.utc),
    end_time=datetime.now(timezone.utc),
    attributes={
        "agent_os.entry_type": "policy_check",
        "agent_os.agent_id": "agent-42",
        "agent_os.policy_name": "SQLPolicy",
        "agent_os.policy_result": "denied",
        "agent_os.policy_violated": True,
    },
    events=[],
)

# Serialise for storage
span_dict = span.to_dict()
span_json = span.to_json()
```

Span attributes vary by entry type:

| Entry Type | Attributes |
|------------|------------|
| `policy_check` | `policy_name`, `policy_result`, `policy_violated` |
| `signal` | `signal_type`, `signal_target` |
| `tool_call` | `tool_name`, `tool_args` (truncated to 1000 chars), `tool_result` (truncated) |

All spans also include `agent_os.entry_type` and `agent_os.agent_id`.

### 6.3 Emitting to LightningStore

Push all spans to an Agent-Lightning store:

```python
count = emitter.emit_to_store(lightning_store)
print(f"Emitted {count} spans")
```

The emitter looks for `emit_span` or `add_span` on the store object, so
it works with any compatible store implementation.

### 6.4 Exporting to File

For offline analysis or compliance archival:

```python
count = emitter.export_to_file("training_audit.json")
print(f"Exported {count} spans to training_audit.json")
```

The output is a JSON array of span dictionaries — one per Flight Recorder
entry.

### 6.5 Streaming Spans

For real-time monitoring during training:

```python
async for span in emitter.stream():
    print(f"{span.name}: {span.attributes}")

    # Or forward to your own telemetry backend
    otel_exporter.export(span.to_dict())
```

The stream polls for new entries every 100 ms (using `get_new_spans`
internally).

### 6.6 Violation Summary

Get an aggregate view of policy violations from the recorded entries:

```python
summary = emitter.get_violation_summary()
print(summary)
# {
#     "total_entries": 1200,
#     "total_violations": 34,
#     "violation_rate": 0.028,
#     "policies_violated": {
#         "SQLPolicy": 22,
#         "CostControlPolicy": 12,
#     },
# }
```

### 6.7 Incremental Export

`get_new_spans` returns only entries added since the last call — useful
for periodic batch exports:

```python
# First call: gets all spans
batch_1 = emitter.get_new_spans()

# ... training continues ...

# Second call: only spans added since batch_1
batch_2 = emitter.get_new_spans()
```

### 6.8 Factory Function

```python
from agent_lightning_gov.emitter import create_emitter

emitter = create_emitter(
    recorder,
    include_policy_checks=True,
    include_signals=False,
    trace_id_prefix="my-training-run",
)
```

---

## 7. Full Training Loop

This section brings everything together into a complete RL training loop
with governance. The agent learns a SQL query task while the kernel
enforces data-safety policies.

### 7.1 Setup

```python
import asyncio
import logging
from agent_os import KernelSpace, FlightRecorder
from agent_os.policies import SQLPolicy, CostControlPolicy
from agent_lightning_gov import (
    GovernedRunner,
    GovernedEnvironment,
    PolicyReward,
    FlightRecorderEmitter,
)
from agent_lightning_gov.reward import RewardConfig
from agent_lightning_gov.environment import EnvironmentConfig

logging.basicConfig(level=logging.INFO)

# ── Kernel with policies ──
kernel = KernelSpace(policy=[
    SQLPolicy(deny=["DROP", "DELETE", "TRUNCATE"]),
    CostControlPolicy(max_cost_usd=50),
])

# ── Flight recorder for audit trail ──
recorder = FlightRecorder()
```

### 7.2 Configure Components

```python
# ── Reward shaping ──
reward_config = RewardConfig(
    critical_penalty=-100.0,
    high_penalty=-50.0,
    medium_penalty=-10.0,
    low_penalty=-1.0,
    clean_bonus=5.0,
    min_reward=-100.0,
    max_reward=100.0,
)

def task_accuracy(rollout):
    """Base reward: how well the agent completed the task."""
    if not rollout.success:
        return 0.0
    output = rollout.task_output
    return getattr(output, "accuracy", 1.0) if output else 0.0

reward_fn = PolicyReward(
    kernel,
    base_reward_fn=task_accuracy,
    config=reward_config,
)

# ── Governed runner ──
violation_log = []

runner = GovernedRunner(
    kernel,
    fail_on_violation=False,
    log_violations=True,
    violation_callback=lambda v: violation_log.append(v),
)

# ── Governed environment ──
import random

def generate_task():
    templates = [
        "SELECT name FROM users WHERE id = {id}",
        "SELECT email FROM contacts WHERE company = 'Acme'",
        "UPDATE orders SET status = 'complete' WHERE id = {id}",
    ]
    return random.choice(templates).format(id=random.randint(1, 500))

env_config = EnvironmentConfig(
    max_steps=50,
    terminate_on_critical=True,
    violation_penalty=-10.0,
    step_penalty=-0.1,
    success_bonus=10.0,
)

env = GovernedEnvironment(
    kernel,
    task_generator=generate_task,
    config=env_config,
)

# ── Audit emitter ──
emitter = FlightRecorderEmitter(recorder)
```

### 7.3 Training Loop

```python
NUM_EPISODES = 200
episode_rewards = []

async def train():
    runner.init(agent=my_agent)

    for episode in range(NUM_EPISODES):
        state, info = env.reset(seed=episode)
        episode_reward = 0.0

        while not env.terminated:
            # Agent selects an action
            action = my_agent.get_action(state)

            # Execute through governed environment
            state, reward, terminated, truncated, info = env.step(action)
            episode_reward += reward

            # Also run through governed runner for detailed rollout
            rollout = await runner.step(action, mode="train")
            shaped_reward = reward_fn(rollout)

            # Feed reward back to agent for learning
            my_agent.update(state, action, shaped_reward)

        episode_rewards.append(episode_reward)

        # Log progress every 20 episodes
        if (episode + 1) % 20 == 0:
            recent = episode_rewards[-20:]
            avg_reward = sum(recent) / len(recent)
            stats = runner.get_stats()
            print(
                f"Episode {episode + 1:4d}  "
                f"avg_reward={avg_reward:+.2f}  "
                f"violation_rate={stats['violation_rate']:.3f}"
            )

    runner.teardown()

asyncio.run(train())
```

### 7.4 Post-Training Analysis

```python
# ── Runner statistics ──
print("Runner stats:", runner.get_stats())

# ── Reward statistics ──
print("Reward stats:", reward_fn.get_stats())

# ── Environment metrics ──
print("Env metrics:", env.get_metrics())

# ── Violation summary from Flight Recorder ──
summary = emitter.get_violation_summary()
print(f"Violation rate: {summary['violation_rate']:.1%}")
print(f"Policies violated: {summary['policies_violated']}")

# ── Export full audit trail ──
emitter.export_to_file("training_audit.json")
print("Audit trail exported to training_audit.json")

# ── Export to LightningStore for dashboard ──
# emitter.emit_to_store(lightning_store)
```

### 7.5 Integration with Agent-Lightning Trainer

If you're using the full Agent-Lightning `Trainer`, plug in the governed
runner directly:

```python
from agentlightning import Trainer

trainer = Trainer(
    runner=runner,
    reward_fn=reward_fn,
    algorithm="GRPO",
)

trainer.train(num_epochs=100)
```

The `Trainer` calls `runner.step` internally, so all governance
constraints are enforced automatically during training.

### 7.6 Distributed Training

`GovernedRunner` supports Agent-Lightning's distributed training. Each
worker gets its own kernel hook but shares violation statistics through
the store:

```python
from agentlightning import Trainer

trainer = Trainer(
    runner=runner,
    reward_fn=reward_fn,
    algorithm="GRPO",
    num_workers=4,   # 4 parallel governed workers
)

# Each worker calls runner.init_worker(worker_id, store)
# Violations are tracked per-worker and aggregated
trainer.train(num_epochs=100)
```

---

## 8. Next Steps

You now have the tools to enforce governance constraints during RL
training. Here's where to go next:

| Goal | Resource |
|------|----------|
| Define custom YAML policies for your domain | [Tutorial 01 — Policy Engine](01-policy-engine.md) |
| Add tamper-proof audit logging to training | [Tutorial 04 — Audit & Compliance](04-audit-and-compliance.md) |
| Wire up distributed tracing and metrics | [Tutorial 13 — Observability & Tracing](13-observability-and-tracing.md) |
| Sandbox agent execution during training | [Tutorial 06 — Execution Sandboxing](06-execution-sandboxing.md) |
| Add reliability (SLOs, circuit breakers) | [Tutorial 05 — Agent Reliability](05-agent-reliability.md) |
| Browse the full Agent-Lightning README | [`agent-governance-python/agent-lightning/README.md`](../../agent-governance-python/agent-lightning/README.md) |

### Key takeaways

1. **GovernedRunner** wraps Agent-Lightning's runner protocol — drop it in
   and every agent action passes through the kernel policy engine.
2. **PolicyReward** turns violations into negative reward signals, teaching
   the agent to avoid unsafe actions during training — not just in production.
3. **RewardConfig** gives you fine-grained control over penalty severity,
   clean-execution bonuses, and reward bounds.
4. **GovernedEnvironment** provides a standard Gym `reset`/`step` interface
   so you can use governance with any RL framework.
5. **FlightRecorderEmitter** ensures every training step is auditable — the
   same Flight Recorder that protects production also covers training.
6. The net result: **agents that learn to be safe from the start**, with
   0% policy violations achievable before the model ever reaches production.

---

*Part of the [Agent Governance Toolkit](../../README.md) tutorial series.*
