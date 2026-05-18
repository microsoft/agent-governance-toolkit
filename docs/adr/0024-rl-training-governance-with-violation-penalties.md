# ADR-0024: RL Training Governance with Violation Penalties

## Status

Accepted

## Context

Agent Lightning provides reinforcement learning infrastructure for agent
optimization. Without governance integration, RL training could:

- Reward policy-violating behavior (if violations lead to higher task completion)
- Produce agents that learn to circumvent governance controls
- Generate training data that includes unsafe action sequences

We needed training-time governance that discourages policy violations through
the reward signal itself, rather than relying solely on runtime enforcement.

## Decision

`GovernedEnvironment` wraps the RL environment with violation-aware reward
shaping:

- Each policy violation incurs a **penalty** subtracted from the reward signal
- Severity levels map to penalty magnitudes:
  - `critical` -- episode termination (agent is stopped immediately)
  - `high` -- large negative reward
  - `medium` -- moderate negative reward
  - `low` -- small negative reward
- Violation records include: `policy`, `description`, `severity`, `blocked`,
  `step`, `timestamp`
- `FlightRecorderEmitter` exports training spans with full policy evaluation
  context for audit

Key design choices:
- Penalties are configurable per deployment (not hardcoded)
- Critical violations terminate the episode, preventing further unsafe exploration
- All violations are recorded regardless of severity for audit trail
- Training audit spans carry `agent_os.*` prefixed attributes for policy
  name, result, and violation status

## Consequences

- Agents learn that policy violations are costly, shaping behavior toward compliance
- Critical violations prevent unsafe exploration entirely
- Training audit trail enables post-hoc analysis of what the agent learned
- Penalty magnitudes can be tuned without code changes
- No modification to the underlying RL algorithm required -- works with any
  algorithm that uses scalar rewards

## References

- `agent-governance-python/agent-lightning/src/agent_lightning_gov/environment.py`
- `agent-governance-python/agent-lightning/src/agent_lightning_gov/emitter.py`
- `docs/specs/AGENT-LIGHTNING-FAST-PATH-1.0.md`
- `docs/specs/AUDIT-COMPLIANCE-1.0.md` Section 20
