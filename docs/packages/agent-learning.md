---
title: Agent Learning Governance
last_reviewed: 2026-08-20
owner: agt-maintainers
---

# Agent Learning Governance

!!! important "Public Preview"
    `agent_learning_gov` is a source package targeting Microsoft Agent Learning
    `0.8.x`. The integration API may change before general availability.

`agent_learning_gov` applies Agent Governance Toolkit controls across the
Agent Learning lifecycle while preserving Agent Learning's discrete-action
policy architecture.

| Layer | Integration capability |
|---|---|
| Episode capture | Pre-action and pre-tool policy checks; durable decisions, violations, risk, and tool-use metadata |
| Evaluation and rewards | Agent Learning scoring plus bounded governance bonuses and penalties |
| Offline learning | Governed batches, Bayesian episode exclusion from REINFORCE, candidate action validation |
| Policy lineage | Run-backed candidates with parent policy and training-run identifiers |
| Promotion | Explainable evaluation suite, shadow/canary/production stages, fail-closed activation |
| Operations | JSONL audit events and signed decision, candidate, and rollout provenance |

## Source

Package source: `agent-governance-python/agent-learning`

The package name and import name are both `agent_learning_gov`.

## Compatibility

The implementation is validated against
[`microsoft/agent-learning` tag `v0.8.0`](https://github.com/microsoft/agent-learning/releases/tag/v0.8.0).
That release introduces a unified task-policy decision surface with two routes:

| Authority | Selection | Governance treatment |
|---|---|---|
| `low` | Learned softmax policy | Policy checked; requires a behavior-policy `action_logprob`; may train with REINFORCE |
| `full` | Bayesian `DecisionFrame` resolution | Constraints and evidence are audited; no `action_logprob`; scored but never used as a REINFORCE sample |

Full-authority decisions use confidence-weighted Bayesian evidence,
information gain, robust utility, Pareto elimination, and explicit user
adjudication when required. The governance integration does not reinterpret
those calculations. It enforces policy around the selected action and preserves
their certificate in lineage and audit data.

## Install

At the time of this review, GitHub release `v0.8.0` is newer than the version
reported by PyPI. For repository development, use the tagged Agent Learning
source and install this package from the AGT checkout. Maintainers must apply
the repository's seven-day dependency review rule before installing a newly
published release:

```bash
git clone --branch v0.8.0 https://github.com/microsoft/agent-learning.git ../agent-learning
python -m pip install -e ../agent-learning
python -m pip install -e "./agent-governance-python/agent-learning"
```

## Public API

### Lifecycle

- `GovernedEpisodeCapture`
- `EpisodePersistenceError`
- `UnresolvedDecisionError`
- `PolicyAwareRewardAdapter`
- `GovernedLearningRunner`
- `GovernedPolicyPromotion`
- `GovernanceEvaluationPack`

### Audit

- `AuditEvent`
- `InMemoryAuditSink`
- `JsonlAuditSink`

### Durable governance metadata

- `GovernanceTelemetry`
- `PolicyDecisionRecord`
- `GovernanceViolation`
- `ToolUsageRecord`
- `GovernanceOutcome`
- `RiskLevel`

All metadata is stored under the stable `agent_governance` key on Agent
Learning episodes, rewards, policy snapshots, and training runs.

Decision, candidate, and rollout provenance uses HMAC-SHA256. The default key
is process-local; durable workflows pass the same secret-backed
`provenance_key` to capture, learning, and promotion.

Only `DecisionStatus.RESOLVED` decisions can start capture. Execute the action
from `CaptureContext.action_id`, because governance may substitute a different
action and clear the original behavior-policy log probability. Use
`authorize_tool_call()` before invoking a tool; execute its
`effective_action_id`, then pass that one-shot authorization to
`record_tool_call()` with the same arguments.

## Promotion safety

Agent Learning `0.8.0` treats `LearningStore.store_policy()` as both persistence
and activation. The integration therefore keeps candidates inside
`TrainingRun.metadata` through validation and canary rollout. A deployed canary
and an explicit approved violation-rate baseline are required for production.
Production persists signed state and approval audit, activates the candidate,
and then invokes the synchronous callback. Callback rejection restores the
prior active policy. A configured audit sink and run-backed candidate storage
are mandatory for production.

This prevents evaluation, blocked promotion, canary persistence, or failed
production preparation from silently replacing the active policy.

## Next steps

- Review the [reference architecture](../integrations/agent-learning-governance.md).
- Read [ADR-0033](../adr/0033-agent-learning-governance-integration.md) for the
  dependency, governance, and delivery decisions.
