# Agent Learning Governance Integration

> [!IMPORTANT]
> **Public Preview.** `agent_learning_gov` targets Microsoft Agent Learning
> `0.8.x`. Its API may change before general availability.

Apply Agent Governance Toolkit controls throughout an Agent Learning lifecycle:

- authorize discrete actions and tool calls during episode capture;
- persist policy decisions, violations, risk, and tool-use telemetry with each
  Agent Learning artifact;
- add compliant-behavior bonuses and violation penalties to aggregate rewards;
- score Bayesian decisions without treating them as REINFORCE samples;
- isolate learned candidates from the active policy until promotion succeeds;
- run explainable governance evaluations before shadow, canary, or production
  rollout;
- emit audit events and persist signed policy lineage.

Agent Learning learns an interpretable policy over discrete actions. This
integration does not fine-tune LLM weights and does not replace Agent Learning's
episode, reward, policy, run, or storage models.

See [ADR-0033](../../docs/adr/0033-agent-learning-governance-integration.md)
for the integration scope, dependency boundary, governance model, and delivery
split.

## Compatibility

This package is built against `microsoft/agent-learning` release `v0.8.0`,
including its two decision routes:

| Authority | Selection basis | Learning treatment |
|---|---|---|
| `low` | `learned_policy` | Requires `action_logprob`; eligible for REINFORCE when governance allows it |
| `full` | `bayesian_decision` | Uses hard constraints, confidence-weighted Bayesian evidence, robust utility, Pareto elimination, and information gain; scored and audited but excluded from REINFORCE |

The `v0.8.0` GitHub release was published on 2026-08-10. At implementation
time, PyPI still reported an older Agent Learning build, so this repository
validated compatibility directly against tag `v0.8.0` without installing the
new release.

## Install from this repository

Until Agent Learning `0.8.x` is available from the configured package index,
install the audited `v0.8.0` source checkout first. Repository maintainers must
apply the seven-day dependency review rule before installing a newly published
upstream release.

```bash
git clone --branch v0.8.0 https://github.com/microsoft/agent-learning.git ../agent-learning
python -m pip install -e ../agent-learning
python -m pip install -e "./agent-governance-python/agent-learning"
```

## Quickstart

```python
import secrets

from agent_learning import InMemoryStore, LearningRunner
from agent_learning_gov import (
    GovernedEpisodeCapture,
    GovernedLearningRunner,
    GovernedPolicyPromotion,
    InMemoryAuditSink,
)
from agent_os.lite import govern

store = InMemoryStore()
audit = InMemoryAuditSink()
kernel = govern(deny=["delete_records"])
provenance_key = secrets.token_bytes(32)

capture = GovernedEpisodeCapture(
    kernel,
    store=store,
    audit_sink=audit,
    provenance_key=provenance_key,
)

# task_policy.decide() returns an Agent Learning DecisionResult.
decision = task_policy.adjudicate(task_policy.decide(), "accept")
context = capture.start(
    "Summarize the account",
    decision_result=decision,
    intent_summary="summarize an account",
    action_type="workflow",
    expected_outcome="return a grounded summary",
)
# Execute the effective action. Governance substitutions update context.action_id.
assistant_output = execute_action(context.action_id)
episode = capture.end(
    context,
    assistant_output,
    execution_status="completed",
    result_summary="returned a grounded summary",
)

learning = LearningRunner(store=store, policy=policy)
runner = GovernedLearningRunner(
    kernel,
    learning,
    audit_sink=audit,
    provenance_key=provenance_key,
)
run = runner.run_offline_batch("account-agent", task_id="summarize")

candidate = runner.last_candidate
promoter = GovernedPolicyPromotion(
    kernel,
    store=store,
    audit_sink=audit,
    provenance_key=provenance_key,
    deploy_callback=deploy_policy,
)
canary = promoter.promote_if_compliant(
  candidate,
  stage="canary",
  baseline={"violation_rate": 0.0},
)
```

## Components

### `GovernedEpisodeCapture`

Delegates to Agent Learning's `EpisodeCapture`, preserving its configured
output/tool redaction and verifying that returned episodes reached stores that
implement the standard `get_episode` contract. It adds:

- pre-action and pre-tool policy checks;
- allowed, denied, warned, or modified decisions;
- normalized risk and violation records;
- tool usage without raw tool arguments or results in governance telemetry;
- `selection_basis` and explicit `reinforce_eligible` metadata;
- a bounded Agent Learning decision certificate for Bayesian lineage;
- policy and episode audit events.

A denied initial action is persisted as a `governance_denied` episode before
`GovernanceDeniedError` is raised. A denied tool attempt is recorded with no
tool result. A pending Bayesian recommendation raises `UnresolvedDecisionError`;
resolve or adjudicate it before starting execution.

Agent Learning `0.8.0` does not redact `user_input`, `system_message`, or
`conversation_history`. Redact or minimize those fields before capture and
protect the durable store accordingly.

`end()` raises `EpisodePersistenceError` when a standard Agent Learning store
returns no persisted episode after capture. Preflight tool authorizations are
bound to the capture ID, tool name, and arguments and are consumed by the first
`record_tool_call()` attempt.

The default provenance key is ephemeral and supports one-process local use.
For durable or multi-process workflows, load one stable key of at least 32
bytes from a secret store and pass it as `provenance_key` to capture, learning,
and promotion. HMAC signatures then reject modified decision certificates,
policy candidates, and rollout receipts without persisting the key itself.

Execute `context.action_id`, not the original proposal, because a policy may
replace an action. Preauthorize tools before invoking them and pass the returned
authorization back when recording the result:

```python
authorization = capture.authorize_tool_call(
  context,
  "lookup_account",
  {"account_id": account_id},
)
tool_name = authorization.effective_action_id
result = execute_tool(tool_name, account_id=account_id)
capture.record_tool_call(
  context,
  "lookup_account",
  {"account_id": account_id},
  result,
  authorization=authorization,
  cost=0.02,
)
```

### `PolicyAwareRewardAdapter`

Shapes only Agent Learning aggregate reward rows and leaves metric rows intact:

```text
final_reward = clamp(
    base_reward + compliant_bonus + sum(violation_penalties),
    -1.0,
    1.0,
)
```

The adapter stores its decomposition under
`reward.metadata["agent_governance"]["reward_shaping"]`. Reapplying it is
idempotent because the original base reward is retained.

### `GovernedLearningRunner`

Runs an offline batch without mutating or activating the supplied policy:

1. query complete episodes from the Agent Learning store;
2. govern legacy episodes that lack capture telemetry;
3. score missing rewards for non-blocked episodes through the wrapped `LearningRunner`;
4. apply governance reward shaping;
5. exclude blocked and Bayesian episodes from REINFORCE;
6. update a deep-copied policy;
7. authorize every candidate action;
8. persist the candidate and governance report inside the `TrainingRun`.

Use `runner.last_candidate` to inspect the isolated candidate. The active
policy pointer remains unchanged.

### `GovernedPolicyPromotion`

Runs policy authorization and the standard evaluation pack. Validation and
canary state remain attached to the run-backed candidate. Before invoking a
production callback, the promoter persists signed production state, emits the
approval audit event, records the current active policy for rollback, and calls
Agent Learning `store_policy()` to activate the candidate. Callback rejection
or failure restores the prior active policy.

Production rollout requires a deployed canary by default. Deployment callbacks
must be synchronous, idempotent, and transactional: an awaitable is rejected,
and a callback that reports failure triggers local rollback. Successful local
activation is not rolled back when only the final deployment-audit emission
fails; inspect `last_audit_error` and application logs for that condition. Every
standard validation requires an explicit approved `violation_rate` baseline.
Production also requires a configured `AuditSink` and a candidate linked to a
training run in a store that implements `get_run()` and `store_run()`; missing
durable infrastructure fails before activation or callback execution.

### `GovernanceEvaluationPack`

The default pack checks:

- Bayesian/REINFORCE decision-route integrity;
- unsafe tool selection;
- excessive privilege;
- restricted action attempts;
- action and observed episode cost ceilings;
- governance violation-rate regression against an approved baseline.

Every check returns independent findings and metrics for audit and remediation.

### Audit models

`InMemoryAuditSink` is intended for tests and notebooks.
`JsonlAuditSink` provides an append-only UTF-8 local audit trail.

## Policy evaluator compatibility

`PolicyEvaluatorAdapter` normalizes synchronous evaluators that expose one of:

- `evaluate(action, content=..., **context)` (AGT Lite);
- `evaluate(action, context)` (OPA, Cedar, or another external backend);
- `evaluate_action`, `authorize`, `is_allowed`, or `check_policy`;
- a compatible callable.

Agent Learning capture and training are synchronous. Async-only policy
evaluators are rejected explicitly instead of being run through a nested event
loop.

## Security notes

- Keep `fail_closed=True` for promotion and runtime enforcement.
- Do not put credentials, raw tokens, or sensitive tool arguments into custom
  governance metadata.
- Use managed identity or workload identity in production Foundry deployments.
- Treat evaluation success as one gate, not proof that a policy is safe for
  every deployment context.
- Keep the default staged rollout requirement for production policies.

## License

MIT. See [LICENSE](LICENSE).
