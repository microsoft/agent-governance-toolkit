---
title: Tutorial 56 - Govern Agent Learning
last_reviewed: 2026-08-20
owner: agt-maintainers
---

# Tutorial 56 - Govern Agent Learning

> **Package:** `agent_learning_gov` | **Time:** 30 minutes | **Prerequisites:** Python 3.11+

This tutorial captures governed episodes, shapes rewards, runs an offline
REINFORCE update, audits a full-authority Bayesian decision, validates the
candidate, and promotes it through canary and production stages.

## 1. Prepare source checkouts

Agent Learning `v0.8.0` is available as a GitHub release. At the time of this
review, the PyPI package still reports an older version.

```bash
git clone --branch v0.8.0 https://github.com/microsoft/agent-learning.git ../agent-learning
python -m pip install -e ../agent-learning
python -m pip install -e "./agent-governance-python/agent-learning"
```

Verify the target version:

```bash
python -c "import agent_learning; print(agent_learning.__version__)"
```

The output must start with `0.8.`.

Repository maintainers must apply the seven-day dependency review rule before
installing a newly published upstream release.

## 2. Create a policy and governance gate

```python
import secrets

from agent_learning import Action, InMemoryStore, SoftmaxPolicy
from agent_learning_gov import InMemoryAuditSink
from agent_os.lite import govern

store = InMemoryStore()
audit = InMemoryAuditSink()
kernel = govern(deny=["delete_records"])
provenance_key = secrets.token_bytes(32)

policy = SoftmaxPolicy.from_actions(
    [
        Action(id="grounded_summary", parameters={"role": "user"}),
        Action(id="fast_summary", parameters={"role": "user"}),
    ],
    agent_id="account-agent",
    task_id="choose-summary-strategy",
)
parent = policy.snapshot()
store.store_policy(parent)
```

The action IDs map to executable strategies in your application. The learner
updates only their interpretable logits.

## 3. Capture governed learned-policy episodes

```python
from agent_learning import CaptureConfig, Reward, RewardSource, TaskPolicy
from agent_learning_gov import GovernedEpisodeCapture

capture = GovernedEpisodeCapture(
    kernel,
    config=CaptureConfig(
        enabled=True,
        agent_id="account-agent",
        task_id="choose-summary-strategy",
    ),
    store=store,
    audit_sink=audit,
    provenance_key=provenance_key,
)

for index in range(5):
    action_id = "grounded_summary" if index else "fast_summary"
    task_policy = TaskPolicy(policy.snapshot())
    decision = task_policy.adjudicate(
        task_policy.decide(selected_action_id=action_id),
        "accept",
    )
    context = capture.start(
        f"Summarize account {index}",
        decision_result=decision,
        intent_summary="summarize an account",
        action_type="workflow",
        expected_outcome="return a grounded summary",
    )
    episode = capture.end(
        context,
        "Grounded summary" if action_id == "grounded_summary" else "Fast summary",
        execution_status="completed",
        result_summary="returned a summary",
    )
    store.store_reward(
        Reward(
            episode_id=episode.id,
            agent_id=episode.agent_id,
            source=RewardSource.AGGREGATE,
            value=0.85 if action_id == "grounded_summary" else 0.25,
        )
    )
```

Each episode now contains the policy decision, risk, compliance result,
selection basis, and REINFORCE eligibility under `metadata.agent_governance`.
Execute `context.action_id`; it contains any policy-approved replacement.

For tools, authorize before execution and record against the same certificate:

```python
authorization = capture.authorize_tool_call(
    context,
    "lookup_account",
    {"account_id": "42"},
)
result = execute_tool(authorization.effective_action_id, account_id="42")
capture.record_tool_call(
    context,
    "lookup_account",
    {"account_id": "42"},
    result,
    authorization=authorization,
    cost=0.02,
)
```

## 4. Capture a Bayesian decision

Create a full-authority snapshot over the same actions:

```python
from agent_learning import (
    DecisionAuthority,
    DecisionCriterion,
    DecisionFrame,
    DecisionOption,
    EvidencePoint,
)

snapshot = policy.snapshot()
snapshot.metadata["decision_authority"] = DecisionAuthority.FULL.value
actions = {action.id: action for action in snapshot.actions}

frame = DecisionFrame(
    task="Choose a strategy for a regulated account",
    criteria=[
        DecisionCriterion(id="grounding", weight=0.7),
        DecisionCriterion(id="latency", weight=0.3),
    ],
    constraints=["data_residency"],
    options=[
        DecisionOption(
            action=actions["grounded_summary"],
            constraint_results={"data_residency": True},
            evidence=[
                EvidencePoint(
                    criterion_id="grounding",
                    source="evaluation",
                    support=0.95,
                ),
                EvidencePoint(
                    criterion_id="latency",
                    source="telemetry",
                    support=0.70,
                ),
            ],
        ),
        DecisionOption(
            action=actions["fast_summary"],
            constraint_results={"data_residency": True},
            evidence=[
                EvidencePoint(
                    criterion_id="grounding",
                    source="evaluation",
                    support=0.45,
                ),
                EvidencePoint(
                    criterion_id="latency",
                    source="telemetry",
                    support=0.90,
                ),
            ],
        ),
    ],
)

task_policy = TaskPolicy(snapshot)
decision = task_policy.decide(frame)
if decision.status.value != "resolved":
    decision = task_policy.adjudicate(decision, "accept")
assert decision.status.value == "resolved"
context = capture.start(
    "Summarize the regulated account",
    decision_result=decision,
    intent_summary="summarize a regulated account",
    action_type="workflow",
    expected_outcome="return a compliant summary",
)
bayesian_episode = capture.end(
    context,
    "Grounded regulated-account summary",
    execution_status="completed",
    result_summary="returned a compliant summary",
)

assert decision.selection_basis == "bayesian_decision"
assert bayesian_episode.action_logprob is None
```

Attach an evaluation reward as usual. The episode remains available for
quality analysis, but the governed runner will not treat it as a behavior-policy
sample.

If the resolver returns `needs_evidence`, `needs_user_tie_break`, or
`needs_user_feedback`, gather evidence or adjudicate the recommendation first.
`GovernedEpisodeCapture.start()` raises `UnresolvedDecisionError` for those
non-executable states.

## 5. Run a governed offline batch

```python
from agent_learning import LearningRunner
from agent_learning_gov import GovernedLearningRunner

learning = LearningRunner(store=store, policy=policy, metrics=[])
runner = GovernedLearningRunner(
    kernel,
    learning,
    audit_sink=audit,
    provenance_key=provenance_key,
)
run = runner.run_offline_batch(
    "account-agent",
    task_id="choose-summary-strategy",
    score_missing=False,
)

candidate = runner.last_candidate
report = run.metrics["governance"]

assert report["reinforce_eligible_episodes"] == 5
assert report["bayesian_episodes"] == 1
assert store.get_active_policy(
    "account-agent",
    "choose-summary-strategy",
).id == parent.id
```

The policy supplied to `LearningRunner` was not mutated. The new candidate is
stored in the training run, and the active policy remains the parent.

## 6. Validate and promote

```python
from agent_learning_gov import GovernedPolicyPromotion, PromotionStage

deployments = []

def deploy(snapshot, stage, context):
    receipt = {"policy_id": snapshot.id, "stage": stage.value, **context}
    deployments.append(receipt)
    return receipt

promoter = GovernedPolicyPromotion(
    kernel,
    store=store,
    audit_sink=audit,
    provenance_key=provenance_key,
    deploy_callback=deploy,
)

canary = promoter.promote_if_compliant(
    candidate,
    stage=PromotionStage.CANARY,
    baseline={"violation_rate": 0.0},
    deployment_context={"traffic_percent": 5},
)
production = promoter.promote_if_compliant(
    candidate.id,
    agent_id="account-agent",
    task_id="choose-summary-strategy",
    stage=PromotionStage.PRODUCTION,
    baseline={"violation_rate": 0.0},
)

assert canary.promoted
assert production.promoted
assert store.get_active_policy(
    "account-agent",
    "choose-summary-strategy",
).id == candidate.id
```

Canary deployment updates candidate history but does not activate the policy.
Approval without a deployment callback does not satisfy the production gate.
Production first persists signed rollout state and approval audit, activates the
candidate, and then invokes the callback. Callback rejection or failure restores
the prior active policy. Production callbacks must be synchronous, idempotent,
and transactional. Production also requires a configured audit sink and the
run-backed candidate created by `GovernedLearningRunner`.

This tutorial uses one in-memory key. Durable or multi-process deployments must
load the same key of at least 32 bytes from a secret store for capture,
learning, and promotion. The key is never written to Agent Learning metadata.

## 7. Inspect governance state

```python
from agent_learning_gov import LearningGovernanceDashboardModel

snapshot = LearningGovernanceDashboardModel(
    store,
    audit_sink=audit,
).snapshot(
    "account-agent",
    task_id="choose-summary-strategy",
)

print(snapshot.summary)
```

For durable local data, switch to Agent Learning `LocalFileStore` and
`JsonlAuditSink`, export the privacy-safe projection, then open the local
dashboard and select the resulting JSON file:

```bash
python agent-governance-python/agent-learning/examples/export_dashboard.py \
    --data-dir ./data/agent-learning/store \
    --audit-file ./data/agent-learning/governance-audit.jsonl \
    --agent-id account-agent \
    --task-id choose-summary-strategy \
    --output ./governance-dashboard.json
```

[Open the dashboard](../../agent-governance-python/agent-learning/examples/dashboard.html).

## 8. Run the complete samples

The repository includes an executable version of this tutorial and an
interactive notebook:

```bash
python agent-governance-python/agent-learning/examples/governed_learning.py
```

- [Python example](../../agent-governance-python/agent-learning/examples/governed_learning.py)
- [Notebook](../../agent-governance-python/agent-learning/examples/governed_agent_learning.ipynb)
- [Foundry sample](../../agent-governance-python/agent-learning/examples/azure_ai_foundry.py)
- [Reference architecture](../integrations/agent-learning-governance.md)
