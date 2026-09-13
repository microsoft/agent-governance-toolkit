---
title: "ADR-0033: Agent Learning Governance Integration"
last_reviewed: 2026-08-20
owner: agt-maintainers
---

# ADR-0033: Agent Learning Governance Integration

- Status: proposed
- Date: 2026-08-20

## Context

Microsoft Agent Learning owns episode capture, reward records, policy learning,
training runs, and policy storage. Agent Governance Toolkit (AGT) needs to
enforce policy across that lifecycle without forking Agent Learning or making
governance behavior an application-specific example.

The integration must preserve two distinct Agent Learning decision routes:
learned-policy decisions may be eligible for REINFORCE, while Bayesian
decisions are scored and audited but must not be presented to REINFORCE as
sampled actions. Learned candidates must also remain isolated from the active
policy until governance validation and staged promotion succeed.

## Decision

Create `agent_learning_gov` as a first-party adapter package. Agent Learning
continues to own learning and storage semantics; AGT owns policy enforcement,
governance metadata, audit evidence, candidate validation, and promotion gates.
The package does not fine-tune model weights, replace Agent Learning models, or
provide a deployment platform.

### Dependency boundary

Use the direct runtime dependency `agent-learning>=0.8.0,<0.9.0`.

- The adapter is implemented and tested against the `0.8.x` contracts for
  `EpisodeCapture`, `LearningRunner`, `TrainingRun`, policy snapshots, stores,
  and the learned-policy and Bayesian decision routes.
- A direct dependency makes the supported object model explicit. Reproducing
  these contracts through local look-alikes would weaken compatibility checks
  and could silently misclassify learning data.
- The upper bound prevents a pre-1.0 minor release that has not been reviewed
  from changing decision, storage, or activation semantics beneath governance
  controls.
  Supporting `0.9.x` requires compatibility tests and a deliberate bound bump.
- Agent Framework and Foundry remain optional extras because the core
  governance path does not require either runtime.

The integration was validated against the upstream `v0.8.0` tag. Installation
of a newly published build remains subject to the repository's seven-day
dependency review and supply-chain checks.

### Governance model

Governance is applied at four lifecycle boundaries:

1. `GovernedEpisodeCapture` authorizes proposed actions and tool calls before
   execution, records allow/deny/warn/modify outcomes, and binds decision
   provenance to the captured episode.
2. `PolicyAwareRewardAdapter` adjusts aggregate rewards using explicit
   compliance bonuses and violation penalties. It leaves metric rows unchanged
   and retains the original reward decomposition.
3. `GovernedLearningRunner` excludes blocked or ineligible episodes from
   REINFORCE, keeps Bayesian decisions out of sampled-action updates, learns on
   a deep copy, and persists a signed candidate without changing the active
   policy pointer.
4. `GovernedPolicyPromotion` re-authorizes candidate actions, runs the
   evaluation pack, requires staged rollout by default, and activates a
   production candidate only with durable run state, audit support, and a
   rollback policy.

Policy evaluators remain the source of truth. Adapter failures default to
fail-closed behavior at enforcement and promotion boundaries. HMAC provenance
protects decision certificates, candidates, and promotion receipts; operators
must supply a stable secret-managed key for durable or multi-process use. The
default ephemeral key is only suitable for one-process local workflows.

Dashboard projections, HTML, examples, and the notebook are non-normative.
They consume privacy-reduced governance records and do not participate in
authorization, learning eligibility, validation, activation, or rollback.

### Review and delivery boundary

The implementation has two independently reviewable units:

- **Core:** package metadata; capture, policy, audit, reward, runner,
  evaluation, promotion, provenance, and model code; and their focused tests.
- **Demonstration and visualization:** dashboard projection and tests, runnable
  examples, optional framework/Foundry walkthroughs, static HTML, and notebook.

The core unit must land first. The second unit may depend on the core public API
but must not introduce or alter enforcement semantics implicitly. Documentation
needed to explain the core contract stays with the core review.

## Consequences

- Applications receive reusable, testable governance controls without changes
  to Agent Learning itself.
- Compatibility is intentionally limited to `0.8.x`; each new upstream minor
  version requires an explicit review and test update.
- Governance metadata augments Agent Learning artifacts rather than replacing
  them, so unwrapped Agent Learning calls remain outside this enforcement
  boundary.
- Promotion approval is not proof of universal safety. Deployment callbacks,
  durable storage, secret management, and operational monitoring remain the
  application's responsibility.
- Separating core enforcement from demonstrations reduces review scope and
  prevents examples or dashboard behavior from becoming accidental policy.

## Alternatives considered

- **Modify Agent Learning directly:** rejected because it couples a general
  learning library to AGT policy and release cadence.
- **Ship documentation and examples only:** rejected because examples cannot
  provide reusable enforcement, provenance, or testable rollback semantics.
- **Use structural look-alikes with no Agent Learning dependency:** rejected
  because the adapter relies on concrete pre-1.0 decision and storage semantics
  where silent compatibility drift would be unsafe.

## References

- [Agent Learning package metadata](../../agent-governance-python/agent-learning/pyproject.toml)
- [Package design and operational limits](../../agent-governance-python/agent-learning/README.md)
- [Governed episode capture](../../agent-governance-python/agent-learning/src/agent_learning_gov/capture.py)
- [Governed offline learning](../../agent-governance-python/agent-learning/src/agent_learning_gov/runner.py)
- [Governed policy promotion](../../agent-governance-python/agent-learning/src/agent_learning_gov/promotion.py)
- [ADR-0013: Fail Closed on Policy Evaluation Errors](0013-fail-closed-on-policy-evaluation-errors.md)
- [ADR-0024: RL Training Governance with Violation Penalties](0024-rl-training-governance-with-violation-penalties.md)