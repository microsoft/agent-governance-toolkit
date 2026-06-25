---
title: Embodied Action Governance Boundary Profile
last_reviewed: 2026-06-25
owner: agt-maintainers
---

# Proposal: Embodied Action Governance Boundary Profile

**Status:** Draft
**Type:** Docs and policy profile
**Scope:** Software decision-layer governance for embodied action requests

**Related ADRs and docs:**

- [ADR-0030: Action-bound approval protocol](../adr/0030-action-bound-approval-protocol.md)
- [ADR-0032: AGT emits TRACE v0.1 trust records](../adr/0032-agt-emits-trace-v01-trust-records.md)
- [ADR-0009: RFC 9334 RATS architecture alignment](../adr/0009-rfc-9334-rats-architecture-alignment.md)
- [ADR-0010: TEE keystore and SEV-SNP attestation](../adr/0010-tee-keystore-sevsnp-attestation.md)
- [ADR-0017: Merkle chain for audit tamper evidence](../adr/0017-merkle-chain-for-audit-tamper-evidence.md)
- [ADR-0024: RL training governance with violation penalties](../adr/0024-rl-training-governance-with-violation-penalties.md)
- [Known limitations and design boundaries](../LIMITATIONS.md)
- [Sample policy fixture](../../examples/policies/embodied-action-governance.yaml)

## Summary

This proposal defines a small boundary profile for agents that request actions
with possible physical effects, such as robot motion, drone navigation, lab
automation, building controls, or industrial actuator changes.

The profile reuses existing AGT concepts: policy evaluation, action-bound
approval, audit logs, and software trace records. It does not introduce a robot
safety controller, hardware attestation requirement, ROS integration, or proof
that the physical world changed as intended.

## Problem

Embodied agents can turn an allowed software action into a physical request. A
policy decision like "allow `robot.move`" is useful, but it is not the same as
"the motion is physically safe" or "the controller executed the motion
successfully."

AGT needs a clear contribution path for this domain that helps users govern
software decisions while preserving the boundary stated in
[physical AI limitations](../LIMITATIONS.md#10-physical-ai-and-embodied-agent-governance):
physical safety remains the job of downstream controllers, safety PLCs,
interlocks, emergency stops, certified runtime monitors, and domain-specific
validation.

## Non-goals

- Certify functional safety or conformity with robotics, aviation, medical, or
  industrial-control standards.
- Replace robot controllers, safety PLCs, motion planners, collision monitors,
  emergency stops, force limits, or hardware interlocks.
- Prove physical completion, physical non-harm, or world-state correctness after
  an action executes.
- Make AGT a hard real-time control loop.
- Require TEEs, hardware roots of trust, or a specific downstream controller.
- Add first-party ROS, ROS 2, Isaac, PLC, or drone SDK adapters in this proposal.

## Boundary Model

| Layer | AGT can help with | AGT does not prove |
|-------|-------------------|--------------------|
| Policy decision | Whether the agent is authorized to request a named physical action under declared context | That the action is physically safe |
| Action-bound approval | Whether an exact action digest was approved before execution | That the approver certified the physical outcome |
| Audit and trace records | That AGT observed and recorded the request, decision, and selected context | That a downstream controller executed or completed the action |
| Tamper-evident logs | That local audit entries were chained and alteration is detectable | That the entire chain was externally anchored or impossible to replace |
| Downstream controller | External evidence can be referenced or required by policy | AGT itself does not create controller-level safety evidence |

## Suggested Action Context

The profile treats embodied requests as ordinary governed actions with extra
context. These keys are illustrative, not a committed runtime schema:

```yaml
physical_action:
  embodiment_id: "cell-7-arm-a"
  controller_id: "safety-plc-3"
  operation: "bounded_motion"
  workspace: "assembly-cell-7"
  target_ref: "bin-slot-12"
  max_speed_mps: 0.25
  max_force_n: 35
  human_proximity: "unknown"
  reversibility: "reversible"
  safety_state_token_ref: "controller-state-2026-06-25T11:40:00Z"
  outcome_evidence_required: true
```

Deployments can map these fields into the existing policy context passed to the
policy evaluator. High-risk deployments should fail closed when required safety
state is missing or stale.

## Risk Tiers

| Tier | Examples | Suggested AGT treatment |
|------|----------|-------------------------|
| Observation only | Read robot state, read sensor state, query controller status | Allow or audit, subject to normal data access policy |
| Simulation and planning | Validate a trajectory in simulation, generate a plan without actuation | Allow or audit when clearly separated from live controllers |
| Bounded actuation | Move within a validated workspace, set a low-risk actuator state | Require explicit allowlist, current context, audit, and downstream safety gate |
| Human-proximate or contact action | Gripper close, robot move near people, drone navigation, lab dispensing | Use `require_approval` with action-bound approval and fail closed on missing safety state |
| Irreversible or critical action | Disable interlock, release emergency stop, force PLC output, bypass controller | Deny by default; allow only outside AGT through certified operational procedures |

## Mapping To Existing AGT Decisions

- Use [ADR-0030](../adr/0030-action-bound-approval-protocol.md) for high-risk
  embodied actions. `require_approval` is a suspended decision until a terminal
  approval is bound to the exact action.
- Use [ADR-0032](../adr/0032-agt-emits-trace-v01-trust-records.md) as the
  software trace baseline. Treat hardware-backed or controller-issued evidence
  as external evidence, not as something AGT itself guarantees.
- Use [ADR-0009](../adr/0009-rfc-9334-rats-architecture-alignment.md) and
  [ADR-0010](../adr/0010-tee-keystore-sevsnp-attestation.md) when a deployment
  needs attested controller or enclave claims. This profile does not make those
  mandatory.
- Use [ADR-0017](../adr/0017-merkle-chain-for-audit-tamper-evidence.md) for
  tamper-evident local audit chains, while preserving the limitation that local
  chains are not the same as externally anchored evidence.
- Use [ADR-0024](../adr/0024-rl-training-governance-with-violation-penalties.md)
  for training-time or reinforcement-learning governance concerns. Runtime
  physical safety still belongs to the downstream safety layer.

## Example Policy

The sample fixture in
[examples/policies/embodied-action-governance.yaml](../../examples/policies/embodied-action-governance.yaml)
shows a deny-by-default policy profile with:

- hard blocks for safety bypass language and direct interlock override actions
- `require_approval` for human-proximate or actuator-changing actions
- audit-only treatment for physical state reads
- allowlisted simulation-only planning actions

The fixture is intentionally generic. It should be copied, reviewed, and mapped
to deployment-specific controller actions before use.

## Integration Path

1. Document the boundary profile and keep it aligned with the limitations page.
2. Maintain generic policy fixtures for action names and risk tiers.
3. Add optional examples that pass physical-action context into existing policy
   evaluation APIs without adding new AGT runtime dependencies.
4. Defer ROS, PLC, drone, cMCP, hardware-attestation, or controller-specific
   adapters until maintainers approve a concrete integration surface.

## Acceptance Criteria

- The limitations page states that AGT can govern embodied action requests but
  does not provide physical safety, real-time control, or outcome proof.
- The sample policy fixture is discoverable from `examples/policies/README.md`.
- The profile maps to existing ADRs instead of introducing a parallel approval,
  trace, or attestation model.
- The proposal avoids claims that AGT certifies physical execution or replaces
  domain safety systems.
