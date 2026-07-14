---
title: Workshop Lab Guide
last_reviewed: 2026-07-12
owner: docs-team
---

# Workshop Lab Guide

## Lab 1 - Native ACS Policy

**Files**

- `labs/lab1_first_policy.py`
- `labs/lab1-manifest.yaml`
- `labs/lab1-policy.rego`

### Goal

Run a native manifest and observe allow and deny verdicts for tool-shaped input.

### Steps

1. Read the manifest and identify the `input` intervention-point binding.
2. Read the Rego policy and identify the three deny conditions.
3. Run:

   ```bash
   python docs/workshop/labs/lab1_first_policy.py
   ```

4. Confirm `execute_code`, `write_database`, and the over-budget read are
   denied.
5. Add one new deny condition to `lab1-policy.rego`, rerun the script, and
   explain which input field the policy reads.

### Discussion

- Why does the manifest own the policy binding?
- Why does `AdapterRuntimeSession` own counters?
- What would happen if the policy dispatcher or OPA process failed?

## Lab 2 - Multi-Agent Trust

**File**

- `labs/lab2_multi_agent_trust.py`

### Goal

Create two AgentMesh identities, evaluate trust, build reputation, and verify
revocation.

### Steps

1. Complete `create_agents()` with two `AgentIdentity` values.
2. Complete `attempt_handshake()` with the required capability and trust
   threshold.
3. Record positive events in `build_trust()`.
4. Revoke the initiator and verify the next handshake fails.
5. Run:

   ```bash
   python docs/workshop/labs/lab2_multi_agent_trust.py
   ```

### Discussion

- Which controls belong to AgentMesh rather than ACS?
- Why must policy evaluation and identity verification remain separate?
- Which audit fields are needed to reconstruct a cross-agent decision?

## Wrap-up

The two labs demonstrate separate control planes:

| Control | Owner |
|---------|-------|
| Policy definitions and intervention points | Native ACS manifest |
| Session counters | `AdapterRuntimeSession` |
| Agent identity and trust | AgentMesh |
| Framework lifecycle ordering | Agent OS adapter |
| Resource and network isolation | `SandboxConfig` |

Continue with the [Quickstart](../quickstart.md) and
[Framework Integrations](../tutorials/03-framework-integrations.md).
