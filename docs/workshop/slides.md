---
title: AI Agent Governance Workshop Slides
last_reviewed: 2026-07-12
owner: docs-team
marp: true
theme: default
paginate: true
---

# Introduction to AI Agent Governance

Native policy, host controls, identity, and trust

---

# Why governance

- Agent actions can create external side effects.
- Prompt instructions are not an authorization boundary.
- Policy, identity, isolation, audit, and reliability solve different
  problems.

---

# Native ACS policy

An ACS manifest declares:

- policy engines and bundles
- intervention-point bindings
- tool catalogs
- transforms and evidence
- approval
- limits

---

# Runtime model

```python
from agt.policies import AdapterRuntimeSession, AgtRuntime

runtime = AgtRuntime("policies/manifest.yaml")
session = AdapterRuntimeSession(
    runtime,
    agent_id="agent-1",
    session_id="session-1",
)
```

---

# Tool mediation

```python
evaluation = session.evaluate_pre_tool_call(
    tool_name="delete_file",
    args={"path": "report.txt"},
)
```

No side effect occurs before the pre-intervention evaluation.

---

# Result contract

`PolicyEvaluation` carries:

- verdict and reason code
- transform and evidence
- input and enforced identities
- approval metadata
- restricted audit payload

---

# Lab 1

Run `labs/lab1_first_policy.py`.

1. Inspect the manifest binding.
2. Inspect the Rego policy.
3. Run the scenarios.
4. Add one deny condition.

---

# Host controls

Policy evaluation does not replace:

- sandbox resource and network controls
- framework lifecycle ordering
- circuit breakers and SLOs
- identity and trust

---

# AgentMesh

AgentMesh owns:

- cryptographic identity
- trust and reputation
- capability grants
- cross-agent transport

---

# Lab 2

Complete `labs/lab2_multi_agent_trust.py`.

1. Create identities.
2. Attempt a trust handshake.
3. Build trust.
4. Revoke and verify denial.

---

# Fail closed

- Unknown tools can be denied by manifest contract.
- Runtime and approval errors deny.
- Action-identity mismatch denies.
- Public errors remain sanitized.

---

# Production checklist

- Lint and replay manifests.
- Test every mediated framework path.
- Test sandbox isolation.
- Test approval and runtime failures.
- Restrict audit access.
- Monitor SLOs and incident signals.

---

# Next steps

- `docs/quickstart.md`
- `docs/tutorials/03-framework-integrations.md`
- `docs/tutorials/55-agent-control-specification.md`
- `docs/workshop/lab-guide.md`
