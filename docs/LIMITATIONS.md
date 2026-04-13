# Known Limitations & Design Boundaries

> **Transparency is a feature.** This document describes what AGT does *not* do
> so you can make informed architecture decisions.

## 1. Action Governance, Not Reasoning Governance

AGT governs **what agents do** (tool calls, resource access, inter-agent messages).
It does **not** govern what agents *think* or *say*.

**What this means in practice:**

- ✅ AGT blocks an agent from calling `delete_file` if policy forbids it
- ❌ AGT does **not** detect if the *content* passed to an allowed tool is a hallucination
- ❌ AGT does **not** detect indirect prompt injection that corrupts the agent's reasoning
- ❌ AGT does **not** correlate sequences of individually-allowed actions that form a malicious workflow

**Example gap:** If policy allows both `read_database` and `send_slack_message`,
an agent could read your customer list and post it to a public channel — both
actions are individually permitted.

**Mitigations available today:**
- Use **content policies** with blocked patterns (regex) to catch PII in outputs
- Use **PromptDefenseEvaluator** to test for prompt injection vulnerabilities
- Combine AGT with a model-level safety layer like [Azure AI Content Safety](https://learn.microsoft.com/azure/ai-services/content-safety/)
- Use **max_tool_calls** limits to cap action sequences

**What we're building:**
- **Workflow-level policies** that evaluate action *sequences*, not just individual actions
- **Intent declaration** where agents declare what they plan to do before doing it,
  and the policy engine validates the plan

## 2. Audit Logs Record Attempts, Not Outcomes

AGT's audit trail records **what the agent attempted** and whether the governance
layer allowed or denied it. It does **not** verify whether the action actually
succeeded in the external world.

**Example gap:** An agent calls a web API that returns `200 OK` but the data
was stale. AGT logs "action allowed, executed" — but the agent's goal was not
actually achieved.

**Mitigations available today:**
- Use the **SRE module** with SLOs to track action success rates over time
- Use **saga orchestration** with compensating actions for multi-step workflows
- Implement application-level result validation in your agent code

**What we're building:**
- **Post-action verification hooks** where users register validators that check
  world-state after action execution
- **Outcome attestation** in audit logs (succeeded/failed/unknown)

## 3. Performance: Policy Eval vs. End-to-End

Our published benchmark (<0.1ms policy evaluation) measures the **policy engine
only** — the deterministic rule evaluation step. This is accurate and reproducible.

In a **distributed multi-agent deployment**, the full governance overhead includes:

| Component | Typical Latency | When It Applies |
|-----------|-----------------|-----------------|
| Policy evaluation | <0.1 ms | Every action |
| Ed25519 signature verification | 1–3 ms | Inter-agent messages |
| Trust score lookup | <1 ms | Inter-agent messages |
| IATP handshake (first contact) | 10–50 ms | First message between two agents |
| Network round-trip (mesh) | 1–10 ms | Distributed deployments only |

**For single-agent, single-process deployments:** the <0.1ms number is the full overhead.

**For multi-agent mesh deployments:** expect 5–50ms per governed inter-agent
interaction, dominated by cryptographic verification and network latency — not
the policy engine itself.

## 4. Complexity Spectrum

AGT is designed for enterprise governance. For simple use cases, the full stack
(mesh identity, execution rings, SRE) may be overkill.

**Minimal path (no mesh, no identity):**
```python
from agent_os.policies import PolicyEvaluator
evaluator = PolicyEvaluator()
evaluator.load_policies("policies/")
# That's it — just policy evaluation, no crypto, no mesh
```

**Full path (everything):**
```bash
pip install agent-governance-toolkit[full]
```

You do **not** need to adopt the entire stack. Each package is independently
installable and useful on its own.

## 5. Vendor Independence

AGT is MIT-licensed with **zero Azure/Microsoft dependencies** in the core packages.
The policy engine, identity system, trust scoring, and execution rings work
entirely offline with no cloud services required.

**Cloud integrations exist** (Azure AI Foundry deployment guide, Entra ID adapter)
but they are optional and in separate packages. You can run AGT on AWS, GCP,
on-premises, or air-gapped environments.

**To verify:** run `agt doctor` — it shows all installed packages and none require
cloud connectivity.

**Migration path:** All governance state (policies, audit logs, identity keys)
is stored in standard formats (YAML, JSON, Ed25519 keys). There is no proprietary
format or cloud-locked state.

## 6. What AGT Is Not

| AGT Is | AGT Is Not |
|--------|------------|
| Runtime action governance | Model safety / content moderation |
| Deterministic policy enforcement | Probabilistic guardrails |
| Application-layer middleware | OS kernel / hardware isolation |
| Framework-agnostic library | A managed cloud service |
| Audit trail of actions | Audit trail of outcomes |
| Permission layer (L3/L4) | Application logic security (L7) |

## Recommended Architecture

For production deployments, we recommend a **layered defense**:

```
┌─────────────────────────────────┐
│   Model Safety Layer            │  Azure AI Content Safety, Llama Guard
│   (input/output filtering)      │  ← catches hallucinations, toxic content
├─────────────────────────────────┤
│   AGT Governance Layer          │  Policy engine, identity, trust, audit
│   (action enforcement)          │  ← catches unauthorized actions
├─────────────────────────────────┤
│   Application Layer             │  Your agent code, framework adapters
│   (business logic validation)   │  ← catches domain-specific errors
├─────────────────────────────────┤
│   Infrastructure Layer          │  Containers, network policies, IAM
│   (OS/network isolation)        │  ← catches escape attempts
└─────────────────────────────────┘
```

AGT is one layer in a defense-in-depth strategy, not the entire strategy.

---

*This document is maintained alongside the codebase. If you find a limitation
not listed here, please [open an issue](https://github.com/microsoft/agent-governance-toolkit/issues).*
