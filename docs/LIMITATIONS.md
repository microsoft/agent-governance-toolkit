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
| Action governance | Knowledge / data provenance governance |
| Enforcement infrastructure | Turnkey compliance solution |

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

## 7. Knowledge Governance Gap

AGT governs **agent actions** (tool calls, resource access, inter-agent messages).
It does **not** govern the **knowledge agents consume** — the documents, databases,
embeddings, and context retrieved during reasoning.

**What this means in practice:**

- ✅ AGT blocks an agent from calling `send_email` if policy forbids it
- ❌ AGT does **not** verify the provenance, freshness, or authorization of
  documents retrieved via RAG
- ❌ AGT does **not** track which knowledge sources influenced an agent's decision
- ❌ AGT does **not** enforce data classification labels on retrieved context

**Example gap:** An agent retrieves a confidential HR document via a search tool
(which AGT permits via policy), then summarizes it in a Slack message (also
permitted). Both actions are individually governed, but the *knowledge flow* —
confidential data reaching an unauthorized channel — is invisible to AGT.

**Mitigations available today:**
- Use **egress policies** to restrict which domains agents can send data to
- Use **blocked_patterns** to catch PII/confidential patterns in tool arguments
- Combine AGT with a **data classification** layer that labels context before
  it reaches the agent

**What we're building:**
- Integration points for external knowledge governance systems
- Context provenance tracking in audit logs

> *This gap was identified in external analysis by [Mojar AI](https://www.mojar.ai/blog/industry-news/microsoft-agent-governance-toolkit-missing-knowledge-layer).*

## 8. Credential Persistence Gap

AGT governs **what agents do** with tools. It does **not** manage or observe the
**credentials agents hold** across tasks within a session.

**What this means in practice:**

- ✅ AGT blocks an agent from calling a tool it's not authorized to use
- ❌ AGT does **not** track which API keys, OAuth tokens, or secrets an agent
  is currently holding
- ❌ AGT does **not** revoke credentials at task boundaries within a session
- ❌ AGT does **not** detect credential accumulation beyond what's needed for
  the current task

**Example gap:** An agent receives an email API token for Task A, then moves to
Task B (which doesn't require email access). The token persists. If the agent is
compromised during Task B, the attacker gains email access that should no longer
be active.

**Mitigations available today:**
- Use **scoped capabilities** in Agent OS policies to limit which tools are
  available per task context
- Use **short-lived credentials** with external secret managers (e.g., Azure
  Key Vault, HashiCorp Vault) and TTL-based rotation
- Use **trust decay** in AgentMesh to reduce trust scores over time

**What we're building:**
- Task-scoped credential lifecycle hooks
- Automatic credential revocation at context switches

> *This gap was identified in external analysis by [Moltbook](https://www.moltbook.com/post/c3fdafe4-f58e-4854-9fd6-eec2052b7638).*

## 9. Initialization and Configuration Bypass Risk

AGT's governance enforcement requires **correct initialization**. If the
governance middleware is imported but not properly configured, agents may run
without effective policy enforcement.

**What this means in practice:**

- ✅ When properly initialized with policies loaded, AGT enforces all rules
  before execution
- ⚠️ If the policy evaluator has **no policies loaded**, the default action is
  `allow` — all actions pass through ungoverned
- ⚠️ If `permissive` mode is used without realizing it allows all actions, agents
  run effectively ungoverned
- ✅ On **runtime errors** during policy evaluation, AGT fails closed (denies
  access) — this is correct behavior

**Example gap:** A developer imports `agent_os` and adds it to their agent
framework integration, but forgets to load policy files. The governance
dashboard shows "governed" status, but no rules are enforced.

**Mitigations available today:**
- Use `strict` mode (deny-by-default) in production — this requires explicit
  allow rules for every permitted action
- Use `agt audit` CLI command to verify loaded policies and detect permissive
  defaults
- Use the **MCP Security Scanner** to validate tool configurations
- Run `agt doctor` to check that all components are properly initialized

**What we're building:**
- Startup validation that warns when no policies are loaded
- Dashboard indicators for effective enforcement state (not just import state)

> *This risk was identified in external red-team analysis by [Periculo](https://www.periculo.co.uk/cyber-security-blog/red-teaming-the-microsoft-agent-governance-toolkit-15-bypass-vectors).*

## 10. Physical AI and Embodied Agent Governance

AGT governs **software agents** that call tools via APIs, MCP, or inter-agent
protocols. It does **not** provide governance primitives specific to **physical
agents** (robots, drones, autonomous vehicles, industrial actuators).

**What this means in practice:**

- ✅ AGT can govern the *software decision layer* of a robotic agent (e.g.,
  blocking an API call to arm a mechanism)
- ❌ AGT does **not** provide hardware kill switches, force-limiting, or actuator
  safety interlocks
- ❌ AGT does **not** model physical world state, collision boundaries, or
  safety zones
- ❌ AGT does **not** address latency requirements for real-time control loops
  (typically <10ms) — policy evaluation at <0.1ms is fast enough, but the
  full governance stack (identity, trust, audit) may not be

**Example gap:** A warehouse robot governed by AGT has its `move_to_location`
call approved by policy, but the target location is occupied by a human. AGT
has no spatial awareness to detect this.

**Mitigations available today:**
- Use AGT's policy engine for the *decision layer* — blocking unsafe commands
  before they reach the actuator layer
- Combine AGT with domain-specific robot safety frameworks (e.g., ROS 2 Safety
  Controller, ISO 10218 / ISO 15066 compliance layers)
- Use **execution rings** to isolate physical actuator calls in Ring 0 with
  human-in-the-loop approval

**Status:** Physical AI governance is out of scope for AGT's current roadmap.
We welcome community contributions exploring this space.

## 11. Streaming Data and Real-Time Assurance

AGT evaluates policies **per-action at invocation time**. It does not provide
continuous assurance over **streaming data**, real-time sensor feeds, or
long-running data pipelines.

**What this means in practice:**

- ✅ AGT can govern an agent's decision to *subscribe* to a data stream
- ❌ AGT does **not** inspect individual messages within an active stream
- ❌ AGT does **not** guarantee data freshness, completeness, or consistency
  in streaming contexts
- ❌ AGT does **not** detect stale or poisoned data arriving via a governed
  stream after the initial subscription was approved

**Example gap:** An agent subscribes to a real-time market data feed (permitted
by policy). The feed starts returning stale data due to an upstream outage.
AGT logs the subscription as approved but has no visibility into data quality
degradation.

**Mitigations available today:**
- Use **SRE SLOs** to monitor data freshness and error rates at the stream level
- Use **circuit breakers** to halt agent actions when upstream data quality
  degrades
- Implement application-level stream validation in your agent code

## 12. DID Method Inconsistency Across SDKs

AGT uses two DID (Decentralized Identifier) method prefixes across its SDKs:

| SDK | DID Format | Example |
|-----|-----------|---------|
| Python | `did:mesh:*` | `did:mesh:a7f3b2c1...` |
| .NET | `did:mesh:*` | `did:mesh:a7f3b2c1...` |
| TypeScript | `did:agentmesh:*` | `did:agentmesh:analyst:abc123` |
| Rust | `did:agentmesh:*` | `did:agentmesh:agent_id` |
| Go | `did:agentmesh:*` | `did:agentmesh:agent_id` |

**What this means in practice:**

- Both formats use the same cryptographic primitives (Ed25519) and are
  functionally equivalent
- Cross-SDK agent interactions work if both sides parse the DID correctly
- Policy rules that match on DID prefix (e.g., `did:mesh:*`) will not match
  agents using `did:agentmesh:*` and vice versa

**Mitigations available today:**
- Use wildcard DID matching in policies (e.g., `did:*`) to match both formats
- Normalize DIDs at your application boundary before passing to the policy engine
- When building cross-SDK systems, use the same SDK family for identity
  generation

**What we're building:**
- DID method standardization to `did:agentmesh:*` across all SDKs (planned for v4.0)
- Migration tooling to update existing identity registries

---

*This document is maintained alongside the codebase. If you find a limitation
not listed here, please [open an issue](https://github.com/microsoft/agent-governance-toolkit/issues).*
