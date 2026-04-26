# Integrating with NVIDIA OpenShell

Deploy the Agent Governance Toolkit as the governance layer inside (or alongside) [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) sandboxes to combine **runtime isolation** with **governance intelligence**.

> **TL;DR** — OpenShell provides the *walls* (sandbox, network, filesystem policies). The toolkit provides the *brain* (identity, trust, policy decisions, audit). Together they form a complete agent security stack.

---

## Why Combine Them?

OpenShell and the Agent Governance Toolkit solve **different halves** of the agent security problem:

| Capability | OpenShell | Governance Toolkit |
|---|:---:|:---:|
| Container isolation | ✅ | — |
| Filesystem policies | ✅ | — |
| Network egress control | ✅ | — |
| Process / syscall restrictions | ✅ | — |
| Inference routing | ✅ | — |
| Agent identity (Ed25519 DIDs) | — | ✅ |
| Behavioral trust scoring | — | ✅ |
| Policy engine (YAML + OPA + Cedar) | — | ✅ |
| Authority resolution (reputation-gated delegation) | — | ✅ |
| Tamper-evident Merkle audit chains | — | ✅ |
| SLOs, circuit breakers, execution rings | — | ✅ |
| Multi-agent governance | — | ✅ |

OpenShell asks: *"Is this network call allowed by sandbox policy?"*
The toolkit asks: *"Should this agent be trusted to make this call at all?"*

Neither replaces the other — they're complementary layers in a defense-in-depth stack.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  OpenShell Sandbox                                                │
│                                                                   │
│  ┌────────────────────────┐   ┌────────────────────────────────┐ │
│  │  AI Agent (Claude,     │   │  Governance Toolkit (sidecar)  │ │
│  │  Codex, OpenCode, etc) │   │                                │ │
│  │                        │   │  AgentIdentity  — Ed25519 DIDs │ │
│  │  Tool call ────────────────► PolicyEngine   — YAML/OPA/Cedar│ │
│  │             ◄──────────────  RewardService  — trust scoring │ │
│  │  (allow / deny)        │   │  AuditLog      — Merkle chain  │ │
│  │                        │   │  AuthorityResolver — delegation │ │
│  └────────────────────────┘   └────────────────────────────────┘ │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │  OpenShell Policy Engine                                      │ │
│  │  Filesystem ▸ Network ▸ Process ▸ Inference                   │ │
│  └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

**Request flow:**

1. Agent issues a tool call (e.g., `shell:curl`, `file:write`)
2. **Governance Toolkit** evaluates: identity verified? trust score above threshold? policy allows action? authority delegated?
3. If governance approves → OpenShell's **sandbox policy engine** enforces runtime constraints (network egress, filesystem boundaries, process restrictions)
4. Both layers log independently — governance writes to the Merkle audit chain, OpenShell writes to its own policy log
5. If either layer denies → action is blocked

---

## Setup

### Option A: Governance Skill Inside the Sandbox (Python Library)

Install the [OpenShell governance skill](../../agent-governance-python/agentmesh-integrations/openshell-skill/) and use it from your agent's code:

```python
# Inside the sandbox
# pip install openshell-agentmesh  (or install from repo)
from openshell_agentmesh import GovernanceSkill

skill = GovernanceSkill(policy_dir="./policies")

# Before each tool call, check policy
decision = skill.check_policy("shell:curl https://api.example.com")
if not decision.allowed:
    print(f"Blocked: {decision.reason}")
```

See the [runnable example](../../examples/openshell-governed/) for a complete demo.

### Option B: Governance Sidecar (Production)

Run the governance API server as a sidecar container. Your agent (or orchestration layer) calls the sidecar's HTTP API before executing actions:

```yaml
# openshell-governance-policy.yaml — OpenShell sandbox network rules
network:
  outbound:
    - match:
        host: "localhost"
        port: 8081
      action: allow          # Allow agent → governance sidecar
    - match:
        host: "*.openai.com"
      action: allow          # Allow approved LLM calls
    - action: deny           # Block everything else
```

```bash
# Start the governance sidecar (Agent OS server)
python -m agent_os.server --host 127.0.0.1 --port 8081 &

# Create the sandbox with the policy
openshell sandbox create \
  --policy openshell-governance-policy.yaml \
  -- claude
```

> **Note:** The sidecar does not yet transparently intercept tool calls — your agent must call `http://localhost:8081/api/v1/detect/injection` or `/api/v1/execute` explicitly. See the [sidecar API docs](../deployment/openclaw-sidecar.md#sidecar-api-endpoints).

See the full [OpenClaw sidecar deployment guide](../deployment/openclaw-sidecar.md) for Docker Compose and AKS configurations.

---

## Policy Layering Example

A single agent action passes through **two policy layers**:

```
Agent: "I want to POST to https://api.github.com/repos/org/repo/issues"

Layer 1 — Governance Toolkit:
  ✅ Agent identity verified (did:mesh:a1b2c3)
  ✅ Trust score 0.82 > threshold 0.5
  ✅ Policy allows "http:POST:api.github.com/*"
  ✅ Authority: delegated by parent agent with scope "github:issues:create"
  → ALLOW (logged to Merkle audit chain)

Layer 2 — OpenShell:
  ✅ Network policy permits POST to api.github.com
  ✅ Process policy permits curl binary
  → ALLOW (logged to OpenShell policy log)

Result: Action executes
```

If either layer denies:

```
Agent: "I want to POST to https://169.254.169.254/metadata"

Layer 1 — Governance Toolkit:
  ❌ Policy blocks "http:*:169.254.169.254/*" (cloud metadata endpoint)
  → DENY (logged with violation reason)

Result: Action blocked before reaching OpenShell
```

---

## OpenShell Policy + Governance Policy Mapping

| OpenShell Layer | Governance Toolkit Equivalent | How They Interact |
|---|---|---|
| `filesystem.read/write` | Capability policies (`file:read:*`, `file:write:*`) | Governance decides *who can*, OpenShell enforces *where* |
| `network.outbound` | Capability policies (`http:GET:*`, `http:POST:*`) | Governance decides *what action*, OpenShell enforces *which endpoints* |
| `process` | Blocked-tool policies, execution rings | Governance gates by trust level, OpenShell gates by syscall |
| `inference` routing | N/A (complementary) | OpenShell routes LLM traffic; governance audits responses |
| N/A | Identity, trust scoring, audit | Governance-only capabilities |

---

## Monitoring

When running both layers, you get two complementary telemetry streams:

**Governance Toolkit metrics** (Prometheus / OpenTelemetry):
- `policy_decisions_total{result="allow|deny"}`
- `trust_score_current{agent="did:mesh:..."}`
- `audit_chain_entries_total`
- `authority_resolutions_total{decision="allow|deny|narrowed"}`

**OpenShell metrics**:
- Sandbox network egress logs
- Filesystem access logs
- Process execution logs
- Inference routing logs

Both can feed into the same Grafana dashboard for a unified view. See the [Agent SRE monitoring guide](../../agent-governance-python/agent-sre/README.md) for SLO configuration.

---

## FAQ

**Q: Do I need both?**
No. Each works independently. But together they provide defense-in-depth: governance intelligence (who, what, why) plus runtime isolation (where, how).

**Q: Does the toolkit work with agents other than OpenClaw?**
Yes. The toolkit is agent-agnostic — it works with any AI agent framework (LangChain, CrewAI, AutoGen, Semantic Kernel, etc.) on any cloud (AWS, GCP, Azure) or locally.

**Q: Does OpenShell replace the sidecar deployment?**
OpenShell can *host* the sidecar. The governance sidecar runs inside or alongside the OpenShell sandbox. OpenShell provides the isolation boundary; the sidecar provides the governance logic.

**Q: What about NemoClaw?**
[NemoClaw](https://nvidianews.nvidia.com/news/ai-agents) bundles OpenShell with NVIDIA Nemotron models. The governance toolkit works with NemoClaw the same way — it adds identity, trust, and audit capabilities on top of the NemoClaw runtime.

---

## Related

- [OpenShell Governance Skill](../../agent-governance-python/agentmesh-integrations/openshell-skill/) — Python skill package for OpenShell agents
- [Runnable Example](../../examples/openshell-governed/) — Self-contained demo with policy enforcement
- [OpenClaw Sidecar Deployment](../deployment/openclaw-sidecar.md) — AKS and Docker Compose guide
- [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) — Runtime sandbox for AI agents
- [Architecture](../ARCHITECTURE.md) — Full toolkit architecture
