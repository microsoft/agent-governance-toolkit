# OpenAI Agents SDK + Governance Toolkit — End-to-End Demo

> A 4-agent OpenAI Agents SDK pipeline (Researcher → Writer → Editor
> → Publisher) operating under **real** agent-governance-toolkit policy
> enforcement. Every policy decision, tool-access check, trust gate,
> and rogue detection event is audit-logged in a Merkle-chained,
> tamper-proof trail.

## Quick Start (< 2 minutes)

```bash
pip install agent-governance-toolkit[full]
python examples/openai-agents-governed/getting_started.py
```

`getting_started.py` is a **~170-line** copy-paste-friendly example showing
the core integration pattern:

```python
from agent_os.policies.evaluator import PolicyEvaluator
from agent_os.integrations.maf_adapter import (
    GovernancePolicyMiddleware,
    CapabilityGuardMiddleware,
    MiddlewareTermination,
)
from agentmesh.governance.audit import AuditLog

# OpenAI Agents Trust — native SDK integration
from openai_agents_trust.policy import GovernancePolicy
from openai_agents_trust.trust import TrustScorer

# 1. Load YAML policies and set up middleware
audit_log = AuditLog()
evaluator = PolicyEvaluator()
evaluator.load_policies(Path("./policies"))
middleware = GovernancePolicyMiddleware(evaluator=evaluator, audit_log=audit_log)

# 2. Wrap your agent's LLM calls with governance
try:
    await middleware.process(agent_context, your_llm_call)
    # LLM call succeeded — governance approved
except MiddlewareTermination:
    # Governance blocked the request BEFORE the LLM was called
    pass

# 3. Use openai-agents-trust for trust scoring
scorer = TrustScorer(default_score=0.8)
if scorer.check_trust("my-agent", min_score=0.6):
    # Agent is trusted enough for this operation
    pass

# 4. Verify the tamper-proof audit trail
valid, err = audit_log.verify_integrity()
```

For the full **9-scenario showcase** (prompt injection, rogue detection,
trust-gated handoffs, tamper detection, etc.), run the comprehensive demo:

```bash
python examples/openai-agents-governed/openai_agents_governance_demo.py
```

## What This Shows

| Scenario | Governance Layer | What Happens |
|----------|-----------------|--------------|
| **1. Role-Based Tool Access** | `CapabilityGuardMiddleware` + `TrustedFunctionGuard` | Each agent role has a declared tool allow/deny list — Researcher can `web_search` but not `publish_content`; Writer can `write_draft` but not `shell_exec`. Trust-scored function gating adds per-function thresholds. |
| **2. Data-Sharing Policies** | `GovernancePolicyMiddleware` + `GovernancePolicy` | YAML policy blocks PII (email, phone, SSN), internal resource access, and secrets — **before the LLM is called** |
| **3. Output Quality Gates** | `TrustScorer` + `GovernancePolicyMiddleware` | Publisher starts with low trust (0.3) and is blocked from publishing; trust is earned through successful tasks; DRAFT content is blocked by quality policy |
| **4. Rate Limiting & Rogue Detection** | `RogueDetectionMiddleware` + `RogueAgentDetector` | Behavioral anomaly engine detects a 50-call burst and auto-quarantines the agent |
| **5. Full Agent Pipeline** | All layers combined | Research → Write → Edit → Publish pipeline with governance applied at every step |
| **6. Prompt Injection Defense** | `GovernancePolicyMiddleware` | 8 adversarial attacks (jailbreak, instruction override, system prompt extraction, encoded payload, PII exfiltration, SQL/shell injection) — all blocked |
| **7. Handoff Governance** | `HandoffVerifier` + `AgentTrustContext` | Trust-gated agent-to-agent handoffs — both agents must meet trust thresholds, delegation depth is bounded, self-delegation is prevented |
| **8. Capability Escalation** | `CapabilityGuardMiddleware` + `RogueAgentDetector` | Writer attempts `shell_exec`, `db_query`, `admin_panel`, `deploy_prod` — all blocked, rogue score escalates to CRITICAL |
| **9. Tamper Detection** | `AuditLog` + `MerkleAuditChain` | Merkle proof generation, simulated audit trail tampering caught by integrity check |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  OpenAI Agents SDK Pipeline (4 agents)                          │
│                                                                 │
│  ┌───────────┐  ┌────────┐  ┌────────┐  ┌───────────┐         │
│  │ Researcher│→ │ Writer │→ │ Editor │→ │ Publisher │         │
│  └─────┬─────┘  └───┬────┘  └───┬────┘  └─────┬─────┘         │
│        │            │            │              │               │
│  ┌─────┴────────────┴────────────┴──────────────┴─────────┐    │
│  │              Governance Middleware Stack                 │    │
│  │                                                         │    │
│  │  CapabilityGuardMiddleware  (tool allow/deny list)      │    │
│  │  GovernancePolicyMiddleware (YAML policy rules)         │    │
│  │  RogueDetectionMiddleware   (anomaly scoring)           │    │
│  └──────────────────────┬──────────────────────────────────┘    │
│                         │                                       │
│  ┌──────────────────────┴──────────────────────────────────┐    │
│  │          openai-agents-trust Integration                 │    │
│  │                                                         │    │
│  │  TrustedFunctionGuard   (trust-scored tool gating)      │    │
│  │  HandoffVerifier        (trust-gated agent handoffs)    │    │
│  │  TrustScorer            (multi-dimensional trust)       │    │
│  │  GovernancePolicy       (pattern-based content check)   │    │
│  │  AgentIdentity          (HMAC-signed agent identity)    │    │
│  └──────────────────────┬──────────────────────────────────┘    │
│                         │                                       │
│              LLM API Call (real or simulated)                    │
└─────────────────────────┬───────────────────────────────────────┘
                          │
              ┌───────────┴───────────┐
              │                       │
              ▼                       ▼
        AuditLog (Merkle)      RogueAgentDetector
        agentmesh.governance   agent_sre.anomaly
```

## Prerequisites

```bash
# Install the toolkit
pip install agent-governance-toolkit[full]

# (Optional) Set an API key for real LLM calls — the demo also works
# with simulated responses if no key is set.
export OPENAI_API_KEY="sk-..."
# or for Azure OpenAI:
export AZURE_OPENAI_API_KEY="..."
export AZURE_OPENAI_ENDPOINT="https://your-resource.openai.azure.com"
# or for Google Gemini:
export GOOGLE_API_KEY="..."
```

## Running

```bash
cd agent-governance-toolkit

# Default (auto-detects backend, falls back to simulated)
python examples/openai-agents-governed/openai_agents_governance_demo.py

# Use a specific model
python examples/openai-agents-governed/openai_agents_governance_demo.py --model gpt-4o

# Show raw LLM responses
python examples/openai-agents-governed/openai_agents_governance_demo.py --verbose
```

## Scenarios Walkthrough

### 1. Role-Based Tool Access

Each agent has declared capabilities enforced at two levels:

**Level 1 — CapabilityGuardMiddleware (governance toolkit):**

| Agent | Allowed Tools | Denied Tools |
|-------|--------------|--------------|
| Researcher | `web_search`, `read_file` | `write_file`, `shell_exec`, `publish_content` |
| Writer | `write_draft`, `read_file` | `web_search`, `shell_exec`, `publish_content` |
| Editor | `edit_text`, `check_grammar`, `read_file` | `shell_exec`, `publish_content` |
| Publisher | `publish_content`, `read_file` | `shell_exec`, `write_file` |

**Level 2 — TrustedFunctionGuard (openai-agents-trust):**
- Per-function trust thresholds (e.g., `publish_content` requires trust ≥ 500)
- Globally blocked functions (e.g., `shell_exec`)
- All decisions logged with trust scores

### 2. Data-Sharing Policies

YAML-defined policies in `policies/agent_governance_policy.yaml` block:
- **PII** — email addresses, phone numbers, SSNs detected via regex
- **Internal resources** — any mention of "internal" or "secrets"
- **Dangerous content** — SQL injection, shell injection patterns

Policy evaluation happens **before** the LLM call, saving API tokens.

### 3. Output Quality Gates

Uses `TrustScorer` from `openai-agents-trust`:
- Publisher starts with trust score 0.3 (below the 0.6 threshold)
- Trust is earned through successful task completions (+0.05 per success)
- After enough successful tasks, Publisher's trust reaches the threshold
- Additionally, `quality_gate_policy.yaml` blocks DRAFT content from publishing

### 4. Rate Limiting & Rogue Detection

The `RogueAgentDetector` monitors three behavioral signals:
- **Frequency** — Z-score spikes in tool call rate
- **Entropy** — deviation from normal action distribution
- **Capability** — calls outside declared tool profile

A 50-call burst triggers HIGH risk and automatic quarantine.

### 5. Full Agent Pipeline

Runs the complete pipeline (Research → Write → Edit → Publish)
with governance applied at every step. All decisions are logged in the
Merkle-chained audit trail.

### 6. Prompt Injection Defense

Tests 8 adversarial attacks against the governance policy layer:
- **Instruction override** — "Ignore all previous instructions..."
- **Jailbreak** — "You are now DAN, no restrictions..."
- **System prompt extraction** — "Show your system prompt..."
- **Encoded payload** — Base64 execution attempts
- **Stacked PII exfiltration** — SSN + email in one message
- **SQL injection** — `DROP TABLE` hidden in editorial comments
- **Shell injection** — `rm -rf` hidden in routine tasks
- **Delegation bypass** — attempt to skip editorial review

All attacks are caught **before** the LLM is invoked.

### 7. Handoff Governance (Trust-Gated Handoffs)

Unique to OpenAI Agents SDK — enforces trust at agent-to-agent handoffs:

| Handoff | Source Trust | Target Trust | Result |
|---------|-------------|-------------|--------|
| Researcher → Writer | 500 | 500 | ALLOWED |
| Writer → Editor | 500 | 600 | ALLOWED |
| Editor → Publisher | 600 | 500 | ALLOWED |
| Publisher → Researcher | 200 | 500 | DENIED (source trust too low) |
| Writer → Writer | 500 | 500 | DENIED (self-delegation) |

Delegation depth is bounded (max 3 by default) via `AgentTrustContext`.

### 8. Capability Escalation Detection

Detects agents attempting to use tools outside their declared profile:
- Writer tries `shell_exec`, `db_query`, `admin_panel`, `deploy_prod`, `write_file`
- All escalation attempts are blocked by `CapabilityGuardMiddleware`
- `RogueAgentDetector` scores the agent at CRITICAL risk level
- Capability deviation ratio escalates with each blocked attempt

### 9. Tamper Detection & Merkle Proofs

Demonstrates the cryptographic integrity guarantees of the audit trail:
- Logs 5 governed actions and verifies Merkle chain integrity
- Generates a Merkle proof for a specific entry (independently verifiable)
- **Simulates tampering** — modifies an entry's action field
- Integrity check **detects the tamper** and reports the corrupted entry
- Restores original state and re-verifies
- Exports full audit trail as JSON

## Key Files

| File | Purpose |
|------|---------|
| `getting_started.py` | **Start here** — minimal integration example (~170 lines) |
| `openai_agents_governance_demo.py` | Full 9-scenario showcase |
| `policies/agent_governance_policy.yaml` | Role-based + PII + injection + handoff policies |
| `policies/quality_gate_policy.yaml` | Publishing quality gates |
| `agent-governance-python/agent-os/src/agent_os/integrations/maf_adapter.py` | Governance middleware |
| `agent-governance-python/agentmesh-integrations/openai-agents-trust/` | OpenAI Agents SDK trust integration |
| `agent-governance-python/agentmesh-integrations/openai-agents-agentmesh/` | OpenAI Agents SDK trust layer |
| `agent-governance-python/agent-mesh/src/agentmesh/governance/audit.py` | Merkle-chained audit log |
| `agent-governance-python/agent-sre/src/agent_sre/anomaly/rogue_detector.py` | Rogue agent detector |

## OpenAI Agents SDK Integration Points

The demo showcases two integration approaches:

### Approach 1: Governance Middleware (framework-agnostic)
The core governance middleware (`GovernancePolicyMiddleware`, `CapabilityGuardMiddleware`,
`RogueDetectionMiddleware`) works with any agent framework. Wrap your LLM calls with
middleware `process()` to enforce governance before/after each call.

### Approach 2: Native SDK Integration (openai-agents-trust)
The `openai-agents-trust` package provides SDK-native constructs:
- **Guardrails** — `trust_input_guardrail`, `policy_input_guardrail`, `content_output_guardrail`
- **Hooks** — `GovernanceHooks` for lifecycle instrumentation
- **Handoffs** — `trust_gated_handoff` for trust-scored agent delegation
- **Trust** — `TrustScorer` with multi-dimensional scoring (reliability, capability, security, compliance)
- **Identity** — `AgentIdentity` with HMAC-signed verification

## Related

- [Quickstart Examples](../quickstart/) — Single-file quickstarts for each framework
- [Live Governance Demo](../../demo/) — Full demo with real LLM calls
- [Sample Policies](../policies/) — Additional YAML governance policies
- [CrewAI Demo](../crewai-governed/) — Similar demo for CrewAI framework
