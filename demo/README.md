# Agent Governance Toolkit × MAF — Runtime Demo

> **Show & Tell demo** for the Microsoft Agent Framework VP and team.
> Demonstrates real-time governance enforcement across a multi-agent
> research pipeline using four composable middleware layers.

## What This Shows

| Scenario | Layer | What Happens |
|----------|-------|--------------|
| **1. Policy Enforcement** | `GovernancePolicyMiddleware` | Declarative YAML policy allows web search but blocks access to `**/internal/**` paths |
| **2. Capability Sandboxing** | `CapabilityGuardMiddleware` | Ring-2 tool guard allows `run_code` but denies `write_file` |
| **3. Rogue Detection** | `RogueDetectionMiddleware` | Behavioral anomaly engine detects a 50-call email burst and auto-quarantines the agent |
| **Audit Trail** | `AuditTrailMiddleware` + Merkle chain | Every decision is logged with cryptographic integrity verification |

All governance decisions are made by **real middleware** from the Agent
Governance Toolkit — the same code that runs in production.

## Architecture

```
┌───────────────────────────────────────────────────┐
│  MAF Agent (agent_framework.Agent)                │
│  ┌─────────────────────────────────────────────┐  │
│  │  AuditTrailMiddleware   (AgentMiddleware)   │◄── Tamper-proof logging
│  │  GovernancePolicyMiddleware (AgentMiddleware)│◄── YAML policy eval
│  │  CapabilityGuardMiddleware  (FuncMiddleware) │◄── Tool allow/deny
│  │  RogueDetectionMiddleware   (FuncMiddleware) │◄── Anomaly scoring
│  └─────────────────────────────────────────────┘  │
│                      ▼                            │
│            Agent / Tool Execution                 │
└───────────────────────────────────────────────────┘
        │                              │
        ▼                              ▼
  AuditLog (Merkle)           RogueAgentDetector
  agentmesh.governance        agent_sre.anomaly
```

## Prerequisites

```bash
# From the repo root (packages are already installed in editable mode)
pip install agent-os-kernel agentmesh-platform agent-sre agent-hypervisor

# Or install everything at once
pip install ai-agent-compliance[full]

# For YAML policy loading
pip install pyyaml
```

## Running

```bash
cd agent-governance-toolkit

# Default mode — simulated agents, REAL governance middleware
python demo/maf_governance_demo.py

# Live mode — uses real LLM calls (requires OPENAI_API_KEY)
python demo/maf_governance_demo.py --live
```

## Expected Output

You'll see colourful terminal output with three scenarios:

```
╔════════════════════════════════════════════════════════════════════╗
║  Agent Governance Toolkit  ×  Microsoft Agent Framework           ║
║  Runtime Governance Demo — Show & Tell Edition                    ║
╚════════════════════════════════════════════════════════════════════╝

━━━ Scenario 1: Policy Enforcement ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🤖 Research Agent → "Search for AI governance papers"
  ├── ✅ Policy Check: ALLOWED (web_search permitted)
  ├── 🔧 Tool: web_search("AI governance papers")
  ├── 📝 Audit: Entry #audit_a1b2c3 logged
  └── 📦 Result: "Found 15 papers on AI governance..."

🤖 Research Agent → "Read /internal/secrets/api_keys.txt"
  ├── ⛔ Policy Check: DENIED (blocked pattern: **/internal/**)
  ├── 📝 Audit: Entry #audit_d4e5f6 logged (VIOLATION)
  └── 📦 Agent received: "Policy violation: Access restricted"

━━━ Scenario 2: Capability Sandboxing ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🤖 Analysis Agent → run_code("import pandas; ...")
  ├── ✅ Capability Guard: ALLOWED
  └── 📦 Result: "DataFrame loaded: 1,000 rows × 5 columns"

🤖 Analysis Agent → write_file("/output/results.csv")
  ├── ⛔ Capability Guard: DENIED (not in permitted tools)
  └── 📦 Agent received: "Tool not permitted by governance policy"

━━━ Scenario 3: Rogue Agent Detection ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🤖 Report Agent → send_email (normal)
  ├── ✅ Rogue Check: LOW RISK (score: 0.00)
  └── 📦 Result: "Email sent"

🤖 Report Agent → send_email × 50 — rapid burst
  ├── 🚨 Rogue Check: CRITICAL (score: 3.42)
  ├── 🛑 Action: QUARANTINED — Agent execution halted
  └── 📦 Agent received: "Agent quarantined: anomalous frequency"

━━━ Audit Trail Summary ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📋 Total entries: 8
  ✅ Allowed: 4  │  ⛔ Denied: 2  │  🚨 Quarantined: 1  │  📝 Info: 1
🔒 Merkle chain integrity: VERIFIED ✓
🔗 Root hash: a3f7c2...b2d1e8
```

## Key Files

| File | Purpose |
|------|---------|
| `demo/maf_governance_demo.py` | Main demo script |
| `demo/policies/research_policy.yaml` | Declarative governance policy |
| `packages/agent-os/src/agent_os/integrations/maf_adapter.py` | MAF middleware integration |
| `packages/agent-mesh/src/agentmesh/governance/audit.py` | Merkle-chained audit log |
| `packages/agent-sre/src/agent_sre/anomaly/rogue_detector.py` | Rogue agent detector |

## Links

- **Agent Governance Toolkit**: [github.com/imran-siddique/agent-governance-toolkit](https://github.com/imran-siddique/agent-governance-toolkit)
- **Microsoft Agent Framework**: [github.com/microsoft/agent-framework](https://github.com/microsoft/agent-framework)
