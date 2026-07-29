# Agent Governance Toolkit — Live Governance Demo

> Demonstrates governance enforcement through the MAF adapter against a real
> ACS manifest. The policy decisions and audit entries are real; the example
> does not call a model, so it runs offline with no API key.

## What This Shows

| Scenario | Layer | What Happens |
|----------|-------|--------------|
| **1. Policy Enforcement** | `RuntimeGovernanceMiddleware` | The manifest allows a search prompt but blocks `**/internal/**` — **before the LLM is called** |
| **2. Capability Sandboxing** | `CapabilityGuardMiddleware` | LLM requests tool calls; governance allows `run_code` but denies `write_file` |
| **3. Rogue Detection** | `RogueDetectionMiddleware` | Behavioral anomaly engine detects a 50-call burst and auto-quarantines |
| **4. Content Filtering** | `RuntimeGovernanceMiddleware` | Multiple prompts evaluated — dangerous ones blocked, safe ones forwarded |
| **Audit Trail** | `AuditLog` + Merkle chain | Every decision is cryptographically chained and verifiable |

## Architecture

```
+-------------------------------------------------------+
|  Agent (MAF adapter, no model call in this example)   |
|  +--------------------------------------------------+ |
|  |  RuntimeGovernanceMiddleware (manifest + Rego)| <-- Blocks before LLM
|  |  CapabilityGuardMiddleware  (tool allow/deny)     | <-- Intercepts tools
|  |  RogueDetectionMiddleware   (anomaly scoring)     | <-- Behavioral SRE
|  +--------------------------------------------------+ |
|                      |                                |
|         Mediated call site (model optional)           |
+-------------------------------------------------------+
        |                              |
        v                              v
  AuditLog (Merkle)           RogueAgentDetector
  agentmesh.governance        agent_sre.anomaly
```

## Prerequisites

```bash
pip install -e "agent-governance-python/agt-policies"
pip install -e "agent-governance-python/agent-os"
```

## Running

```bash
python examples/maf-integration/01-loan-processing/python/main.py
```

## Key Files

| File | Purpose |
|------|---------|
| `examples/maf-integration/` | Native ACS MAF scenarios |
| `examples/demos/governance-dashboard/` | Real-time Streamlit dashboard |
| `agent-governance-python/agent-os/src/agent_os/integrations/maf_adapter.py` | Governance middleware |
| `agent-governance-python/agent-mesh/src/agentmesh/governance/audit.py` | Merkle-chained audit log |
| `agent-governance-python/agent-sre/src/agent_sre/anomaly/rogue_detector.py` | Rogue agent detector |

## Governance Dashboard

For a visual overview of your agent fleet:

```bash
cd demo/governance-dashboard
pip install -r requirements.txt
streamlit run app.py
# or: docker-compose up
```

See the [dashboard README](governance-dashboard/README.md) for details.

## Links

- [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)