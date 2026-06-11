# Governed Agent in 10 Minutes

End-to-end demo of the Agent Governance Toolkit (AGT) runtime governance
capabilities. Six live demos covering policy enforcement, zero-trust identity,
MCP security scanning, and tamper-proof audit trails.

## Prerequisites

```bash
pip install agent-governance-toolkit[full]
```

## Quick Start

```bash
# Run all six demos interactively (press Enter between demos)
python examples/demos/governed-agent-in-10-min/demo.py

# Run without pauses (CI/automated mode)
python examples/demos/governed-agent-in-10-min/demo.py --no-pause

# Run a single demo
python examples/demos/governed-agent-in-10-min/demo.py --demo 2
```

## What the Demo Covers

| Demo | Title | What You See |
|------|-------|-------------|
| 1 | Install and Health Check | Six AGT components verified in one install |
| 2 | Sub-millisecond Enforcement | 10,000 policy evaluations live with p50/p95/p99 latency |
| 3 | Multi-Agent Loan Workflow | Loan Officer, Credit Checker, Fraud Detector with PII blocking |
| 4 | Zero-Trust Agent Identity | DID handshake, capability scoping, delegation, kill switch |
| 5 | MCP Tool Poisoning Detection | Hidden instructions, invisible unicode, base64 payloads found |
| 6 | Tamper-Proof Audit Trail | SHA-256 hash-chained log with live tamper detection |

## Reference Architecture (Bicep)

The `bicep/` directory contains a sample Azure deployment for a governed
agent environment:

- **Azure Container App**: agent runtime with AGT policy enforcement
- **Azure Key Vault**: agent credentials and policy signing keys
- **Azure Log Analytics**: observability and audit trail storage
- **Azure Container Registry**: governed agent images
- **Managed Identity**: zero-trust, no shared secrets

```bash
az group create --name rg-agt-demo --location eastus2

az deployment group create \
  --resource-group rg-agt-demo \
  --template-file bicep/main.bicep \
  --parameters environmentName=agt-demo
```

## Policy File

The `policies/contoso-bank.yaml` file demonstrates a production enterprise
policy with:

- Tool-call restrictions (block destructive ops, unauthorized financial ops)
- PII leak prevention (SSN pattern matching in messages and tool inputs)
- Exfiltration prevention (block outbound network calls)
- Dangerous code pattern blocking (subprocess, eval, pip install)

## Expected Output (Demo 3 Sample)

```
  Actor              Action                                   Verdict    Reason
  ------------------ ---------------------------------------- ---------- --------
  Loan Officer       -> Credit Checker                        ALLOWED    -
  Credit Checker     -> tool: lookup_score                    ALLOWED    -
  Credit Checker     -> Loan Officer (reply with PII)         BLOCKED    SSN in inter-agent message blocked
  Loan Officer       -> Fraud Detector                        ALLOWED    -
  Fraud Detector     -> tool: pattern_check                   ALLOWED    -
  Fraud Detector     -> tool: transfer_funds (rogue)          BLOCKED    transfer_funds blocked
  Loan Officer       -> tool: approve_loan                    BLOCKED    approve_loan blocked

  4 allowed, 3 blocked. Policy violations reaching execution: 0
```

## Cleanup

No persistent resources are created by the Python demo. For the Bicep
deployment:

```bash
az group delete --name rg-agt-demo --yes --no-wait
```
