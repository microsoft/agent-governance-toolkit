# 🎧 Contoso Support — Customer Service Governance Demo (.NET)

> Part of the [Agent Governance Toolkit (AGT)](https://github.com/microsoft/agent-governance-toolkit) demo suite

## What This Demo Shows

This demo simulates **Contoso's AI-powered customer support agent** and demonstrates
how the Agent Governance Toolkit enforces four layers of governance in real time:

| Layer | What It Does | Example |
|-------|-------------|---------|
| **Policy Enforcement** | YAML-driven rules intercept requests | Block refunds > $500, deny PII access |
| **Capability Sandboxing** | Tool allow/deny lists | Permit `lookup_order`, block `modify_account_billing` |
| **Rogue Agent Detection** | Behavioral anomaly scoring | Detect refund-farming attack patterns |
| **Audit Trail** | Merkle-chained tamper-proof logging | SHA-256 hash chain for compliance |

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                Customer Request                      │
└──────────────────────┬──────────────────────────────┘
                       │
          ┌────────────▼────────────┐
          │    PolicyEngine (YAML)     │
          │  (rule evaluation)         │
          └────────────┬───────────────┘
                       │ allowed?
          ┌────────────▼────────────┐
          │    CapabilityGuard         │
          │  (tool allow/deny lists)   │
          └────────────┬───────────────┘
                       │ tool permitted?
          ┌────────────▼────────────┐
          │    RogueDetector           │
          │  (anomaly scoring)         │
          └────────────┬───────────────┘
                       │ not anomalous?
          ┌────────────▼────────────┐
          │       LLM / Tools         │
          │  (GPT-4o-mini or sim)     │
          └────────────┬───────────────┘
                       │
          ┌────────────▼────────────┐
          │    AuditTrail (Merkle)    │
          │  (SHA-256 hash chain)     │
          └───────────────────────────┘
```

## Prerequisites

- **.NET 8 SDK** ([Download](https://dotnet.microsoft.com/download/dotnet/8.0))

## Quick Start

### 1. Run in simulated mode (no API key needed)

```bash
cd demo/maf-scenarios/02-customer-service/dotnet
dotnet run
```

### 2. Run with GitHub Models (recommended)

```bash
export GITHUB_TOKEN=ghp_your_token_here
dotnet run
```

### 3. Run with Azure OpenAI

```bash
export AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com
export AZURE_OPENAI_API_KEY=your_key_here
export AZURE_OPENAI_DEPLOYMENT=gpt-4o-mini  # optional
dotnet run
```

## LLM Configuration

The demo auto-detects your LLM backend in this order:

1. **GitHub Models** — Set `GITHUB_TOKEN` (free tier available)
2. **Azure OpenAI** — Set `AZURE_OPENAI_ENDPOINT` + `AZURE_OPENAI_API_KEY`
3. **Simulated** — No environment variables needed; uses realistic mock responses

All governance middleware runs identically regardless of which backend is active.

## Customization Guide

### Editing Policies

The governance policy is defined in `policies/support_governance.yaml`. You can:

- **Adjust the refund limit** — Change the regex in the `refund_limit` rule
- **Add PII patterns** — Extend the `block_pii_access` keywords
- **Allow new tools** — Add entries to the `allow_support_inquiries` rule
- **Change priorities** — Higher priority rules are evaluated first

## Understanding the Output

The demo runs in **4 acts**:

1. **Act 1 — Policy Enforcement:** Shows how YAML policies allow/deny customer requests
2. **Act 2 — Capability Sandboxing:** Demonstrates tool-level access control
3. **Act 3 — Rogue Detection:** Simulates a refund-farming attack and shows anomaly detection
4. **Act 4 — Audit Trail:** Displays the Merkle hash chain and compliance summary

### Status Icons

| Icon | Meaning |
|------|---------|
| ✅ | Request/tool allowed |
| ❌ | Request/tool denied |
| 🚨 | Anomaly detected |
| ⚠ | Quarantine triggered |
| 📨 | Incoming request |
| 🔧 | Tool invocation |
| 🤖 | LLM response |

## Related

- [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)
- [01-loan-processing demo](../01-loan-processing/)
- [Python version of this demo](../python/)
