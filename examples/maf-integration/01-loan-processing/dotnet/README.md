# 🏦 Contoso Bank — Loan Processing Governance Demo (.NET)

**Part of the [Agent Governance Toolkit (AGT)](https://github.com/microsoft/agent-governance-toolkit)**

This demo shows how an AI loan officer agent is governed in real-time using AGT's four core middleware layers integrated with the Microsoft Agent Framework (MAF).

## What This Demo Shows

| Governance Layer | What It Does |
|---|---|
| **Policy Enforcement** | YAML-driven rules block PII access (SSN, tax records) before the LLM sees them |
| **Capability Sandboxing** | Allow/deny tool lists restrict which APIs the agent can call |
| **Rogue Agent Detection** | Z-score frequency analysis and entropy scoring detect anomalous behaviour |
| **Audit Trail** | SHA-256 Merkle-chained log provides tamper-proof compliance records |

## Architecture

```
 User Request
      │
      ▼
┌─────────────────────────────────────────────────────┐
│  GovernancePolicyMiddleware                          │
│  ┌──────────────────────┐                           │
│  │ loan_governance.yaml │──→ DENY if PII / spend    │
│  └──────────────────────┘    violation detected      │
│            │ ALLOW                                   │
│            ▼                                         │
│  CapabilityGuardMiddleware                           │
│  ┌──────────────┐                                   │
│  │ Allowed tools │──→ DENY if tool not permitted     │
│  │ Denied tools  │                                   │
│  └──────────────┘                                   │
│            │ ALLOW                                   │
│            ▼                                         │
│  RogueDetectionMiddleware                            │
│  ┌──────────────┐                                   │
│  │ Z-score      │──→ QUARANTINE if anomalous         │
│  │ Entropy      │                                    │
│  └──────────────┘                                   │
│            │                                         │
│            ▼                                         │
│  AuditTrailMiddleware                                │
│  ┌──────────────────┐                                │
│  │ SHA-256 Merkle   │──→ Every action logged         │
│  │ chain            │                                │
│  └──────────────────┘                                │
│            │                                         │
│            ▼                                         │
│        LLM Call                                      │
└─────────────────────────────────────────────────────┘
```

## Prerequisites

- **.NET 8 SDK** (or later)
- (Optional) `GITHUB_TOKEN` for live LLM calls via GitHub Models
- (Optional) Azure OpenAI credentials

## Quick Start

```bash
# 1. Build and run
dotnet run

# 2. (Optional) With live LLM
export GITHUB_TOKEN=ghp_your_token_here
dotnet run
```

The demo works **with or without an API key**. Without one, it uses simulated LLM responses while still enforcing all governance rules.

## LLM Configuration

The demo auto-detects your LLM backend in this order:

| Priority | Backend | Environment Variables |
|---|---|---|
| 1 | **GitHub Models** (recommended, free) | `GITHUB_TOKEN` |
| 2 | Azure OpenAI | `AZURE_OPENAI_ENDPOINT` + `AZURE_OPENAI_API_KEY` |
| 3 | Simulated | (none needed) |

## Customization Guide

### Editing Policies

The governance policy is in `policies/loan_governance.yaml` (shared with the Python version). To add a new rule:

```yaml
- name: "block_crypto_transactions"
  condition:
    field: "message"
    operator: "contains_any"
    value: "bitcoin,crypto,ethereum,wallet"
  action: "deny"
  priority: 95
  message: "Cryptocurrency transactions are not permitted"
```

### Changing Tool Permissions

In `Program.cs`, modify the `CapabilityGuardMiddleware` initialization:

```csharp
var capabilityMw = new CapabilityGuardMiddleware(
    allowedTools: new[] { "check_credit_score", "get_loan_rates" },
    deniedTools: new[] { "access_tax_records", "transfer_funds" });
```

## Understanding the Output

| Act | What It Demonstrates |
|---|---|
| **Act 1** | YAML policy rules block PII requests (SSN, tax records) before the LLM |
| **Act 2** | Tool allow/deny lists prevent the agent from calling restricted APIs |
| **Act 3** | Rapid-fire transfer attempts trigger anomaly detection and quarantine |
| **Act 4** | Merkle chain integrity verification and compliance proof generation |

## Learn More

- [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)
- [AGT Documentation](https://github.com/microsoft/agent-governance-toolkit/tree/main/docs)
- [MAF Integration Guide](https://github.com/microsoft/agent-governance-toolkit/tree/main/packages/agent-os/src/agent_os/integrations)
