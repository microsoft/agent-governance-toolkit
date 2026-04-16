# 🔐 SecureDesk — IT Helpdesk Privilege Escalation Prevention (.NET)

**Part of the [Agent Governance Toolkit (AGT)](https://github.com/microsoft/agent-governance-toolkit)**

This demo shows how an AI IT helpdesk agent is governed in real-time using AGT's four core middleware layers integrated with the Microsoft Agent Framework (MAF).

## What This Demo Shows

| Governance Layer | What It Does |
|---|---|
| **Policy Enforcement** | YAML-driven rules block privilege escalation (sudo, admin) and credential access before the LLM sees them |
| **Capability Sandboxing** | Allow/deny tool lists restrict which system operations the agent can invoke |
| **Rogue Agent Detection** | Z-score frequency analysis and entropy scoring detect systematic privilege probing |
| **Audit Trail** | SHA-256 Merkle-chained log provides tamper-proof compliance records |

## Prerequisites

- **.NET 8.0 SDK**
- (Optional) `GITHUB_TOKEN` for live LLM calls via GitHub Models
- (Optional) Azure OpenAI credentials

## Quick Start

```bash
# 1. Run the demo (dependencies restore automatically)
dotnet run

# 2. (Optional) Set a GitHub token for live LLM
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

## Understanding the Output

| Act | What It Demonstrates |
|---|---|
| **Act 1** | YAML policy rules block privilege escalation and credential access requests before the LLM |
| **Act 2** | Tool allow/deny lists prevent the agent from invoking admin commands and infrastructure tools |
| **Act 3** | Rapid-fire admin command attempts trigger anomaly detection and quarantine |
| **Act 4** | Merkle chain integrity verification and compliance proof generation |

## Learn More

- [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit)
- [AGT Documentation](https://github.com/microsoft/agent-governance-toolkit/tree/main/docs)
- [MAF Integration Guide](https://github.com/microsoft/agent-governance-toolkit/tree/main/packages/agent-os/src/agent_os/integrations)
