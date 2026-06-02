# Adopters

Organizations using the Agent Governance Toolkit in production or evaluation.

_If your organization uses AGT, please add it here! It helps the project gain
momentum and credibility. Submit a PR editing this file — see
[CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines._

## Production

| Organization | Industry | Use Case | Since | Contact |
|---|---|---|---|---|
| Microsoft (internal AI agent platform) | AI / Developer Tools | Policy enforcement and governance workflows for multi-agent orchestration | Mar 2026 | [@imran-siddique](https://github.com/imran-siddique) |
| Microsoft (internal engineering tools) | Engineering Productivity | Agent SRE integration for incident management and reliability monitoring | Apr 2026 | [@imran-siddique](https://github.com/imran-siddique) |
| [Dayos](https://dayos.com) | Enterprise AI / ERP Automation | Policy enforcement and prompt-injection detection for a multi-agent system built on Google ADK -- Cedar-based tool-dispatch governance across finance and operations workflows | May 2026 | [@miyannishar](https://github.com/miyannishar) |

## Evaluation / Pilot

| Organization | Industry | Use Case | Since | Contact |
|---|---|---|---|---|
| [Nobulex](https://github.com/arian-gogani/nobulex) | AI Agent Security | Bilateral receipt primitive for tamper-evident agent audit trails (PRs #1302, #1333) | Mar 2026 | [@arian-gogani](https://github.com/arian-gogani) |
| [GitHub -- awesome-copilot](https://github.com/github/awesome-copilot) | Developer Tools | AGT contributor reputation check (`agt-contributor-check`) integrated into CI for PR risk scoring | Apr 2026 | [@imran-siddique](https://github.com/imran-siddique) |
| Azure (internal project) | Cloud Infrastructure | AGT identity layer integration for agent mesh trust verification | Apr 2026 | [@imran-siddique](https://github.com/imran-siddique) |
| [chamber](https://github.com/ianphil/chamber) | AI Agent Infrastructure | AGT governance workflows for agent execution policy enforcement | Apr 2026 | [@ianphil](https://github.com/ianphil) |
| [MythologIQ Labs, LLC](https://github.com/MythologIQ-Labs-LLC) | AI Governance / Agent Security | Evaluating AGT as an isolated upstream governance dependency for [Qortara](https://qortara.com), including LangChain/LangGraph tool-dispatch governance through [`qortara-governance-langchain`](https://github.com/MythologIQ-Labs-LLC/qortara-governance). | May 2026 | [@Knapp-Kevin](https://github.com/Knapp-Kevin) |
| [GenAI-Gurus](https://github.com/GenAI-Gurus) | AI Governance / EU AI Act Compliance | EU AI Act compliance tooling and resource curation ([awesome-eu-ai-act](https://github.com/GenAI-Gurus/awesome-eu-ai-act)), cross-referencing AGT's compliance checklist | May 2026 | [@carloshvp](https://github.com/carloshvp) |
| [Provedit](https://provedit.ai) | AI Agent Audit / Compliance Infrastructure | Hosted OTLP receiver for AGT's agent-os OTelLogsBackend (PR #1747) that re-signs each governance decision into a tamper-evident Merkle chain (ADR-0017) and surfaces per-tenant AGT-vs-Provedit agreement dashboards. Walkthrough: https://provedit.ai/agt-otlp.html | May 2026 | [@provedit](https://github.com/provedit) |
| Vortex MSP | Managed Services / Microsoft 365 + Copilot | Productizing AGT as the runtime policy enforcement layer for managed-services client deployments of Copilot Studio and Foundry agents. Building an "AGT Policy Engineering Sprint" service for regulated SMB clients (HIPAA, SOC2, NYC LL 144 AEDT, EU AI Act Article 11) that composes AGT with pre-deployment code audit, AI-BOM generation, and compliance evidence packets. Public reference deliverable: [vibe-m365-agent-audit](https://github.com/anthonyonazure/claude-skills/blob/main/vibe-m365-agent-audit/references/pricing-tiers.md) tier A.5.7. | May 2026 | [@anthonyonazure](https://github.com/anthonyonazure) (Anthony Clendenen) |

## Academic / Research

| Organization | Focus Area | Since | Contact |
|---|---|---|---|
| [Data Quality-Aware Agent Governance](https://github.com/SomeshZanwar/data-quality-aware-agent-governance) | Combining AGT policy evaluation with external data quality signals -- agent actions are blocked when the target dataset fails freshness or validation checks, not only when the agent lacks authorization. | Apr 2026 | [@SomeshZanwar](https://github.com/SomeshZanwar) |

---

## How to Add Your Organization

1. Fork the repository
2. Edit this file — add a row to the appropriate table
3. Submit a pull request

**What to include:**
- **Organization:** Your company/institution name (link to website)
- **Industry:** e.g., Financial Services, Healthcare, Technology, Government
- **Use Case:** Brief description (1-2 sentences) of how you use AGT
- **Contact:** GitHub handle of a representative (optional but helpful)

**Example:**

```markdown
| [Contoso](https://contoso.com) | Financial Services | Policy enforcement for trading agents — deterministic action governance on multi-agent workflows processing market data | [@jsmith](https://github.com/jsmith) |
```

We welcome all adopters — from "just evaluating" to "running in production
at scale." Every entry helps others discover the project and understand
its real-world applicability.

## Why Add Your Name?

- 🏢 **Visibility** — show your organization's AI governance maturity
- 🤝 **Community** — connect with other AGT users facing similar challenges
- 📈 **Project health** — help maintainers prioritize features based on real usage
- 🛡️ **Signal** — demonstrate industry adoption for regulatory conversations
