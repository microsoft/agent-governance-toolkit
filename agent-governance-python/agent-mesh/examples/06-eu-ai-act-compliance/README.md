# EU AI Act Compliance Checker

An AgentMesh example that assesses AI agents against the **EU AI Act** (Regulation 2024/1689) — the world's first comprehensive AI regulation.

## What This Example Shows

- **Risk Classification (Article 6):** Categorise agents as Unacceptable → High → Limited → Minimal risk
- **Prohibited Practices (Article 5):** Detect and block banned AI uses (social scoring, subliminal manipulation, …)
- **Transparency Checks (Articles 13 & 50):** Ensure users know they interact with AI
- **Human Oversight (Article 14):** Verify meaningful human control is in place
- **Accuracy & Robustness (Article 15):** Check bias testing, accuracy metrics, and cybersecurity
- **Quality Management (Article 17):** Validate QMS, risk management, and data governance
- **Record-Keeping (Article 12):** Ensure automatic decision logging
- **Deployment Gate:** Block non-compliant agents from being deployed

## EU AI Act — Quick Primer

| Risk Level | Examples | Obligations |
|---|---|---|
| **Unacceptable** | Social scoring, subliminal manipulation | **Prohibited** — cannot be deployed in the EU |
| **High** | Medical diagnosis, recruitment, credit scoring | Full compliance: documentation, oversight, logging, bias testing, QMS |
| **Limited** | Chatbots, content generators | Transparency disclosure — users must know it's AI |
| **Minimal** | Spam filters, game AI | No specific obligations (voluntary codes of conduct) |

### Key Articles for AI Agents

| Article | Topic | Requirement |
|---|---|---|
| **5** | Prohibited practices | Certain AI uses are outright banned |
| **6** | Risk classification | Systems are tiered by risk level |
| **12** | Record-keeping | High-risk systems must log decisions automatically |
| **13** | Transparency | High-risk systems need full technical documentation |
| **14** | Human oversight | Meaningful human control (override, interrupt, shutdown) |
| **15** | Accuracy & robustness | Bias testing, accuracy metrics, cybersecurity |
| **17** | Quality management | QMS covering risk management, data governance, monitoring |
| **50** | Transparency for GPAI | Users must be told they are interacting with AI |

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│               EU AI Act Compliance Checker                       │
│                                                                  │
│  ┌──────────────┐  ┌──────────────────┐  ┌───────────────────┐  │
│  │ Risk         │  │ Article-Specific │  │ Compliance        │  │
│  │ Classifier   │  │ Checkers         │  │ Report Generator  │  │
│  │ (Art. 5 & 6) │  │ (Art. 12–50)     │  │                   │  │
│  └──────┬───────┘  └────────┬─────────┘  └─────────┬─────────┘  │
│         │                   │                      │             │
│         └───────────────────┴──────────────────────┘             │
│                             │                                    │
│                    ┌────────▼────────┐                           │
│                    │ Deployment Gate │                           │
│                    │ (allow / block) │                           │
│                    └─────────────────┘                           │
└──────────────────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# No dependencies required — uses only the Python standard library

# Run the demo
cd examples/06-eu-ai-act-compliance
python demo.py
```

No API keys needed.

## Files

| File | Purpose |
|---|---|
| `compliance_checker.py` | Core library — risk classifier, article checkers, report generator |
| `demo.py` | Runnable demo — five scenarios covering the main EU AI Act requirements |
| `README.md` | This file |

## Demo Scenarios

### 1. Risk Classification
Classify a medical-diagnosis agent as **high-risk** based on its domain (Annex III) and capabilities.

### 2. Transparency Check
Flag a customer-support chatbot that lacks a transparency disclosure (Article 50 violation).

### 3. Full Compliance Report
Generate a detailed report for a recruitment agent that fails multiple requirements (human oversight, logging, bias testing, documentation, QMS).

### 4. Deployment Gate
Demonstrate the deployment gate blocking the non-compliant recruitment agent while approving the compliant medical agent.

### 5. Prohibited System
Detect a social-scoring system as **unacceptable risk** and block deployment entirely.

## Extending This Example

- **Add custom domains** — extend `HIGH_RISK_DOMAINS` or `UNACCEPTABLE_DOMAINS` in `compliance_checker.py`
- **Integrate with AgentMesh policy engine** — call `can_deploy()` as a pre-deployment hook
- **Export reports** — use `to_json()` to feed reports into dashboards or CI/CD pipelines
- **Add more articles** — implement checkers for Articles 9 (risk management), 10 (data & data governance), or 11 (technical documentation)

## Learn More

- [EU AI Act Full Text](https://eur-lex.europa.eu/eli/reg/2024/1689/oj)
- [AgentMesh Compliance Engine](../../docs/compliance.md)
- [Healthcare HIPAA Example](../03-healthcare-hipaa/)

---

**Disclaimer:** This example demonstrates technical controls for educational purposes. Consult legal and compliance professionals before relying on it for actual EU AI Act compliance.
