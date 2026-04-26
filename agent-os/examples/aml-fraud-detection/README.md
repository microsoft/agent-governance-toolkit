# AML/KYC Fraud Detection Demo

Multi-agent Anti-Money Laundering system powered by **Agent OS** governance.
Four specialized agents collaborate in a pipeline, each governed by
independent policies with PII protection, human approval gates, and
immutable audit trails.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     AML/KYC Detection Pipeline                      │
│                                                                     │
│   ┌──────────────────┐    ┌──────────────────┐                     │
│   │  Transaction      │───▶│  Velocity         │                     │
│   │  Monitor          │    │  Analyzer         │                     │
│   │  • Structuring    │    │  • Daily/weekly   │                     │
│   │  • Round-trip     │    │  • Peer compare   │                     │
│   │  • Dormant acct   │    │  • Activity spike │                     │
│   │  • Geo risk       │    │                   │                     │
│   └──────────────────┘    └────────┬──────────┘                     │
│                                     │                                │
│   ┌──────────────────┐    ┌────────▼──────────┐                     │
│   │  SAR Filer        │◀───│  Sanctions        │                     │
│   │  • Generate SAR   │    │  Screener         │                     │
│   │  • Human approval │    │  • OFAC/SDN       │                     │
│   │  • 30-day filing  │    │  • Fuzzy match    │                     │
│   │  • Tipping-off    │    │  • FATF countries │                     │
│   └──────────────────┘    │  • PEP check      │                     │
│                            └──────────────────┘                     │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │  Agent OS Governance Layer                                   │    │
│  │  • Per-agent GovernancePolicy    • PII redaction (SSN/acct) │    │
│  │  • PolicyInterceptor per agent   • Immutable audit trail    │    │
│  │  • Human approval gate (SAR)     • Checkpoint after N calls │    │
│  └─────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
```

## BSA/AML Compliance Mapping

| Regulation              | Requirement                           | Agent OS Feature                     |
|-------------------------|---------------------------------------|--------------------------------------|
| BSA §5318(g)            | SAR filing within 30 days             | SARFiler deadline tracking           |
| 31 CFR §1020.320        | SAR content requirements              | Structured SAR generation            |
| 31 USC §5318(g)(2)      | Tipping-off prohibition               | Confidentiality in SAR narrative     |
| BSA §5313               | CTR for transactions >$10K            | Structuring detection ($9,500 flag)  |
| OFAC regulations        | SDN list screening                    | Exact + fuzzy Levenshtein matching   |
| FATF Recommendations    | Risk-based approach                   | Geographic risk scoring              |
| BSA/AML §5318           | Immutable audit trail                 | Append-only JSON/CSV audit log       |
| PEP screening           | Enhanced due diligence                | PEP database matching                |
| General AML             | Human-in-the-loop for filings         | GovernancePolicy + approval gate     |
| General AML             | PII protection                        | Blocked patterns (SSN, account #)    |

## Quick Start

```bash
# From the agent-os repository root
python examples/aml-fraud-detection/demo.py
```

No external dependencies required — only the `agent-os` core library.

## Demo Scenarios

| # | Scenario                   | Expected Result      | Key Detection               |
|---|----------------------------|----------------------|-----------------------------|
| 1 | Normal $500 transfer       | ✅ CLEAR             | No alerts                   |
| 2 | 3×$9,500 same day          | 🚨 SAR_FILED         | Structuring detection       |
| 3 | OFAC SDN exact match       | 🚨 SAR_FILED         | Sanctions screening         |
| 4 | Dormant account (270 days) | 🚨 SAR_FILED         | Dormant activation + spike  |
| 5 | A→B→C→A round-trip         | 🚨 SAR_FILED         | Circular flow detection     |
| 6 | PEP + Panama               | 🚨 SAR_FILED         | PEP match + FATF country   |
| 7 | Iran transaction           | 🚨 SAR_FILED         | FATF high-risk jurisdiction |
| 8 | Large + OFAC + SAR filing  | 🚨 SAR_FILED         | Human approval gate demo    |

## Agent Descriptions

### TransactionMonitor
Watches the transaction stream for common AML red flags:
- **Structuring**: Multiple transactions just under the $10,000 CTR threshold
- **Round-trip**: Circular fund flows (A→B→C→A patterns)
- **Dormant activation**: Accounts inactive >180 days with sudden activity
- **Geographic risk**: Transactions involving FATF high-risk jurisdictions

### VelocityAnalyzer
Analyzes transaction velocity and behavioral patterns:
- **Daily/weekly limits**: Flags when cumulative amounts exceed thresholds
- **Activity spikes**: Detects when monthly transaction count exceeds 3× the average

### SanctionsScreener
Screens parties against sanctions lists and PEP databases:
- **OFAC/SDN matching**: Exact name match plus fuzzy matching with Levenshtein distance
- **Country screening**: FATF high-risk and non-cooperative jurisdictions
- **PEP identification**: Politically Exposed Persons database lookup

### SARFiler
Generates and files Suspicious Activity Reports:
- **Human approval required**: Governance gate blocks automatic SAR submission
- **Structured narrative**: Collects all evidence from upstream agents
- **30-day deadline**: Tracks filing deadline per BSA requirements
- **Tipping-off prevention**: Confidentiality notice in every SAR

## Governance Features Used

- `GovernancePolicy` — per-agent policy with tool restrictions and rate limits
- `PolicyInterceptor` — enforces allowed tools, blocked patterns, call limits
- `SARApprovalInterceptor` — custom interceptor requiring human approval for SAR submission
- `BaseIntegration.emit()` — event-driven audit trail
- `GovernanceEventType` — POLICY_CHECK, TOOL_CALL_BLOCKED, CHECKPOINT_CREATED
- `ExecutionContext` — tracks per-agent call counts and checkpoints
- Blocked patterns — SSN regex, account number regex, plaintext keywords

## Output Files

After running the demo, two audit trail files are generated:

- `aml_audit_trail.json` — Full structured audit log
- `aml_audit_trail.csv` — Tabular export for compliance review tools
